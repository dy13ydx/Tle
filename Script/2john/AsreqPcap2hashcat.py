#!/usr/bin/python3
import argparse
import sys
import logging
# Suppress Scapy warning messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from binascii import hexlify

def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract AS-REQ hashes from PCAP (Auto-detect Domain).",
        usage="%(prog)s [options] <pcap_file>"
    )
    parser.add_argument("pcap_file", help="Path to the .pcap capture file")
    return parser.parse_args()

def parse_packet(packet):
    try:
        if not packet.haslayer(Kerberos):
            return None

        if packet.haslayer(KRB_AS_REQ):
            msgType = bytes(packet[Kerberos][KRB_AS_REQ].msgType)[-1:].decode()
            if msgType != '\n': return None
        else:
            return None

        if packet[Kerberos] and packet[Kerberos][PADATA].padataValue.cipher:
            data = packet[Kerberos]

            # 1. Encryption Type
            enctype_byte = bytes(data[EncryptedData].etype)[-1:].decode()
            encryption_type = 18 # Default to AES256
            if enctype_byte == '\x17': encryption_type = 23 # RC4

            # 2. Extract User
            nameString = bytes(data[KRB_KDC_REQ_BODY][PrincipalName].nameString[0])[2:].decode()

            # 3. Extract Realm (Auto-detect)
            # The original code used [2:] to skip ASN.1 headers. We keep that logic.
            # We trust the packet contains the full realm (e.g., GHOST.HTB).
            realm_raw = bytes(data[KRB_KDC_REQ_BODY].realm)
            
            # Simple clean: Skip the first 2 bytes (ASN.1 tag/length) and decode
            full_domain = realm_raw[2:].decode()

            # 4. Extract Cipher
            cipher = hexlify(bytes(data[PADATA].padataValue.cipher)[2:]).decode()

            # Format: $krb5pa$etype$user$realm$salt$cipher
            hashcat_format = f"$krb5pa${encryption_type}${nameString}${full_domain}${cipher}"
            
            return hashcat_format

    except Exception:
        return None

def main():
    args = parse_args()
    
    try:
        pcap = rdpcap(args.pcap_file)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

    sessions = pcap.sessions()
    hashes_found = set()

    for session in sessions:
        for packet in sessions[session]:
            result = parse_packet(packet)
            if result and result not in hashes_found:
                print(result)
                hashes_found.add(result)

    if not hashes_found:
        print("[-] No hashes found.")

if __name__ == "__main__":
    main()
