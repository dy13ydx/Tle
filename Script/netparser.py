#!/usr/bin/env python3
import sys

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"
}

def hex_to_ip_port(hex_str):
    try:
        hex_ip, hex_port = hex_str.split(':')
        ip_bytes = [int(hex_ip[i:i+2], 16) for i in range(0, 8, 2)]
        ip_bytes.reverse()
        return f"{'.'.join(map(str, ip_bytes))}:{int(hex_port, 16)}"
    except:
        return "Unknown"

def parse_input():
    print(f"{'Local Address':<22} {'Remote Address':<22} {'State':<12} {'UID':<6} {'Inode':<8}")
    print("-" * 75)
    
    # Read line by line from standard input stream
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("  sl"): # Skip header lines if present
            continue
        parts = line.split()
        # Handle lines that include or omit the row index column (e.g., '1:')
        if ":" in parts[0] and not parts[0].endswith(":238C"): 
            parts = parts[1:]
            
        if len(parts) < 10:
            continue
            
        local_net = hex_to_ip_port(parts[0])
        remote_net = hex_to_ip_port(parts[1])
        state = TCP_STATES.get(parts[2].upper(), f"UNK({parts[2]})")
        uid = parts[6]
        inode = parts[8]
        
        print(f"{local_net:<22} {remote_net:<22} {state:<12} {uid:<6} {inode:<8}")

if __name__ == "__main__":
    parse_input()
