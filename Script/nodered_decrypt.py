#!/usr/bin/env python3
import argparse
import json
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_creds(secret, cipher_str):
    key = hashlib.sha256(secret.encode()).digest()
    iv = bytes.fromhex(cipher_str[:32])
    ciphertext = base64.b64decode(cipher_str[32:])
    
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    
    return json.loads(decrypted_bytes.decode())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt Node-RED credentials")
    parser.add_argument("-s", "--secret", required=True, help="Raw secret string")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--cred", help="Raw ciphertext string (no JSON)")
    group.add_argument("-C", "--credfile", help="Path to flows_cred.json file")
    
    args = parser.parse_args()
    
    if args.credfile:
        with open(args.credfile, 'r') as f:
            cipher_str = json.load(f)["$"]
    else:
        cipher_str = args.cred
        
    result = decrypt_creds(args.secret, cipher_str)
    print(json.dumps(result, indent=2))
