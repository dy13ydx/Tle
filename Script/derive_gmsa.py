import base64
from impacket.krb5.crypto import _AES256CTS

# 1. User Inputs
b64_blob = "eFkbWLHQ9Zr..."
domain = "DOMAIN.LOCAL"
username = "service_gmsa$"

# 2. Automated Salt & Pwd Processing
salt = f"{domain.upper()}host{username.replace('$', '').lower()}.{domain.lower()}".encode()
blob = base64.b64decode(b64_blob)
pwd = blob.decode('utf-16-le', 'replace').encode('utf-8')

# 3. Run the Math
aes256 = _AES256CTS.string_to_key(pwd, salt, b'\x00\x00\x10\x00').contents.hex()
print(f"AES256 Key: {aes256}")
