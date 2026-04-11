import base64
import click
import six
import itertools
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def b64decode(encoded):
    """Wrapper around `base64.b64decode` to add padding if necessary"""
    padding_len = 4 - (len(encoded) % 4)
    if padding_len < 4:
        encoded += "=" * padding_len
    return base64.b64decode(encoded)


def decrypt(secret, ciphertext, nosalt=False):
    """Given the first 16 bytes of splunk.secret, decrypt a Splunk password"""
    plaintext = None

    if ciphertext.startswith("$1$"):
        ciphertext = b64decode(ciphertext[3:])
        if len(secret) < 16:
            raise ValueError(f"secret too short, need 16 bytes, got {len(secret)}")
        key = secret[:16]

        algorithm = ARC4(key)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext)

        chars = []
        if not nosalt:
            for char1, char2 in zip(plaintext[:-1], itertools.cycle("DEFAULTSA")):
                if six.byte2int([char1]) == ord(char2):
                    chars.append(six.byte2int([char1]))
                else:
                    chars.append(six.byte2int([char1]) ^ ord(char2))
        else:
            chars = [six.byte2int([char]) for char in plaintext[:-1]]

        # Ensure we're correctly converting integers back to characters
        plaintext = "".join([chr(c) for c in chars])  # Changed to chr() to handle integers properly
    elif ciphertext.startswith("$7$"):
        # pad secret to 254 bytes with nulls
        secret = six.ensure_binary(secret).ljust(254, b"\0")

        ciphertext = b64decode(ciphertext[3:])

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"disk-encryption",
            iterations=1,
            backend=default_backend()
        )
        key = kdf.derive(secret[:254])

        iv = ciphertext[:16]  # pylint: disable=invalid-name
        tag = ciphertext[-16:]
        ciphertext = ciphertext[16:-16]

        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, mode=modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext).decode()

    return plaintext


@click.command()
@click.option('--splunk-secret', type=str, required=True, help="Splunk secret key (16 bytes minimum)")
@click.option('--cipher-text', type=str, required=True, help="Ciphertext to decrypt")
def main(splunk_secret, cipher_text):
    """Main function to decrypt Splunk password"""
    try:
        decrypted_password = decrypt(splunk_secret.encode(), cipher_text)
        click.echo(f"Decrypted password: {decrypted_password}")
    except Exception as e:
        click.echo(f"Error: {str(e)}")


if __name__ == "__main__":
    main()

