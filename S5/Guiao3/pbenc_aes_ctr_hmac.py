import sys, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def writebytestofile(file_path: str, byte_list: bytes):
    with open(file_path, 'wb') as file:
        file.write(byte_list)

def readfilesasbytes(file_path: str) -> bytes:
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    with open(file_path, 'rb') as file:
        byte_list = file.read()
    return byte_list

def encrypt_file(filename, text, password):
    salt = os.urandom(16);
    writebytestofile('salt',salt);

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length= 64
        salt=salt,
        interations = 500000,
    )

    key = kdf.derive(password)
