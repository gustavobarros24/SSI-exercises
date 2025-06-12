import struct 
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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

def encrypt(filename, text, key):
    nonce = os.urandom(16)
    algorithm = algorithms.ChaCha20(key,nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text) + encryptor.finalize()
    writebytestofile(filename + ".enc", nonce + ciphertext)
    return 0

def decrypt(filename, text, key):
    nonce = text[:16]
    ciphertext = text[16:]
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    writebytestofile(filename + ".dec", plaintext)


def main():
    if len(sys.argv) < 3:
        print("Input incorreto, tente novamente.")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == 'setup':
        key = os.urandom(32)
        writebytestofile(sys.argv[2], key)
    elif mode == 'enc':
        text = readfilesasbytes(sys.argv[2])
        key = readfilesasbytes(sys.argv[3])
        encrypt(sys.argv[2], text, key)
    elif mode == 'dec':
        text = readfilesasbytes(sys.argv[2])
        key = readfilesasbytes(sys.argv[3])
        decrypt(sys.argv[2],text ,key)
    else:
        print("Modo não existente, tente novamente.")
        sys.exit(1)


if __name__ == "__main__":
    main()