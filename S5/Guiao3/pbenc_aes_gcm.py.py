import os, sys
from utils import write_bytes_to_file, read_file_as_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(filename: str, text: bytes, password: bytes):
    key = AESGCM.generate_key(bit_length=128)
    write_bytes_to_file('aesgcm.key', key)
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, text, password)
    
    write_bytes_to_file(filename + ".enc", nonce + ct)


def decrypt_file(filename: str, text: bytes, password: bytes):
    nonce = text[:12]
    ct = text[12:]

    key = read_file_as_bytes('aesgcm.key')
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, ct, password)    

    write_bytes_to_file(filename + ".dec", decrypted)


def main():
    if len(sys.argv) < 2:
        print("Usage:", "\n\tpython pbenc_aes_gcm.py [enc|dec] <fich>")
        sys.exit(1)

    mode = sys.argv[1]
    password = None
    text = read_file_as_bytes(sys.argv[2])

    if mode == 'enc': 
        encrypt_file(sys.argv[2], text, password)
    elif mode == 'dec':
        decrypt_file(sys.argv[2], text, password)
    else:
        print("Mode must be 'enc'/'dec' for encoding/decoding.")
        sys.exit(1)    
    
    
if __name__ == "__main__":
    main()