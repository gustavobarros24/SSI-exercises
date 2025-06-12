import sys, os
from cryptography.hazmat.primitives.serialization import pkcs12
import os

from cryptography.hazmat.primitives.asymmetric import padding ,rsa
from datetime import datetime


password = "password".encode('utf-8')
# key = b'w:8\x8cZ\x8d\xff\xefg5X\x18\x98\xb6\xbbN'

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

def read_file_as_bytes(file_path: str) -> bytes:
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    with open(file_path, 'rb') as file:
        byte_list = file.read()
    return byte_list

def write_bytes_to_file(file_path: str, byte_list: bytes):
    with open(file_path, 'wb') as file:
        file.write(byte_list)

def mkpair(x, y):
    """produz uma byte-string contendo o tuplo '(x,y)' ('x' e 'y' são byte-strings)"""
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    """extrai componentes de um par codificado com 'mkpair'"""
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    password = None
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
    return (private_key, user_cert, ca_cert)

def verify_certificate_signature(cert, ca_public_key):
    """Verifica a assinatura do certificado com o padding apropriado"""
    if isinstance(ca_public_key, rsa.RSAPublicKey):
        if 'pss' in cert.signature_algorithm_oid._name.lower():
            pad = padding.PSS(
                mgf=padding.MGF1(cert.signature_hash_algorithm),
                salt_length=padding.PSS.MAX_LENGTH
            )
        else:
            pad = padding.PKCS1v15()
        
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            pad,
            cert.signature_hash_algorithm,
        )
    else:
        raise ValueError("CA public key is not RSA, unsupported key type")
    
def log_response(response_text, log_file="../logs/logs.txt"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {response_text}\n")

def clear_logs(log_file="logs.txt"):
    with open(log_file, "w", encoding="utf-8") as f:
        pass