# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from utils import mkpair, unpair, read_file_as_bytes, p, g
from validate import valida_certALICE


conn_port = 7777
max_msg_size = 9999
debug = False
password = b""
privatekeyrsa = load_pem_private_key(read_file_as_bytes('alice.key'), password, default_backend())
clientcrtbytes = read_file_as_bytes('alice.crt')
parameters = dh.DHParameterNumbers(p,g).parameters()
privatekeydl = parameters.generate_private_key()
publickeydl = privatekeydl.public_key()
pemdl = publickeydl.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt +=1
        print('Received (%d): %r' % (self.msg_cnt , msg.decode()))
        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        return new_msg if len(new_msg)>0 else None

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    writer.write(pemdl)
    await writer.drain()
    msg = await reader.read(max_msg_size)
    keysigpair, servercertbytes = unpair(msg)
    publicserverkeydlbytes, serversignature = unpair(keysigpair)
    cert = x509.load_pem_x509_certificate(servercertbytes)

    if not valida_certALICE(cert):
        if debug: print("Certificado inválido!")
        return
    
    publicserverkeyrsa = cert.public_key()
    message = publicserverkeydlbytes + pemdl

    try:
        publicserverkeyrsa.verify(serversignature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    except:
        if debug: print("Assinatura inválida")
        return
    
    message = pemdl + publicserverkeydlbytes
    signature = privatekeyrsa.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    writer.write(mkpair(signature, clientcrtbytes))
    publicserverkeydl = load_pem_public_key(publicserverkeydlbytes)
    sharedkey = privatekeydl.exchange(publicserverkeydl)
    hkdf = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=None)
    key = hkdf.derive(sharedkey)
    msg = client.process()

    while msg:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        cryptedmessage = aesgcm.encrypt(nonce,msg,password)
        writer.write(nonce + cryptedmessage)
        msg = await reader.read(max_msg_size)

        if msg :
            msg = client.process(msg)
        else:
            break

    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()