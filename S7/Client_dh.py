# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
from utils import password,g,p


conn_port = 7777
max_msg_size = 9999
parameters = dh.DHParameterNumbers(p,g).parameters()
privatekey = parameters.generate_private_key()
publickey = privatekey.public_key()
pem = publickey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


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



#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    writer.write(pem)
    await writer.drain()
    msg = await reader.read(max_msg_size)
    publicserverkey = load_pem_public_key(msg)
    sharedkey=privatekey.exchange(publicserverkey)
    hkdf = HKDF(algorithm=hashes.SHA256, length=32, salt=None, info=None)
    key = hkdf.derive(sharedkey)
    msg = client.process()

    while msg:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        cryptedmessage = aesgcm.encrypt(nonce,msg,password)
        writer.write(msg)
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