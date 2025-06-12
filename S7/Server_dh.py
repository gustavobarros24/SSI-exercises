# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from utils import password,g,p


conn_cnt = 0
conn_port = 7777
max_msg_size = 9999
parameters = dh.DHParameterNumbers(p,g).parameters()
privatekey = parameters.generate_private_key()
publickey = privatekey.public_key()
pem =  publickey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.shared_key = None
        self.key = None

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        nonce = msg[:12]
        cryptedmessage = msg[12:]
        aesgcm = AESGCM(self.key)
        decryptedmessage = aesgcm.decrypt(nonce, cryptedmessage, password)
        txt = msg.decode()
        print('%d : %r' % (self.id,txt))
        new_msg = txt.upper().encode()
        return new_msg if len(new_msg)>0 else None

async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    writer.writer(pem)
    await writer.drain()
    data = await reader.read(max_msg_size)
    publicclienkey = load_pem_public_key(data)
    sharedkey = privatekey.exchange(publicclienkey)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None)
    key = hkdf.derive(sharedkey)
    srvwrk.key = key
    data = await reader.read(max_msg_size)

    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)

    print("[%d]" % srvwrk.id)
    writer.close()

def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()