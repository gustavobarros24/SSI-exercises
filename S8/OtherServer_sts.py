# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from utils import mkpair, unpair, read_file_as_bytes, p, g, verify_certificate_signature, get_userdata
from validate import cert_validtime

conn_cnt = 0
conn_port = 7777
max_msg_size = 9999
debug = False


if len(sys.argv) != 2:
    print(f"Usage: python {sys.argv[0]} <server_p12_file>")
    sys.exit(1)

p12_filepath = sys.argv[1]


try:
    privatekeyrsa, servercrt, _ = get_userdata(p12_filepath)
    servercrtbytes = servercrt.public_bytes(serialization.Encoding.PEM)
except FileNotFoundError:
    print(f"Error: P12 file not found at '{p12_filepath}'")
    sys.exit(1)
except Exception as e:
    print(f"Error loading P12 file: {e}")
    sys.exit(1)


cacrt = x509.load_pem_x509_certificate(read_file_as_bytes('VAULT_CA.crt'))


parameters = dh.DHParameterNumbers(p,g).parameters()
privatekeydl = parameters.generate_private_key()
publickeydl = privatekeydl.public_key()
pemdl = publickeydl.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.key = None 
        self.aesgcm = None

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Assume msg is already decrypted.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        txt = msg.decode()
        print('%d : %r' % (self.id,txt))
        new_msg = txt.upper().encode()
        return new_msg if len(new_msg)>0 else None


#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)

    try:
        # Handshake Start
        # 1. Receive Client's DH Public Key
        client_pemdl = await reader.read(max_msg_size)
        if not client_pemdl:
            print(f"[{srvwrk.id}] Client disconnected during handshake (step 1)")
            return

        # 2. Send Server's DH Public Key, Signature, and Certificate
        publicclientkeydl = load_pem_public_key(client_pemdl)
        message_to_sign = pemdl + client_pemdl
        serversignature = privatekeyrsa.sign(
            message_to_sign,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        keysigpair = mkpair(pemdl, serversignature)
        writer.write(mkpair(keysigpair, servercrtbytes))
        await writer.drain()

        # 3. Receive Client's Signature and Certificate
        sig_cert_pair = await reader.read(max_msg_size)
        if not sig_cert_pair:
            print(f"[{srvwrk.id}] Client disconnected during handshake (step 3)")
            return
        clientsignature, clientcrtbytes = unpair(sig_cert_pair)

        # 4. Validate Client Certificate
        try:
            clientcrt = x509.load_pem_x509_certificate(clientcrtbytes)
            verify_certificate_signature(clientcrt,cacrt.public_key())

            cert_validtime(clientcrt)

            if debug: print(f"[{srvwrk.id}] Client certificate validated successfully.")
        except Exception as e:
            print(f"[{srvwrk.id}] Client certificate validation failed: {e}")
            writer.close()
            return

        # 5. Verify Client Signature
        publicclientkeyrsa = clientcrt.public_key()
        message_expected = client_pemdl + pemdl
        try:
            publicclientkeyrsa.verify(
                clientsignature,
                message_expected,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print(f"[{srvwrk.id}] Client signature verified successfully.")
        except Exception as e:
            print(f"[{srvwrk.id}] Client signature verification failed: {e}")
            writer.close()
            return

        # 6. Derive Shared Key and AES Key
        sharedkey = privatekeydl.exchange(publicclientkeydl)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None, backend=default_backend())
        srvwrk.key = hkdf.derive(sharedkey)
        srvwrk.aesgcm = AESGCM(srvwrk.key)
        print(f"[{srvwrk.id}] Secure channel established.")
        #Handshake End


        #Secure Communication Loop
        while True:
            encrypted_data = await reader.read(max_msg_size)
            if not encrypted_data or encrypted_data == b'\n':
                if encrypted_data == b'\n': print(f"[{srvwrk.id}] Client requested disconnect.")
                else: print(f"[{srvwrk.id}] Client disconnected.")
                break

            try:
                nonce = encrypted_data[:12]
                ciphertext = encrypted_data[12:]
                decrypted_data = srvwrk.aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as e:
                print(f"[{srvwrk.id}] Decryption failed: {e}. Closing connection.")
                break

            response_data = srvwrk.process(decrypted_data)
            if not response_data:
                print(f"[{srvwrk.id}] No response generated, closing connection.")
                break

            response_nonce = os.urandom(12)
            encrypted_response = srvwrk.aesgcm.encrypt(response_nonce, response_data, None)

            writer.write(response_nonce + encrypted_response)
            await writer.drain()

    except ConnectionResetError:
        print(f"[{srvwrk.id}] Connection reset by peer.")
    except Exception as e:
        print(f"[{srvwrk.id}] An error occurred: {e}")
    finally:
        print(f"[{srvwrk.id}] Closing connection.")
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()