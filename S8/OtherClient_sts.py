# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
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

conn_port = 7777
max_msg_size = 9999
debug = True
password = None

if len(sys.argv) != 2:
    print(f"Usage: python {sys.argv[0]} <client_p12_file>")
    sys.exit(1)

p12_filepath = sys.argv[1]

try:
    privatekeyrsa, clientcrt, _ = get_userdata(p12_filepath)
    clientcrtbytes = clientcrt.public_bytes(serialization.Encoding.PEM)
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


class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.key = None
        self.aesgcm = None

    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) DECRYPTED enviada pelo SERVIDOR.
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

    try:
        #Handshake Start
        # 1. Send Client's DH Public Key
        writer.write(pemdl)
        await writer.drain()
        if debug: print("Sent Client DH public key.")

        # 2. Receive Server's DH Public Key, Signature, and Certificate
        msg = await reader.read(max_msg_size)
        if not msg:
            print("Server disconnected during handshake (step 2)")
            return
        keysigpair, servercertbytes = unpair(msg)
        publicserverkeydlbytes, serversignature = unpair(keysigpair)
        if debug: print("Received Server DH public key, signature, and certificate.")

        # 3. Validate Server Certificate
        try:
            servercrt = x509.load_pem_x509_certificate(servercertbytes)
            
            verify_certificate_signature(servercrt, cacrt.public_key())
            
            cert_validtime(servercrt)
            
            if debug: print("Server certificate validated successfully.")
        except Exception as e:
            print(f"Server certificate validation failed: {e}")
            writer.close()
            return

        # 4. Verify Server Signature
        publicserverkeyrsa = servercrt.public_key()
        message_expected = publicserverkeydlbytes + pemdl
        try:
            publicserverkeyrsa.verify(
                serversignature,
                message_expected,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            if debug: print("Server signature verified successfully.")
        except Exception as e:
            print(f"Server signature verification failed: {e}")
            writer.close()
            return

        # 5. Send Client's Signature and Certificate
        message_to_sign = pemdl + publicserverkeydlbytes
        clientsignature = privatekeyrsa.sign(
            message_to_sign,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        writer.write(mkpair(clientsignature, clientcrtbytes))
        await writer.drain()
        if debug: print("Sent Client signature and certificate.")

        # 6. Derive Shared Key and AES Key
        publicserverkeydl = load_pem_public_key(publicserverkeydlbytes)
        sharedkey = privatekeydl.exchange(publicserverkeydl)
        hkdf = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=None, backend=default_backend())
        client.key = hkdf.derive(sharedkey)
        client.aesgcm = AESGCM(client.key)
        if debug: print("Secure channel established.")
        #Handshake End

        #Secure Communication Loop
        msg_to_send = client.process()

        while msg_to_send:
            nonce = os.urandom(12)
            encrypted_message = client.aesgcm.encrypt(nonce, msg_to_send, password)

            writer.write(nonce + encrypted_message)
            await writer.drain()

            encrypted_response = await reader.read(max_msg_size)
            if not encrypted_response or encrypted_response == b'\n':
                if encrypted_response == b'\n': print("Server requested disconnect.")
                else: print("Server disconnected.")
                break

            try:
                response_nonce = encrypted_response[:12]
                response_ciphertext = encrypted_response[12:]
                decrypted_response = client.aesgcm.decrypt(response_nonce, response_ciphertext, password)
            except Exception as e:
                print(f"Decryption failed: {e}. Closing connection.")
                break

            msg_to_send = client.process(decrypted_response)

        if not msg_to_send:
             writer.write(b'\n')
             await writer.drain()

    except ConnectionResetError:
        print("Connection reset by peer.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print('Socket closed!')
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()