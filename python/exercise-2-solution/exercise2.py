import os
import socket
import threading
from time import sleep

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

PORT = 10000

print('starting; generating keys may take a minute or two')
# Generate an AES key
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
counter = 0

# Generate DH key pairs
params = dh.generate_parameters(generator=2, key_size=512)
alice_private = params.generate_private_key()
bob_private = params.generate_private_key()

def get_iv():
    global counter
    return counter.to_bytes(12, byteorder='big')

# TODO
def alice_recv_pubkey(bob_pubkey: bytes):
    # should return the shared secret key
    bob_pubkey = load_pem_public_key(bob_pubkey)
    shared_key = alice_private.exchange(bob_pubkey)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None).derive(shared_key)
    return AESGCM(derived_key)

def alice_send(secret_key, msg: bytes):
    ct = secret_key.encrypt(get_iv(), msg, None)
    msg = base64.b64encode(ct)

    print(f'Alice sent:   {msg}')
    return msg

# TODO
def bob_recv_pubkey(alice_pubkey: bytes):
    # should return the shared secret key
    alice_pubkey = load_pem_public_key(alice_pubkey)
    shared_key = bob_private.exchange(alice_pubkey)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None).derive(shared_key)
    return AESGCM(derived_key)

def bob_recv(secret_key, msg: bytes):
    msg = base64.decodebytes(msg)
    msg = secret_key.decrypt(get_iv(), msg, None)
    
    print(f'Bob received: {msg}')

def extract_header(msg: str):
    # Assume messages will be at most 999 chars long
    return int(msg[:3])

def create_header(msg: str):
    # Assume messages will be at most 999 chars long
    return f'{len(msg):03d}'

def bob_listen(sock):
    global counter

    sock.listen()
    client, _ = sock.accept()

    while True:
        # Send our public key to Alice
        pubkey = bob_private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        client.send(bytes(f'{len(pubkey):03d}', 'utf-8'))
        client.send(pubkey)

        # Read Alice's public key
        data = client.recv(3)
        length = extract_header(data)
        alice_key = client.recv(length)
        secret_key = bob_recv_pubkey(alice_key)

        data = client.recv(3)
        length = extract_header(data)
        msg = client.recv(length)
        bob_recv(secret_key, msg)
        counter += 1

# Create server socket
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind(('localhost', PORT))
server_thread = threading.Thread(target=bob_listen, args=(server_sock,))
server_thread.start()

# Create client socket
loaded = False
while not loaded:
    try:
        sleep(0.1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', PORT))
        loaded = True
    except:
        pass

# Send our public key to Bob
pubkey = alice_private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
sock.send(bytes(f'{len(pubkey):03d}', 'utf-8'))
sock.send(pubkey)

# Read Bob's public key
data = sock.recv(3)
length = extract_header(data)
bob_key = sock.recv(length)
secret_key = alice_recv_pubkey(bob_key)

while True:
    try:
        print('Enter a message: ', end='')
        msg = alice_send(secret_key, bytes(input(), 'utf-8'))
        sock.send(bytes(create_header(msg.decode('utf-8')), 'utf-8'))
        sock.send(msg)
        sleep(0.1)
    except EOFError:
        # hacky
        print()
        os._exit(0)
0