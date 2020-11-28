import os
import socket
import threading
from time import sleep

import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = 10000

# Generate an AES key
key = AESGCM.generate_key(bit_length=256)
secret_key = AESGCM(key)
counter = 0

def get_iv():
    global counter
    return counter.to_bytes(12, byteorder='big')

# TODO
def alice_send(msg: bytes):
    # 1. Encrypt the message
    # 2. Encode with base 64

    # 3. Return encrypted message
    print(f'Alice sent:   {msg}')
    return msg

# TODO
def bob_recv(msg: bytes):
    # 1. Decode with base 64
    # 2. Decrypt the message
    
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
        data = client.recv(3)
        length = extract_header(data)
        msg = client.recv(length)
        bob_recv(msg)
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

while True:
    try:
        print('Enter a message: ', end='')
        msg = alice_send(bytes(input(), 'utf-8'))
        sock.send(bytes(create_header(msg.decode('utf-8')), 'utf-8'))
        sock.send(msg)
        sleep(0.1)
    except EOFError:
        # hacky
        print()
        os._exit(0)
