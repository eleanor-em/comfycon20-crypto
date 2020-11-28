## Java Exercise 2: Key agreement

Now we would like Alice and Bob to do key agreement rather than using a hard-coded key. The following code has been added to generate secrets before connecting to the socket:
```python
# Generate DH key pairs
params = dh.generate_parameters(generator=2, key_size=512)
alice_private = params.generate_private_key()
bob_private = params.generate_private_key()
```
Note that it's a key-**pair**. The "public key" is the generator combined with the secret, and the "private key" is the secret itself. This is just the terminology the library uses. Unfortunately I don't think this library supports ECDH, so we'll have to use old-school DH. 512 bits for the key size is far too small, but it takes too long to generate the key at realistic sizes (2048 or preferably 3072 bits).

We've updated our send/receive functions to use a key passed in the argument:
```py
def alice_send(secret_key, msg: bytes):
    ct = secret_key.encrypt(get_iv(), msg, None)
    msg = base64.b64encode(ct)

    print(f'Alice sent:   {msg}')
    return msg
```
and some extra logic after first connecting on the socket to send our public keys:
```py
# Send our public key to Alice
pubkey = bob_private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
client.send(bytes(f'{len(pubkey):03d}', 'utf-8'))
client.send(pubkey)

# Read Alice's public key
data = client.recv(3)
length = extract_header(data)
alice_key = client.recv(length)
secret_key = bob_recv_pubkey(alice_key)
```
The `PEM` encoding is just one easy choice out of many possibilities. You'll need to use `load_pem_public_key()`
to decode the public key from the received message ([documentation link](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization.html#cryptography.hazmat.primitives.serialization.load_pem_private_key)).

Then, you will need to use a **key derivation function** (KDF) to create a shared key from the secret. (If you don't, it won't be properly random!) See the second example [in this documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh.html) for guidance.