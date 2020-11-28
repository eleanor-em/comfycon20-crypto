## Java Exercise 3: Digital signatures

Finally, Alice and Bob need to know who they're talking to. Now their first message to each other will be their DH public key... and a signature of it!
We'll just hard-code the signing and verifying keys. In practice, you'd load them from a config file. We will use the state-of-the-art Ed25519 algorithm ([documentation link](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519.html)).

We've added key generation code at the top of the file:
```py
alice_signing = Ed25519PrivateKey.generate()
alice_verify = alice_signing.public_key()

bob_signing = Ed25519PrivateKey.generate()
bob_verify = bob_signing.public_key()
```

as well as some logic to check signatures after connecting:
```py
# Send its signature
sig = bob_sign_message(pubkey)
client.send(bytes(f'{len(sig):03d}', 'utf-8'))
client.send(sig)

# Check Alice's signature
length = extract_header(client.recv(3))
sig = client.recv(length)
if not check_alice_signature(alice_key, sig):
    print("Bob failed to verify Alice's signature")
    os._exit(0)
```

### What now?
You've just implemented an extremely simple end-to-end encrypted messaging system! Fore xtension, try adding a central server (so that it's actually worth it), and any other features you like. If you're feeling adventurous, maybe check out [https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/) for some more advanced crypto tricks.

Also try messing around with different ways to approach the data models etc. Can you think of some pros and cons of the way I've designed the code base?
