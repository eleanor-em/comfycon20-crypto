## Java Exercise 1: Symmetric-key Cryptography

The code provided allows Alice to send messages to Bob, implementing a simple "echo server". Right now, the messages are sent in the clear. Your task is to encrypt Alice's messages using the state-of-the-art `AES-256-GCM` cryptosystem.

We will use the library [cryptography.io](https://cryptography.io/en/latest/hazmat/primitives/aead.html#cryptography.hazmat.primitives.ciphers.aead.AESGCM). To install, run `pip install cryptography` (or however else you like to install Python packages). The link above contains some relevant documentation. (In practice, you would not use the low-level functions like we've done here. This is just to give you some exposure to the fine details.)

You need to modify:
1. the `alice_send` function
2. the `bob_recv` function

Unlike Java, Python makes this fairly straightforward. We first generate a key, then initialise a `counter`. An important practical issue with symmetric-key ciphers is they require **initialisation vectors** (IVs). You must never, ever use the same IV twice with the same key.

We'll just count the number of messages we've sent, and use that as our IV. To encrypt, use `secret_key.encrypt()`; to decrypt, use `secret_key.decrypt()`. Set the `associated_data` parameter to `None`: this is used when you want to send some plaintext along with the encrypted text.

### Encoding and decoding
As we discussed earlier, encryption gives us a bunch of numbers. To send this in a human-readable form, we need to **encode** it. The standard approach uses **base 64**: encoding binary data in letters, numbers, and the `/+` symbols.

```py
msg = base64.b64encode(ct)
```

To decode, you can use `base64.decodebytes()`.