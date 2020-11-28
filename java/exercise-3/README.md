## Java Exercise 3: Digital signatures

Finally, Alice and Bob need to know who they're talking to. Now their first message to each other will be their ECDH public key... and a signature of it!
We'll just hard-code the signing and verifying keys. In practice, you'd load them from a config file.

Your task (for both `Alice` and `Bob`) is to:
1. Write `createSigningKey()`:
    1. Create a `KeyPairGenerator` object: (256 bits is considered secure for elliptic curves)
        ```java
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
        ```
       
    2. Create a `KeyPair` object:
        ```java
        KeyPair pair = generator.generateKeyPair();
        ```
       
    3. Save the public and private keys in the freshly-created `signingKey` and `verifyingKey attributes.
    
2. Write `signMessage()`:
    1. Create a `Signature` object:
        ```java
        Signature sig = Signature.getInstance("SHA256withECDSA");
       ```
    2. Using this object, call the `initSign()` method with the signing key.
    
    3. Also call the `update()` method with the message bytes.
    
    4. Encode the result of `sign()` to base 64 and return it.

3. Write `checkBobSignature()`/`checkAliceSignature()`. This is very similar to `signMessage()` but using `verify` instead of `sign` for the methods.

### What now?
You've just implemented an extremely simple end-to-end encrypted messaging system! Fore xtension, try adding a central server (so that it's actually worth it), and any other features you like. If you're feeling adventurous, maybe check out [https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/](https://soatok.blog/2020/11/14/going-bark-a-furrys-guide-to-end-to-end-encryption/) for some more advanced crypto tricks.