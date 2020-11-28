## Java Exercise 2: Key agreement

Now we would like Alice and Bob to do key agreement rather than using a hard-coded key. The following code has been added to generate a secret before connecting to the socket:
```java
try {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256);
    keypair = generator.generateKeyPair();
} catch (Exception e) {
    e.printStackTrace();
    System.exit(-1);
}
```
Note that it's a key-**pair**. The "public key" is the generator combined with the secret, and the "private key" is the secret itself. This is just the terminology Java uses.


We've introduced a new `keySpec` variable for both `Alice` and `Bob` to save our agreed key in, and updated `sendMessage`/`receiveMessage` accordingly. The first message Alice and Bob send to each other should be their public results. This has been done, and it calls a `receivePublicKey()` method.

Once again, Java makes this a bit tedious.

1. Create a key factory.
    ```java
    KeyFactory factory = KeyFactory.getInstance("EC");
    ```

2. Decode the key we received.
    ```java
    X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
    PublicKey alicePublicKey = factory.generatePublic(spec);
    ```

3. Create a `KeyAgreement` object.
    ```java
    KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
    ```
   
4. With this object, call `init()` with your private key and `doPhase()` with the public key (set the second argument to `true`) to create the shared secret.

5. To avoid some technical details, there is a method `getSecretKey()` in `Program` that will take both public keys with the shared secret and produce a `SecretKeySpec`.