## Java Exercise 1: Symmetric-key Cryptography

The code provided allows Alice to send messages to Bob, implementing a simple "echo server". Right now, the messages are sent in the clear. Your task is to encrypt Alice's messages using the state-of-the-art `AES-256-GCM` cryptosystem.

You need to modify:
1. the `sendMessage` method in the `Alice` class
1. the `receiveMessage` method in the `Bob` class

Java (as usual) is a bit verbose, so here's a quick guide to encrypting messages. (Type this yourself for the muscle memory!)
1. Create a `Cipher`.

    ```java
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    ```

2. Create a `SecretKeySpec` -- this is your symmetric key. The `Program` class contains a method `getSecretKeySpec()` to help you with the boilerplate.

3. Now we need an **initialisation vector** (IV) to combine with our cipher. You must never, ever use the same IV twice with the same key. For our purposes, we can just count the number of messages we've sent, and use the `Program` class' `getIV()` method to help us out.

4. Create a `GCMParameterSpec` with our IV:

    ```java
    GCMParameterSpec spec = new GCMParameterSpec(128, Program.getIV(counter));
    ```
   
5. Initialise our `Cipher`. (Note: you need to use `DECRYPT_MODE` when decrypting.)
    ```java
    cipher.init(Cipher.ENCRYPT_MODE, Program.getSecretKeySpec(), spec);
    ```

6. Encrypt the message!
    ```java
    byte[] ciphertext = cipher.doFinal(message.getBytes());
    ```
   
### Encoding and decoding
As we discussed earlier, encryption gives us a bunch of numbers (a `byte[]`). To send this in a human-readable form, we need to **encode** it. The standard approach uses **base 64**: encoding binary data in letters, numbers, and the `/+` symbols.

```java
message = Base64.getEncoder().encodeToString(ciphertext);
```

To decode, you can use `Base64.getDecoder().decode()`.