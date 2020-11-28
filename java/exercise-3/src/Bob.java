import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Bob {
    private PrintWriter writer;
    private BufferedReader reader;

    private KeyPair keypair;
    private SecretKeySpec keySpec;

    private PrivateKey signingKey;
    public static PublicKey verifyingKey;

    private int counter;

    private void receiveMessage() throws IOException {
        // 1. Receive the message
        String message = reader.readLine();

        try {
            // 1. Create the cipher
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            // 2. Create the parameter specification
            GCMParameterSpec spec = new GCMParameterSpec(128, Program.getIV(counter));
            // 3. Initialise the cipher
            cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
            // 4. Decode the message from base 64
            byte[] ciphertext = Base64.getDecoder().decode(message);
            // 5. Decrypt the message with doFinal()
            message = new String(cipher.doFinal(ciphertext));

            // 6. Print the result
            System.out.println("Bob received: " + message);

            ++counter;
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private void receivePublicKey(byte[] key) {
        try {
            // 1. Create key factory.
            KeyFactory factory = KeyFactory.getInstance("EC");
            // 2. Decode provided key.
            X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
            PublicKey alicePublicKey = factory.generatePublic(spec);

            // 3. Create key agreement object.
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            // 4. Do key agreement.
            agreement.init(keypair.getPrivate());
            agreement.doPhase(alicePublicKey, true);

            // 5. Assign the key.
            keySpec = Program.getSecretKey(alicePublicKey, keypair.getPublic(), agreement.generateSecret());
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    // TODO
    private void createSigningKey() {
        try {
            // 1. Create a KeyPairGenerator and initialise it.
            // 2. Generate a key pair.
            // 3. Save the keys in our attributes.
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    // TODO
    private String signMessage(String message) {
        try {
            // 1. Create Signature object.
            // 2. Initialise with the signing key.
            // 3. Update with the message bytes.
            // 4. Create the final signature (encoded in base 64)
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
        return null;
    }

    // TODO
    public boolean checkAliceSignature(String message, byte[] signature) {
        try {
            // 1. Create Signature object.
            // 2. Initialise with the verifying key.
            // 3. Update with the message bytes.
            // 4. Verify the signature.
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
        return false;
    }

    public Bob() {
        // Generate a keypair.
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            keypair = generator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }

        createSigningKey();

        // Create the socket and streams.
        new Thread(() -> {
            try {
                ServerSocket serverSocket = new ServerSocket(Program.PORT);
                Socket socket = serverSocket.accept();

                this.writer = new PrintWriter(socket.getOutputStream(), true);
                this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                // Send our public key to Alice and its signature.
                String message = Base64.getEncoder().encodeToString(keypair.getPublic().getEncoded());
                writer.println(message);
                writer.println(signMessage(message));

                // Receive Alice's public key.
                message = reader.readLine();
                receivePublicKey(Base64.getDecoder().decode(message));

                // Check Alice's signature.
                if (!checkAliceSignature(message, Base64.getDecoder().decode(reader.readLine()))) {
                    System.out.println("Alice failed to verify Bob's signature.");
                    System.exit(-1);
                }

                while (true) {
                    receiveMessage();
                }
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(-1);
            }
        }).start();
    }
}
