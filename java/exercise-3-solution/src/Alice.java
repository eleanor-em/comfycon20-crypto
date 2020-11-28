import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Alice {
    private PrintWriter writer;
    private BufferedReader reader;

    private SecretKeySpec keySpec;
    private KeyPair keypair;

    private PrivateKey signingKey;
    public static PublicKey verifyingKey;

    private int counter;

    public void sendMessage(String message) {
        try {
            // 1. Create the cipher
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            // 2. Create the parameter specification
            GCMParameterSpec spec = new GCMParameterSpec(128, Program.getIV(counter));
            // 3. Initialise the cipher
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
            // 4. Encrypt the message with doFinal()
            byte[] ciphertext = cipher.doFinal(message.getBytes());
            // 5. Encode to base 64
            message = Base64.getEncoder().encodeToString(ciphertext);
            // 6. Send the message
            writer.println(message);
            System.out.println("Alice sent:   " + message);

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
            PublicKey bobPublicKey = factory.generatePublic(spec);

            // 3. Create key agreement object.
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            // 4. Do key agreement.
            agreement.init(keypair.getPrivate());
            agreement.doPhase(bobPublicKey, true);

            // 5. Assign the key.
            keySpec = Program.getSecretKey(keypair.getPublic(), bobPublicKey, agreement.generateSecret());
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    // TODO
    private void createSigningKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            KeyPair pair = generator.generateKeyPair();
            signingKey = pair.getPrivate();
            verifyingKey = pair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    // TODO
    private String signMessage(String message) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(signingKey);
            sig.update(message.getBytes());
            return Base64.getEncoder().encodeToString(sig.sign());
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
            return null;
        }
    }

    // TODO
    public boolean checkBobSignature(String message, byte[] signature) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(Bob.verifyingKey);
            sig.update(message.getBytes());
            return sig.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
            return false;
        }
    }

    public Alice() {
        boolean loaded = false;

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

        while (!loaded) {
            try {
                // Create the socket and streams; keep trying until the socket is open.
                Socket socket = new Socket(Program.ADDRESS, Program.PORT);
                this.writer = new PrintWriter(socket.getOutputStream(), true);
                this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                // Send our public key to Bob and its signature.
                String message = Base64.getEncoder().encodeToString(keypair.getPublic().getEncoded());
                writer.println(message);
                writer.println(signMessage(message));

                // Receive Bob's public key.
                message = reader.readLine();
                receivePublicKey(Base64.getDecoder().decode(message));

                // Check Bob's signature.
                if (!checkBobSignature(message, Base64.getDecoder().decode(reader.readLine()))) {
                    System.out.println("Alice failed to verify Bob's signature.");
                    System.exit(-1);
                }

                loaded = true;
            } catch (IOException ignored) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    System.exit(-1);
                }
            }
        }
    }
}
