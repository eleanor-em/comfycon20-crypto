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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Bob {
    private PrintWriter writer;
    private BufferedReader reader;

    private KeyPair keypair;
    private SecretKeySpec keySpec;

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

    // TODO
    private void receivePublicKey(byte[] key) {
        try {
            // 1. Create key factory.
            // 2. Decode provided key.
            // 3. Create key agreement object.
            // 4. Do key agreement.
            // 5. Assign the key.
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
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

        // Create the socket and streams.
        new Thread(() -> {
            try {
                ServerSocket serverSocket = new ServerSocket(Program.PORT);
                Socket socket = serverSocket.accept();

                this.writer = new PrintWriter(socket.getOutputStream(), true);
                this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                // Send our public key to Alice.
                writer.println(Base64.getEncoder().encodeToString(keypair.getPublic().getEncoded()));

                // Receive Alice's public key.
                receivePublicKey(Base64.getDecoder().decode(reader.readLine()));

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
