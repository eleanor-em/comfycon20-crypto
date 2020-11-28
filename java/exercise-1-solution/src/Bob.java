import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;

public class Bob {
    private PrintWriter writer;
    private BufferedReader reader;

    private int counter;

    // TODO
    private void receiveMessage() throws IOException {
        // EXERCISE 1: Alice is sending messages to Bob that are totally un-encrypted. Use AES-256-GCM to encrypt the
        //             messages.

        // 1. Receive the message
        String message = reader.readLine();

        try {
            // 1. Create the cipher
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            // 2. Create the parameter specification
            GCMParameterSpec spec = new GCMParameterSpec(128, Program.getIV(counter));
            // 3. Initialise the cipher
            cipher.init(Cipher.DECRYPT_MODE, Program.getSecretKeySpec(), spec);
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

    public Bob() {
        // Create the socket and streams.
        new Thread(() -> {
            try {
                ServerSocket serverSocket = new ServerSocket(Program.PORT);
                Socket socket = serverSocket.accept();

                this.writer = new PrintWriter(socket.getOutputStream(), true);
                this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

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
