import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Base64;

public class Alice {
    private PrintWriter writer;
    private BufferedReader reader;

    private int counter;

    // TODO
    public void sendMessage(String message) {
        // EXERCISE 1: Alice is sending messages to Bob that are totally un-encrypted. Use AES-256-GCM to encrypt the
        //             messages.
        try {
            // 1. Create the cipher
            // 2. Create the parameter specification
            // 3. Initialise the cipher
            // 4. Encrypt the message with doFinal()
            // 5. Encode to base 64
            // 6. Send the message
            writer.println(message);
            System.out.println("Alice sent:   " + message);

            ++counter;
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    public Alice() {
        boolean loaded = false;

        while (!loaded) {
            try {
                // Create the socket and streams; keep trying until the socket is open
                Socket socket = new Socket(Program.ADDRESS, Program.PORT);
                this.writer = new PrintWriter(socket.getOutputStream(), true);
                this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
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
