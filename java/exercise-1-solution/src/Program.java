import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class Program {
    public static final String ADDRESS = "localhost";
    public static final int PORT = 30000;

    private static SecretKeySpec secretKeySpec;

    public static void main(String[] args) {
        Bob bob = new Bob();
        Alice alice = new Alice();
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("Enter a message: ");
            String message = scanner.nextLine();

            alice.sendMessage(message);
            try { Thread.sleep(100); } catch (InterruptedException e) { e.printStackTrace(); }
        }
    }

    public synchronized static SecretKeySpec getSecretKeySpec() {
        // Generates a secret key if we haven't already, and return it.
        if (secretKeySpec == null) {
            // We have to create a "key generator", then create a "key"... and to use it, create a "SecretKeySpec".
            // Classic Java.

            KeyGenerator generator = null;
            try {
                generator = KeyGenerator.getInstance("AES");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                System.exit(-1);
            }

            // AES-256 is state of the art.
            generator.init(256);
            SecretKey key = generator.generateKey();
            secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");
        }

        return secretKeySpec;
    }

    public static byte[] getIV(int n) {
        return ByteBuffer.allocate(4).putInt(n).array();
    }
}
