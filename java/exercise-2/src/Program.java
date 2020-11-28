import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
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

    public static byte[] getIV(int n) {
        return ByteBuffer.allocate(4).putInt(n).array();
    }

    public static SecretKeySpec getSecretKey(PublicKey alice, PublicKey bob, byte[] secret) {
        try {
            // For technical reasons, the secret we get from ECDH needs to be hashed first.
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(secret);
            hash.update(alice.getEncoded());
            hash.update(bob.getEncoded());
            return new SecretKeySpec(hash.digest(), "AES");
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
            return null;
        }
    }
}
