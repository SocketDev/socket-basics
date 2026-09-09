// Fixtures for java-insecure-random.
import java.util.Random;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class InsecureRandom {
    void weakSecurityValues() {
        Random rnd = new Random();
        // ruleid: java-insecure-random
        String sessionToken = Long.toString(rnd.nextLong(), 36);
        // ruleid: java-insecure-random
        String csrf = Long.toString(rnd.nextLong(), 36);
        // ruleid: java-insecure-random
        String otp = Integer.toString(rnd.nextInt(999999));
        // ruleid: java-insecure-random
        String apiKey = Long.toString(rnd.nextLong(), 36);
    }

    void weakKeyMaterial() {
        byte[] key = new byte[16];
        new Random().nextBytes(key);
        // ruleid: java-insecure-random
        new SecretKeySpec(key, "AES");
    }

    void weakIvMaterial() {
        byte[] iv = new byte[12];
        new java.util.Random().nextBytes(iv);
        // ruleid: java-insecure-random
        new IvParameterSpec(iv);
    }

    // Ordinary non-security uses. The short credential words must not match as
    // substrings of these identifiers.
    void ordinary() {
        Random rnd = new Random();
        // ok: java-insecure-random
        int pivot = rnd.nextInt(10);
        // ok: java-insecure-random
        int divisor = rnd.nextInt(10);
        // ok: java-insecure-random
        int spinner = rnd.nextInt(4);
        // ok: java-insecure-random
        int monkey = rnd.nextInt(4);
        // ok: java-insecure-random
        String author = Integer.toString(rnd.nextInt(4));
        // ok: java-insecure-random
        int jitterMs = rnd.nextInt(250);
    }

    // camelCase and SNAKE_CASE forms of the short words still count.
    void shortWordsThatDoCount() {
        Random rnd = new Random();
        // ruleid: java-insecure-random
        String resetPin = Integer.toString(rnd.nextInt(9999));
        // ruleid: java-insecure-random
        String AUTH_VALUE = Long.toString(rnd.nextLong());
    }
}
