// Fixtures for java-weak-cipher.
// "ruleid:" marks a line that must be reported; "ok:" a line that must not be.
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class WeakCipher {
    void broken() throws Exception {
        // ruleid: java-weak-cipher
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ruleid: java-weak-cipher
        javax.crypto.Cipher.getInstance("DESede/CBC/PKCS5Padding", "SunJCE");
        // ruleid: java-weak-cipher
        Cipher.getInstance("Blowfish");
        // ruleid: java-weak-cipher
        Cipher.getInstance("RC4");
        // ECB really is a block mode here.
        // ruleid: java-weak-cipher
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ruleid: java-weak-cipher
        new SecretKeySpec(new byte[8], "DES");
    }

    void fine() throws Exception {
        // ok: java-weak-cipher
        Cipher.getInstance("AES/GCM/NoPadding");
        // In an RSA transformation "ECB" is a JCA placeholder, not a block mode.
        // ok: java-weak-cipher
        Cipher.getInstance("RSA/ECB/PKCS1Padding");
        // ok: java-weak-cipher
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // ok: java-weak-cipher
        new SecretKeySpec(new byte[32], "AES");
    }
}
