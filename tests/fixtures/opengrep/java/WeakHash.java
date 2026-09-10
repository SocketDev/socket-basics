// Fixtures for java-weak-crypto-sha1 and java-weak-crypto-md5.
import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

public class WeakHash {
    void sha1(byte[] data) throws Exception {
        // ruleid: java-weak-crypto-sha1
        MessageDigest.getInstance("SHA-1");
        // ruleid: java-weak-crypto-sha1
        java.security.MessageDigest.getInstance("SHA1", "SUN");
        // ruleid: java-weak-crypto-sha1
        DigestUtils.sha1(data);
        // ruleid: java-weak-crypto-sha1
        DigestUtils.sha1Hex(data);
        // Both fully qualified spellings, which servlet code routinely writes.
        // ruleid: java-weak-crypto-sha1
        org.apache.commons.codec.digest.DigestUtils.sha1(data);
        // ruleid: java-weak-crypto-sha1
        org.apache.commons.codec.digest.DigestUtils.sha1Hex(data);
    }

    void md5(byte[] data) throws Exception {
        // ruleid: java-weak-crypto-md5
        java.security.MessageDigest.getInstance("MD5");
        // ruleid: java-weak-crypto-md5
        org.apache.commons.codec.digest.DigestUtils.md5Hex(data);
    }

    void fine(byte[] data) throws Exception {
        // ok: java-weak-crypto-sha1
        // ok: java-weak-crypto-md5
        MessageDigest.getInstance("SHA-256");
        // ok: java-weak-crypto-sha1
        DigestUtils.sha256Hex(data);
    }
}
