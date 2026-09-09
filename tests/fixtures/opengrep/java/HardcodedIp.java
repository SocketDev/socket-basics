// Fixtures for java-hardcoded-ip.
public class HardcodedIp {
    // ruleid: java-hardcoded-ip
    static final String A = "10.0.0.1";
    // ruleid: java-hardcoded-ip
    static final String B = "10.0.0.1:8080";
    // ruleid: java-hardcoded-ip
    static final String C = "192.168.1.1";
    // ruleid: java-hardcoded-ip
    static final String D = "172.16.4.9";

    // Version strings, not addresses.
    // ok: java-hardcoded-ip
    static final String E = "10.0";
    // ok: java-hardcoded-ip
    static final String F = "10.2.3";
    // Loopback and wildcard bind are not infrastructure disclosure.
    // ok: java-hardcoded-ip
    static final String G = "127.0.0.1";
    // ok: java-hardcoded-ip
    static final String H = "0.0.0.0";
}
