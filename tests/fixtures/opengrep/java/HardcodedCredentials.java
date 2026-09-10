// Fixtures for java-hardcoded-credentials.
public class HardcodedCredentials {
    // ruleid: java-hardcoded-credentials
    private static final String DEFAULT_PASSWORD = "webgoat";
    // ruleid: java-hardcoded-credentials
    private static final String ADMIN_PASSWORD = "admin";
    // ruleid: java-hardcoded-credentials
    static final String LEAKED_TOKEN = "STAGING-TOKEN-42";
    // Hyphenated but digit bearing, so a real key rather than a header name.
    // ruleid: java-hardcoded-credentials
    static final String API_KEY = "sk-live-9f8e7d6c5b4a";
    // ruleid: java-hardcoded-credentials
    static final String SLACK_TOKEN = "xoxb-2409januaryfake-99";

    // Weak defaults that contain the keyword but also a digit, so they are
    // values rather than a restatement of the field name.
    // ruleid: java-hardcoded-credentials
    static final String LEGACY_PASSWORD = "password123";
    // ruleid: java-hardcoded-credentials
    static final String DB_SECRET = "secret_2024";

    // Header names, not secrets.
    // ok: java-hardcoded-credentials
    public static final String ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
    // ok: java-hardcoded-credentials
    public static final String SEC_TOKEN_BINDING = "Sec-Token-Binding";
    // ok: java-hardcoded-credentials
    public static final String CSRF_TOKEN_HEADER = "X-CSRF-TOKEN";
    // Auth scheme names.
    // ok: java-hardcoded-credentials
    public static final String TOKEN_TYPE = "Bearer";
    // Property paths and class names.
    // ok: java-hardcoded-credentials
    public static final String JAVA_NET_SOCKS_PASSWORD = "java.net.socks.password";
    // ok: java-hardcoded-credentials
    static final String SHARED_SECRETS_CLASSNAME = "sun.misc.SharedSecrets";
    // Values that merely restate the keyword, including snake_case forms.
    // ok: java-hardcoded-credentials
    private static final String AUTH_PASSWORD = "password";
    // A capitalised restatement is a UI label.
    // ok: java-hardcoded-credentials
    private static final String PASSWORD_LABEL = "Password";
    // ok: java-hardcoded-credentials
    public static final String ACCESSKEY_ATTRIBUTE = "accesskey";
    // ok: java-hardcoded-credentials
    static final String TOKEN_PARAM = "access_token";
    // ok: java-hardcoded-credentials
    static final String PASSWORD_FIELD = "j_password";
    // ok: java-hardcoded-credentials
    private static final String CREDENTIALS_HEADER = "stompCredentials";
    // Map keys and attribute names, matched only by a bare "key".
    // ok: java-hardcoded-credentials
    public static final String KEY_ATTRIBUTE = "key";
    // ok: java-hardcoded-credentials
    public static final String SEC_WEBSOCKET_KEY1 = "Sec-WebSocket-Key1";
}
