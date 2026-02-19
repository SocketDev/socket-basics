#!/usr/bin/env python3
"""
Phase 3: Rewrite sparse rule messages and add fix metadata.

This script:
  1. Rewrites messages shorter than 60 characters to follow a "What/Why/How" pattern
  2. Adds `fix` metadata to all CRITICAL and HIGH severity rules that lack one

It uses a string-based approach to modify lines in-place without reformatting the
entire YAML file, preserving comments and formatting.

Usage:
    python scripts/rewrite_messages.py
"""

import os
import re
import sys
import yaml

# ---------------------------------------------------------------------------
# CWE -> Expanded message (What/Why/How pattern, 120-250 chars)
# Only used when existing message < 60 characters.
# ---------------------------------------------------------------------------

CWE_MESSAGES = {
    "CWE-89": "SQL injection vulnerability detected. User-supplied input is included in a SQL query without sanitization, potentially allowing attackers to read, modify, or delete database contents. Use parameterized queries or an ORM instead of string concatenation.",
    "CWE-78": "OS command injection vulnerability detected. User-controlled data flows into a system command without proper sanitization, allowing attackers to execute arbitrary commands. Use safe APIs with argument lists instead of shell execution.",
    "CWE-79": "Cross-site scripting (XSS) vulnerability detected. User input is rendered in HTML output without proper escaping, allowing attackers to inject malicious scripts. Sanitize or escape all user input before rendering.",
    "CWE-502": "Unsafe deserialization detected. Deserializing untrusted data can lead to remote code execution or denial of service. Use safe serialization formats like JSON or validate data before deserializing.",
    "CWE-798": "Hard-coded credentials detected. Embedding secrets in source code makes them easily discoverable and impossible to rotate. Use environment variables or a secrets manager instead.",
    "CWE-327": "Weak cryptographic algorithm detected. Using broken or outdated algorithms may allow attackers to decrypt data or forge signatures. Use modern algorithms like AES-256, SHA-256, or Ed25519.",
    "CWE-338": "Insecure random number generator used. Non-cryptographic PRNGs produce predictable values that attackers can guess. Use a cryptographically secure random generator for security-sensitive operations.",
    "CWE-295": "TLS/SSL certificate validation is disabled or bypassed. This allows man-in-the-middle attacks where attackers can intercept encrypted communications. Always validate certificates in production.",
    "CWE-22": "Path traversal vulnerability detected. User input is used in file paths without validation, allowing attackers to access files outside the intended directory. Validate and canonicalize paths before use.",
    "CWE-319": "Sensitive data transmitted over an unencrypted channel. Using HTTP instead of HTTPS allows network attackers to intercept data in transit. Use HTTPS for all communications containing sensitive data.",
    "CWE-532": "Sensitive information written to log files. Passwords, tokens, or personal data in logs can be exposed to unauthorized parties. Redact sensitive values before logging.",
    "CWE-601": "Open redirect vulnerability detected. The application redirects to a user-controlled URL without validation, enabling phishing attacks. Validate redirect targets against an allowlist.",
    "CWE-434": "Unrestricted file upload detected. Accepting uploads without validating file type and content can allow execution of malicious code. Validate file type, size, and content before storing.",
    "CWE-862": "Missing authorization check. The application does not verify user permissions before granting access to resources. Add authorization checks to all protected endpoints.",
    "CWE-352": "Cross-site request forgery (CSRF) vulnerability. The application does not verify that requests originate from its own interface. Implement CSRF tokens on all state-changing operations.",
    "CWE-611": "XML External Entity (XXE) vulnerability. The XML parser processes external entity references that can read local files or make network requests. Disable external entity processing in XML parsers.",
    "CWE-918": "Server-side request forgery (SSRF) detected. The application fetches resources from user-controlled URLs, allowing attackers to access internal services. Validate and restrict URL targets.",
    "CWE-94": "Code injection vulnerability detected. User-controlled input is passed to a code evaluation function, allowing arbitrary code execution. Avoid eval/exec with user input; use safe alternatives.",
    "CWE-489": "Debug mode or debug code is enabled in a production context. Debug features expose sensitive information and increase attack surface. Disable debug mode before deploying to production.",
    "CWE-400": "Uncontrolled resource consumption detected. The application does not limit resource usage, making it vulnerable to denial-of-service attacks. Implement rate limiting and resource caps.",
    "CWE-200": "Information exposure detected. The application reveals sensitive internal details to unauthorized users. Remove or restrict access to sensitive information in responses.",
    "CWE-209": "Error messages expose sensitive information. Stack traces or internal details in error responses help attackers plan attacks. Use generic error messages in production.",
    "CWE-732": "Overly permissive file or resource permissions. Resources are accessible to unauthorized users due to incorrect permission settings. Apply the principle of least privilege.",
    "CWE-614": "Sensitive cookie missing the Secure flag. The cookie may be transmitted over unencrypted HTTP, allowing interception. Set the Secure flag on all sensitive cookies.",
    "CWE-347": "Cryptographic signature verification is missing or improper. Unverified signatures allow attackers to tamper with data. Always verify signatures before trusting signed data.",
    "CWE-90": "LDAP injection vulnerability detected. User input in LDAP queries without sanitization allows attackers to modify query logic. Escape special characters in LDAP filters.",
    "CWE-703": "Improper error handling detected. The application does not properly handle exceptions, which may cause crashes or information leaks. Catch specific exceptions and handle them gracefully.",
    "CWE-943": "NoSQL injection vulnerability detected. User input in NoSQL queries without sanitization allows data theft or modification. Use parameterized queries and validate input types.",
    "CWE-755": "Improper handling of exceptional conditions. The application may crash or behave unexpectedly on errors. Add proper exception handling for all expected failure modes.",
    "CWE-377": "Insecure temporary file creation. Predictable temp file names or insecure permissions can be exploited via symlink attacks. Use secure temp file creation functions.",
    "CWE-1333": "Regular expression denial of service (ReDoS) risk. A regex with catastrophic backtracking can freeze the application on crafted input. Simplify the regex or set a timeout.",
    "CWE-409": "Decompression bomb risk detected. Processing compressed data without size limits can exhaust memory. Set maximum decompression size limits.",
    "CWE-20": "Missing input validation. User input is not sufficiently validated, enabling injection or logic bypass attacks. Validate all inputs against expected format, type, and range.",
    "CWE-307": "No limit on authentication attempts. The application allows unlimited login attempts, enabling brute-force password attacks. Implement account lockout or rate limiting.",
    "CWE-384": "Session fixation vulnerability. Session tokens are not regenerated after authentication, allowing session hijacking. Regenerate session IDs on login.",
    "CWE-521": "Weak password requirements. The application does not enforce strong password policies. Require minimum length, complexity, and check against breached password lists.",
    "CWE-287": "Improper authentication detected. The application does not properly verify user identity before granting access. Implement proper authentication mechanisms.",
    "CWE-916": "Weak password hashing algorithm. Fast hash algorithms make password cracking feasible. Use bcrypt, scrypt, or Argon2 for password hashing.",
    "CWE-190": "Integer overflow risk detected. Arithmetic operations may exceed integer bounds, causing unexpected behavior. Validate arithmetic operands and use safe math functions.",
    "CWE-120": "Buffer overflow vulnerability. Data is copied without checking buffer size, potentially allowing code execution. Always validate input length before buffer operations.",
    "CWE-119": "Memory buffer boundary violation. Operations read or write beyond buffer bounds, causing crashes or code execution. Use bounds-checked functions and validate sizes.",
    "CWE-416": "Use-after-free vulnerability. Accessing freed memory can cause crashes or arbitrary code execution. Nullify pointers after free and use smart pointers where possible.",
    "CWE-415": "Double free vulnerability. Freeing memory twice corrupts memory management and may allow code execution. Track allocation state and nullify freed pointers.",
    "CWE-476": "Null pointer dereference risk. Using a null pointer causes crashes. Check pointers for null before dereferencing.",
    "CWE-134": "Format string vulnerability. User input in format strings allows memory read/write. Never pass user input as a format string argument.",
    "CWE-242": "Use of inherently dangerous function. The called function cannot be used safely regardless of input handling. Replace with a safe alternative.",
    "CWE-401": "Memory leak detected. Allocated memory is never freed, leading to resource exhaustion. Free all dynamically allocated memory when no longer needed.",
    "CWE-362": "Race condition on shared resource. Concurrent access without synchronization can corrupt data. Use proper locking or atomic operations.",
    "CWE-367": "Time-of-check time-of-use (TOCTOU) race condition. A resource can change between check and use, allowing bypass. Perform check and use atomically.",
    "CWE-667": "Improper locking detected. Lock mismanagement may cause deadlocks or data corruption. Ensure locks are acquired and released in consistent order.",
    "CWE-697": "Incorrect comparison detected. Flawed comparison logic can bypass security checks. Use strict equality and proper type checking.",
    "CWE-704": "Incorrect type conversion. Unsafe type casting may cause data loss or memory corruption. Validate types before conversion and handle edge cases.",
    "CWE-248": "Uncaught exception risk. Unhandled exceptions can crash the application or leak information. Catch and handle all expected exception types.",
    "CWE-396": "Generic exception handler detected. Catching broad exceptions masks errors and may hide security issues. Catch specific exception types.",
    "CWE-693": "Security protection mechanism bypassed or missing. A security feature is absent or improperly configured. Verify all security mechanisms are active.",
    "CWE-494": "Code downloaded without integrity verification. Executing unverified code allows supply chain attacks. Verify checksums or signatures before execution.",
    "CWE-345": "Insufficient data authenticity verification. Data is accepted without verifying its source. Validate data origin using signatures or MACs.",
    "CWE-353": "Missing integrity check. Data modifications go undetected without integrity verification. Implement checksums or HMACs on sensitive data.",
    "CWE-312": "Sensitive data stored in cleartext. Plaintext storage of secrets allows unauthorized access. Encrypt sensitive data at rest.",
    "CWE-522": "Credentials transmitted or stored with insufficient protection. Weak protection makes credentials recoverable. Use strong encryption and secure channels.",
    "CWE-276": "Incorrect default permissions. Resources are created with overly permissive access. Set restrictive permissions explicitly on creation.",
    "CWE-250": "Code runs with unnecessary privileges. Excess permissions increase the impact of exploits. Apply the principle of least privilege.",
    "CWE-639": "Insecure direct object reference (IDOR). User-supplied IDs access resources without authorization checks. Verify user permissions for every resource access.",
    "CWE-477": "Use of obsolete or deprecated function. The function may have known security weaknesses. Replace with the recommended modern alternative.",
    "CWE-1104": "Use of unmaintained third-party component. Unpatched dependencies contain known vulnerabilities. Update to a maintained version or find an alternative.",
    "CWE-1059": "Insufficient code documentation. Missing documentation makes security issues harder to identify. Document security-sensitive code sections.",
    "CWE-778": "Insufficient security logging. Critical events are not logged, hindering incident detection. Log authentication, authorization, and data access events.",
    "CWE-926": "Improperly exported Android component. The component is accessible to other apps without restrictions. Set android:exported=false or add permission checks.",
    "CWE-942": "Overly permissive CORS policy. Any origin can access the API, enabling cross-origin data theft. Restrict CORS to trusted origins only.",
    "CWE-915": "Mass assignment vulnerability. Users can set object attributes they should not control. Use an allowlist of permitted attributes.",
    "CWE-74": "Injection vulnerability. User input reaches a downstream interpreter without sanitization. Sanitize or parameterize all user-controlled data.",
    "CWE-95": "Eval injection risk. User input is passed to an eval-like function, enabling code execution. Avoid eval with user input; use safe parsing.",
    "CWE-98": "Remote file inclusion vulnerability. User input controls file include paths, enabling remote code execution. Validate file paths against an allowlist.",
    "CWE-88": "Argument injection detected. User input is passed as command arguments without sanitization. Validate and escape all command arguments.",
    "CWE-91": "XML/XPath injection detected. User input in XML queries can alter query logic. Use parameterized XPath queries.",
    "CWE-863": "Incorrect authorization implementation. Authorization checks exist but are flawed. Review and test authorization logic for bypass conditions.",
    "CWE-73": "External file path control. User input determines which file is accessed. Validate paths against an allowlist and canonicalize before use.",
    "CWE-259": "Hard-coded password detected. Passwords embedded in code are easily discovered. Use environment variables or a secrets manager.",
    "CWE-208": "Timing side-channel detected. Response time differences can leak sensitive information. Use constant-time comparison for secrets.",
    "CWE-1321": "Prototype pollution vulnerability. User input modifies object prototypes, affecting application behavior. Freeze prototypes or validate input keys.",
    "CWE-1336": "Server-side template injection detected. User input in template expressions enables code execution. Sandbox templates and validate user input.",
    "CWE-470": "Unsafe reflection detected. User input selects classes or methods dynamically, enabling code execution. Use an allowlist of permitted class names.",
    "CWE-131": "Incorrect buffer size calculation. Buffer size miscalculation can cause overflow. Double-check size arithmetic and use safe allocation wrappers.",
    "CWE-117": "Log injection risk. Unsanitized input in logs allows forged entries. Sanitize newlines and special characters before logging.",
    "CWE-479": "Signal handler uses non-reentrant function. This causes undefined behavior on signal delivery. Only call async-signal-safe functions in signal handlers.",
    "CWE-310": "Cryptographic weakness detected. Misuse of cryptographic primitives undermines data protection. Use well-tested crypto libraries with recommended configurations.",
    "CWE-322": "Key exchange without authentication. Unauthenticated key exchange enables man-in-the-middle attacks. Use authenticated key exchange protocols.",
    "CWE-326": "Inadequate encryption strength. Short key lengths make brute-force attacks feasible. Use at least 128-bit symmetric keys or 2048-bit RSA keys.",
    "CWE-330": "Insufficiently random values used. Predictable random values can be guessed by attackers. Use a cryptographically secure random generator.",
    "CWE-16": "Insecure configuration detected. A misconfigured setting weakens the application's security posture. Review and harden security-relevant configuration.",
}

# ---------------------------------------------------------------------------
# (CWE, language) -> language-specific fix text
# ---------------------------------------------------------------------------

FIX_BY_CWE_LANG = {
    # SQL Injection (CWE-89)
    ("CWE-89", "python"): "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,)). For Django, use the ORM or QuerySet API. For SQLAlchemy, use bound parameters.",
    ("CWE-89", "java"): "Use PreparedStatement with parameter binding: ps = conn.prepareStatement('SELECT * FROM t WHERE id = ?'); ps.setString(1, userId);",
    ("CWE-89", "javascript_typescript"): "Use parameterized queries with your database driver, e.g., db.query('SELECT * FROM t WHERE id = $1', [userId]) for pg, or use an ORM like Prisma or Sequelize.",
    ("CWE-89", "go"): "Use parameterized queries: db.Query('SELECT * FROM t WHERE id = ?', userId). Never concatenate user input into SQL strings.",
    ("CWE-89", "php"): "Use PDO prepared statements: $stmt = $pdo->prepare('SELECT * FROM t WHERE id = ?'); $stmt->execute([$userId]);",
    ("CWE-89", "ruby"): "Use parameterized queries with ActiveRecord: User.where('id = ?', user_id) or use the ORM query interface.",
    ("CWE-89", "dotnet"): "Use parameterized queries with SqlCommand: cmd.Parameters.AddWithValue(\"@id\", userId); or use Entity Framework LINQ queries.",
    ("CWE-89", "kotlin"): "Use PreparedStatement with parameter binding or use an ORM like Exposed or Room with parameterized queries.",
    ("CWE-89", "scala"): "Use Slick's type-safe query DSL or JDBC PreparedStatement with parameter binding.",
    ("CWE-89", "elixir"): "Use Ecto parameterized queries: Repo.all(from u in User, where: u.id == ^user_id). Never interpolate user input into raw SQL.",
    ("CWE-89", "erlang"): "Use parameterized queries with your database driver, e.g., epgsql:equery(C, \"SELECT * FROM t WHERE id = $1\", [UserId]).",
    ("CWE-89", "rust"): "Use parameterized queries with sqlx: sqlx::query('SELECT * FROM t WHERE id = $1').bind(user_id). Never format user input into SQL strings.",
    ("CWE-89", "c_cpp"): "Use parameterized queries with your database API (e.g., sqlite3_bind_text for SQLite, PQexecParams for PostgreSQL). Never use sprintf to build SQL.",
    ("CWE-89", "objective-c"): "Use parameterized queries with sqlite3_bind_text() or NSPredicate with substitution variables. Never concatenate user input into SQL strings.",
    ("CWE-89", "swift"): "Use parameterized queries with sqlite3_bind_text() or a Swift ORM like GRDB with parameterized statements.",

    # Command Injection (CWE-78)
    ("CWE-78", "python"): "Use subprocess.run() with a list of arguments instead of shell=True: subprocess.run(['cmd', arg1, arg2]). Never pass user input to os.system() or shell commands.",
    ("CWE-78", "java"): "Use ProcessBuilder with separate arguments: new ProcessBuilder('cmd', arg1, arg2). Never concatenate user input into Runtime.exec() strings.",
    ("CWE-78", "javascript_typescript"): "Use child_process.execFile() or spawn() with argument arrays instead of exec(). Never interpolate user input into shell commands.",
    ("CWE-78", "go"): "Use exec.Command() with separate arguments: exec.Command('cmd', arg1, arg2). Never pass user input to exec.Command('sh', '-c', userInput).",
    ("CWE-78", "ruby"): "Use system() with separate arguments: system('cmd', arg1, arg2). Avoid backticks or %x{} with user input.",
    ("CWE-78", "php"): "Use escapeshellarg() for arguments and escapeshellcmd() for commands. Prefer language-level APIs over shell execution.",
    ("CWE-78", "dotnet"): "Use Process.Start() with Arguments set separately. Never concatenate user input into process arguments.",
    ("CWE-78", "kotlin"): "Use ProcessBuilder with separate arguments: ProcessBuilder('cmd', arg1, arg2). Never concatenate user input into command strings.",
    ("CWE-78", "scala"): "Use ProcessBuilder or scala.sys.process with separate arguments. Never interpolate user input into shell command strings.",
    ("CWE-78", "elixir"): "Use System.cmd/2 with separate arguments: System.cmd(\"cmd\", [arg1, arg2]). Never pass user input to :os.cmd/1.",
    ("CWE-78", "erlang"): "Use erlang:open_port with {spawn_executable, Cmd} and {args, Args} instead of os:cmd/1. Never interpolate user input into commands.",
    ("CWE-78", "rust"): "Use std::process::Command with separate arguments: Command::new('cmd').arg(arg1).arg(arg2). Never pass user input to shell commands.",
    ("CWE-78", "c_cpp"): "Use execve() or posix_spawn() with separate argument arrays. Never pass user input to system() or popen().",
    ("CWE-78", "objective-c"): "Use NSTask with launchPath and arguments array. Never pass user input to system() or popen().",
    ("CWE-78", "swift"): "Use Process (NSTask) with separate arguments array. Never pass user input to system() or shell commands.",

    # XSS (CWE-79)
    ("CWE-79", "python"): "Use template engine auto-escaping (Jinja2 autoescape=True, Django default). Use markupsafe.escape() for manual escaping. Never render raw user input with |safe or Markup().",
    ("CWE-79", "java"): "Use context-aware output encoding (OWASP Java Encoder: Encode.forHtml()). Enable auto-escaping in templates (Thymeleaf, JSP with JSTL).",
    ("CWE-79", "javascript_typescript"): "Use textContent instead of innerHTML. Use DOMPurify.sanitize() if HTML must be rendered. Enable auto-escaping in template engines (React JSX, Handlebars).",
    ("CWE-79", "php"): "Use htmlspecialchars($input, ENT_QUOTES, 'UTF-8') for output. Enable auto-escaping in Twig/Blade templates. Never echo raw user input.",
    ("CWE-79", "ruby"): "Use ERB auto-escaping (<%= %>) or sanitize helper. Never use raw() or html_safe on user input without sanitization.",
    ("CWE-79", "dotnet"): "Use Razor auto-encoding or HtmlEncoder.Default.Encode(). Never use Html.Raw() with user input. Validate input on both client and server.",
    ("CWE-79", "kotlin"): "Use context-aware output encoding. Enable auto-escaping in template engines. Use OWASP Java Encoder for manual escaping.",
    ("CWE-79", "scala"): "Use Play framework's Twirl templates (auto-escaped by default). Use Html() only for trusted content. Sanitize user input before rendering.",
    ("CWE-79", "elixir"): "Phoenix templates auto-escape by default. Never use raw/1 or {:safe, ...} with user input. Use Phoenix.HTML.html_escape/1 for manual escaping.",
    ("CWE-79", "erlang"): "Escape all user input before inserting into HTML output. Use a templating library with auto-escaping enabled.",
    ("CWE-79", "objective-c"): "Escape user input before rendering in web views. Use NSString methods to encode HTML entities. Avoid loading untrusted HTML in WKWebView.",
    ("CWE-79", "swift"): "Escape user input before rendering in web views. Use String extension to encode HTML entities. Set WKWebView configuration to restrict JavaScript.",

    # Path Traversal (CWE-22)
    ("CWE-22", "python"): "Use os.path.abspath() and verify the result starts with your allowed base directory. Use pathlib.Path.resolve() for canonicalization.",
    ("CWE-22", "java"): "Use File.getCanonicalPath() and verify the result starts with the allowed base directory. Use java.nio.file.Path.normalize() and resolve().",
    ("CWE-22", "javascript_typescript"): "Use path.resolve() and verify the result starts with the allowed base directory using path.relative() to check for '..' traversal.",
    ("CWE-22", "go"): "Use filepath.Clean() and filepath.Abs(), then verify the result is within the allowed base directory with strings.HasPrefix().",
    ("CWE-22", "php"): "Use realpath() and verify the result starts with the allowed base directory. Reject paths containing '..' sequences.",
    ("CWE-22", "ruby"): "Use File.expand_path() and verify the result starts with the allowed base directory. Use Pathname#cleanpath for normalization.",
    ("CWE-22", "dotnet"): "Use Path.GetFullPath() and verify the result starts with the allowed base directory. Use Path.Combine() instead of string concatenation.",
    ("CWE-22", "kotlin"): "Use File.canonicalPath and verify it starts with the allowed base directory. Use java.nio.file.Path.normalize().",
    ("CWE-22", "scala"): "Use java.io.File.getCanonicalPath() and verify it starts with the allowed base directory. Use java.nio.file.Path.normalize().",
    ("CWE-22", "elixir"): "Use Path.expand/1 and verify the result starts with the allowed base directory. Reject paths containing '..' components.",
    ("CWE-22", "erlang"): "Use filename:absname/1 and verify the result starts with the allowed base directory. Reject paths containing '..' components.",
    ("CWE-22", "rust"): "Use std::fs::canonicalize() and verify the result starts with the allowed base directory. Use Path::starts_with() for validation.",
    ("CWE-22", "objective-c"): "Use -[NSString stringByStandardizingPath] and verify the result starts with the allowed base directory. Reject '..' path components.",
    ("CWE-22", "swift"): "Use URL.standardizedFileURL or (path as NSString).standardizingPath and verify the result is within the allowed base directory.",

    # Unsafe Deserialization (CWE-502)
    ("CWE-502", "python"): "Replace pickle/shelve with json.loads() for data interchange. If pickle is required, use hmac to verify data integrity before deserializing.",
    ("CWE-502", "java"): "Use ObjectInputFilter (JEP 290) to restrict deserializable classes. Prefer JSON (Jackson/Gson) or Protocol Buffers for data interchange.",
    ("CWE-502", "javascript_typescript"): "Avoid eval() or Function() for deserialization. Use JSON.parse() with a reviver function to validate types.",
    ("CWE-502", "php"): "Replace unserialize() with json_decode(). If unserialize() is required, use the allowed_classes option to restrict types.",
    ("CWE-502", "ruby"): "Replace Marshal.load/YAML.load with JSON.parse or YAML.safe_load. Never deserialize untrusted data with Marshal.",
    ("CWE-502", "dotnet"): "Use System.Text.Json or Newtonsoft.Json instead of BinaryFormatter/SoapFormatter. Set TypeNameHandling.None in Newtonsoft.Json.",
    ("CWE-502", "kotlin"): "Use kotlinx.serialization with JSON format. Avoid Java ObjectInputStream for untrusted data. Use ObjectInputFilter if needed.",
    ("CWE-502", "scala"): "Use circe, play-json, or upickle for JSON deserialization. Avoid Java ObjectInputStream for untrusted data.",
    ("CWE-502", "elixir"): "Use Jason.decode/1 or :erlang.binary_to_term/2 with [:safe] option. Never use :erlang.binary_to_term/1 on untrusted data.",
    ("CWE-502", "erlang"): "Use binary_to_term/2 with [safe] option. Use jsx or jiffy for JSON deserialization. Never use binary_to_term/1 on untrusted data.",
    ("CWE-502", "rust"): "Use serde with JSON/MessagePack instead of bincode for untrusted data. Validate deserialized data before use.",
    ("CWE-502", "objective-c"): "Use NSJSONSerialization instead of NSKeyedUnarchiver for untrusted data. Use NSSecureCoding with allowedClasses for type validation.",
    ("CWE-502", "swift"): "Use JSONDecoder with Codable instead of NSKeyedUnarchiver. Use NSSecureCoding with unarchivedObject(ofClass:from:) for type-safe unarchiving.",

    # Hard-coded credentials (CWE-798)
    ("CWE-798", "python"): "Store secrets in environment variables (os.environ['KEY']) or use a secrets manager (AWS Secrets Manager, HashiCorp Vault, python-dotenv).",
    ("CWE-798", "java"): "Store secrets in environment variables (System.getenv('KEY')), a secrets manager, or externalized configuration (Spring Vault, AWS Secrets Manager).",
    ("CWE-798", "javascript_typescript"): "Store secrets in environment variables (process.env.KEY) or use a secrets manager. Use dotenv for local development.",
    ("CWE-798", "go"): "Store secrets in environment variables (os.Getenv('KEY')) or use a secrets manager (HashiCorp Vault, AWS Secrets Manager).",
    ("CWE-798", "php"): "Store secrets in environment variables (getenv('KEY')) or use a secrets manager. Use vlucas/phpdotenv for local development.",
    ("CWE-798", "ruby"): "Store secrets in environment variables (ENV['KEY']) or use Rails credentials (config/credentials.yml.enc) or a secrets manager.",
    ("CWE-798", "dotnet"): "Store secrets in environment variables, Azure Key Vault, or user-secrets for development. Use IConfiguration to access secrets.",
    ("CWE-798", "kotlin"): "Store secrets in environment variables (System.getenv('KEY')) or use Android Keystore / a secrets manager. Never commit secrets to source control.",
    ("CWE-798", "scala"): "Store secrets in environment variables or use a secrets manager. Use Typesafe Config with environment variable substitution.",
    ("CWE-798", "elixir"): "Store secrets in environment variables (System.get_env/1) or use runtime configuration. Use config/runtime.exs for production secrets.",
    ("CWE-798", "erlang"): "Store secrets in environment variables (os:getenv/1) or use a secrets manager. Load secrets from configuration files excluded from version control.",
    ("CWE-798", "rust"): "Store secrets in environment variables (std::env::var('KEY')) or use a secrets manager. Use dotenvy for local development.",
    ("CWE-798", "c_cpp"): "Store secrets in environment variables (getenv('KEY')) or read from a protected configuration file. Never embed secrets in source code.",
    ("CWE-798", "objective-c"): "Store secrets in the iOS Keychain or environment variables. Never embed secrets in source code or property lists.",
    ("CWE-798", "swift"): "Store secrets in the iOS Keychain or environment variables. Use a secrets manager for server-side Swift. Never embed secrets in source code.",

    # Weak crypto (CWE-327)
    ("CWE-327", "python"): "Use hashlib.sha256() or hashlib.sha3_256() instead of md5/sha1. Use cryptography library with AES-GCM or ChaCha20-Poly1305 for encryption.",
    ("CWE-327", "java"): "Use MessageDigest.getInstance('SHA-256') instead of MD5/SHA1. Use AES/GCM/NoPadding for encryption. Use Cipher from javax.crypto with strong algorithms.",
    ("CWE-327", "javascript_typescript"): "Use crypto.createHash('sha256') instead of md5/sha1. Use crypto.createCipheriv('aes-256-gcm', ...) for encryption.",
    ("CWE-327", "go"): "Use crypto/sha256 instead of crypto/md5 or crypto/sha1. Use crypto/aes with GCM mode for encryption.",
    ("CWE-327", "ruby"): "Use OpenSSL::Digest::SHA256 instead of MD5/SHA1. Use OpenSSL::Cipher.new('aes-256-gcm') for encryption.",
    ("CWE-327", "dotnet"): "Use SHA256.Create() instead of MD5/SHA1. Use Aes.Create() with CipherMode.CBC or AesGcm for encryption.",
    ("CWE-327", "kotlin"): "Use MessageDigest.getInstance('SHA-256') instead of MD5/SHA1. Use Cipher with 'AES/GCM/NoPadding' for encryption.",
    ("CWE-327", "scala"): "Use MessageDigest.getInstance('SHA-256') instead of MD5/SHA1. Use javax.crypto.Cipher with AES-GCM for encryption.",
    ("CWE-327", "elixir"): "Use :crypto.hash(:sha256, data) instead of :md5/:sha. Use :crypto.crypto_one_time_aead for AES-GCM encryption.",
    ("CWE-327", "erlang"): "Use crypto:hash(sha256, Data) instead of md5/sha. Use crypto:crypto_one_time_aead for AES-GCM encryption.",
    ("CWE-327", "rust"): "Use sha2 crate (Sha256::digest) instead of md5. Use aes-gcm crate for authenticated encryption.",
    ("CWE-327", "c_cpp"): "Use SHA-256 (e.g., EVP_sha256() from OpenSSL) instead of MD5/SHA-1. Use AES-GCM for authenticated encryption.",
    ("CWE-327", "objective-c"): "Use CC_SHA256 from CommonCrypto instead of CC_MD5/CC_SHA1. Use CCCrypt with kCCAlgorithmAES for encryption.",
    ("CWE-327", "swift"): "Use SHA256 from CryptoKit instead of Insecure.MD5/SHA1. Use AES.GCM.seal() for authenticated encryption.",

    # TLS/SSL bypass (CWE-295)
    ("CWE-295", "python"): "Always use verify=True (the default) in requests. Set ssl_context properly. Never set CERT_NONE or disable hostname checking.",
    ("CWE-295", "java"): "Never override TrustManager to accept all certificates. Use the default SSLContext or configure with trusted CA certificates only.",
    ("CWE-295", "javascript_typescript"): "Never set rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED=0. Configure proper CA certificates for custom TLS needs.",
    ("CWE-295", "go"): "Never set InsecureSkipVerify: true in tls.Config. Use the default TLS configuration which validates certificates properly.",
    ("CWE-295", "ruby"): "Never set verify_mode = OpenSSL::SSL::VERIFY_NONE. Use the default certificate validation in Net::HTTP and OpenSSL.",
    ("CWE-295", "dotnet"): "Never return true from ServerCertificateCustomValidationCallback. Use the default certificate validation from ServicePointManager.",
    ("CWE-295", "kotlin"): "Never override TrustManager to accept all certificates. Use the default SSLContext or OkHttp's CertificatePinner for pinning.",
    ("CWE-295", "scala"): "Never override TrustManager to accept all certificates. Use the default SSLContext or configure trusted CA certificates.",
    ("CWE-295", "rust"): "Never use danger_accept_invalid_certs(true) in reqwest or rustls. Use the default TLS verification with proper CA certificates.",
    ("CWE-295", "c_cpp"): "Always call SSL_CTX_set_verify with SSL_VERIFY_PEER. Never skip certificate or hostname verification in OpenSSL/BoringSSL.",
    ("CWE-295", "objective-c"): "Never override NSURLSession delegate to accept invalid certificates. Use App Transport Security (ATS) defaults.",
    ("CWE-295", "swift"): "Never override URLSession delegate to accept invalid certificates. Use App Transport Security (ATS) defaults.",

    # Code injection (CWE-94)
    ("CWE-94", "python"): "Remove eval()/exec() calls with user input. Use ast.literal_eval() for safe parsing of Python literals. Use a sandboxed environment if dynamic execution is required.",
    ("CWE-94", "java"): "Avoid ScriptEngine.eval() with user input. Use a sandboxed interpreter or template engine. Restrict class loading with a SecurityManager.",
    ("CWE-94", "javascript_typescript"): "Remove eval(), Function(), and setTimeout/setInterval with string arguments. Use JSON.parse() for data parsing. Use a sandboxed environment (vm2) if dynamic execution is needed.",
    ("CWE-94", "php"): "Remove eval(), assert(), and preg_replace with /e flag. Use proper parsing functions for data. Never include user-controlled file paths.",
    ("CWE-94", "ruby"): "Remove eval(), instance_eval(), and send() with user input. Use safe parsing methods. Use a sandboxed environment if dynamic execution is required.",
    ("CWE-94", "dotnet"): "Avoid CSharpScript.EvaluateAsync() or Roslyn compilation with user input. Use expression parsers or sandboxed environments.",
    ("CWE-94", "kotlin"): "Avoid ScriptEngine.eval() or javax.tools.JavaCompiler with user input. Use a sandboxed interpreter or expression parser.",
    ("CWE-94", "scala"): "Avoid scala.tools.reflect.ToolBox.eval() with user input. Use a sandboxed interpreter or safe expression parser.",
    ("CWE-94", "elixir"): "Remove Code.eval_string/1 calls with user input. Use pattern matching and safe parsing instead. Never evaluate untrusted Elixir code.",
    ("CWE-94", "erlang"): "Avoid erl_eval:expr/2 and erl_scan with user input. Use pattern matching and safe parsing instead. Never evaluate untrusted Erlang terms.",

    # XXE (CWE-611)
    ("CWE-611", "python"): "Use defusedxml instead of xml.etree or lxml. Set resolve_entities=False and no_network=True in lxml parsers.",
    ("CWE-611", "java"): "Set XMLConstants.FEATURE_SECURE_PROCESSING and disable DOCTYPE declarations: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true).",
    ("CWE-611", "javascript_typescript"): "Use a safe XML parser. In libxmljs, set noent: false and nonet: true. In xml2js, external entities are disabled by default.",
    ("CWE-611", "php"): "Call libxml_disable_entity_loader(true) before parsing XML. Use LIBXML_NOENT flag carefully. Use json_decode() if possible.",
    ("CWE-611", "dotnet"): "Set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit and XmlReaderSettings.XmlResolver = null.",
    ("CWE-611", "kotlin"): "Set XMLConstants.FEATURE_SECURE_PROCESSING and disable DOCTYPE: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true).",

    # SSRF (CWE-918)
    ("CWE-918", "python"): "Validate URLs against an allowlist of permitted hosts and schemes. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x). Use urllib.parse to validate before fetching.",
    ("CWE-918", "javascript_typescript"): "Validate URLs against an allowlist of permitted hosts. Block private IP ranges and localhost. Use the URL constructor to parse and validate before fetching.",
    ("CWE-918", "dotnet"): "Validate URLs against an allowlist of permitted hosts. Block private IP ranges and localhost. Resolve DNS and check the IP before making requests.",

    # File upload (CWE-434)
    ("CWE-434", "python"): "Validate file extension, MIME type, and content. Use werkzeug.utils.secure_filename(). Store uploads outside the web root with randomized names.",
    ("CWE-434", "java"): "Validate file extension, MIME type, and content. Store uploads outside the web root. Use Apache Tika for content-type detection.",
    ("CWE-434", "javascript_typescript"): "Validate file extension, MIME type, and content. Use multer with file filter. Store uploads outside the web root with randomized names.",
    ("CWE-434", "php"): "Validate file extension, MIME type with finfo_file(), and content. Store uploads outside the web root. Never trust $_FILES['type'].",
    ("CWE-434", "kotlin"): "Validate file extension, MIME type, and content. Store uploads outside the web root. Use Apache Tika for content-type detection.",
    ("CWE-434", "scala"): "Validate file extension, MIME type, and content. Store uploads outside the web root with randomized names.",
    ("CWE-434", "elixir"): "Validate file extension, MIME type, and content. Store uploads outside the web root. Use Plug.Upload metadata for validation.",
    ("CWE-434", "erlang"): "Validate file extension, MIME type, and content. Store uploads outside the web root with randomized filenames.",

    # LDAP injection (CWE-90)
    ("CWE-90", "python"): "Use ldap3 library with safe filter escaping: ldap3.utils.conv.escape_filter_chars(user_input). Never concatenate user input into LDAP filters.",
    ("CWE-90", "java"): "Use javax.naming.ldap with properly escaped filter values. Use LdapEncoder.filterEncode() from Spring LDAP for escaping.",
    ("CWE-90", "javascript_typescript"): "Use ldapjs with properly escaped filter values. Use ldapEscape.filter() to escape special characters in LDAP filters.",
    ("CWE-90", "php"): "Use ldap_escape() to sanitize filter values: ldap_escape($input, '', LDAP_ESCAPE_FILTER). Never concatenate user input into LDAP filters.",
    ("CWE-90", "dotnet"): "Use System.DirectoryServices with parameterized searches. Escape special LDAP characters before inserting into filters.",
    ("CWE-90", "kotlin"): "Use javax.naming.ldap with properly escaped filter values. Use Spring LDAP's LdapEncoder.filterEncode() for escaping.",

    # Insecure random (CWE-338)
    ("CWE-338", "python"): "Use secrets.token_bytes(), secrets.token_hex(), or secrets.choice() for security-sensitive operations.",
    ("CWE-338", "java"): "Use java.security.SecureRandom instead of java.util.Random for security-sensitive operations.",
    ("CWE-338", "javascript_typescript"): "Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive operations.",
    ("CWE-338", "dotnet"): "Use System.Security.Cryptography.RandomNumberGenerator instead of System.Random for security-sensitive operations.",
    ("CWE-338", "kotlin"): "Use java.security.SecureRandom instead of kotlin.random.Random or java.util.Random for security-sensitive operations.",

    # CSRF (CWE-352)
    ("CWE-352", "java"): "Enable Spring Security CSRF protection or use a custom CSRF token filter. Include CSRF tokens in all HTML forms and AJAX requests.",
    ("CWE-352", "kotlin"): "Enable Spring Security CSRF protection or use a framework-provided CSRF middleware. Include CSRF tokens in all state-changing requests.",

    # JWT/signature verification (CWE-347)
    ("CWE-347", "python"): "Always verify JWT signatures: jwt.decode(token, key, algorithms=['HS256']). Never use options={'verify_signature': False}.",
    ("CWE-347", "javascript_typescript"): "Always verify JWT signatures with jsonwebtoken: jwt.verify(token, secret). Never use jwt.decode() without verification for authorization.",
    ("CWE-347", "objective-c"): "Always verify cryptographic signatures before trusting signed data. Use Security.framework's SecKeyVerifySignature for RSA/EC verification.",
    ("CWE-347", "swift"): "Always verify cryptographic signatures before trusting signed data. Use CryptoKit's isValidSignature or Security.framework's SecKeyVerifySignature.",

    # NoSQL injection (CWE-943)
    ("CWE-943", "python"): "Use parameterized queries with PyMongo. Validate input types (reject dicts/lists where strings expected). Never pass raw request data to MongoDB queries.",
    ("CWE-943", "javascript_typescript"): "Validate input types before MongoDB queries. Use mongoose schema validation. Replace $where with aggregation pipeline. Sanitize with mongo-sanitize.",
    ("CWE-943", "objective-c"): "Validate all user input before including in NoSQL queries. Use parameterized queries and type-check inputs to reject injection payloads.",
    ("CWE-943", "swift"): "Validate all user input before including in NoSQL queries. Use parameterized queries and type-check inputs to reject injection payloads.",

    # Prototype pollution (CWE-1321)
    ("CWE-1321", "javascript_typescript"): "Use Object.create(null) for lookup objects. Validate keys against a denylist (__proto__, constructor, prototype). Use Map instead of plain objects.",

    # Template injection (CWE-1336)
    ("CWE-1336", "python"): "Never pass user input to Jinja2 Template() or Mako Template(). Use render_template() with variables. Enable sandboxed environment for dynamic templates.",
    ("CWE-1336", "javascript_typescript"): "Never pass user input to template compilation functions. Use pre-compiled templates with data binding. Enable strict mode in template engines.",

    # Debug mode (CWE-489)
    ("CWE-489", "python"): "Set DEBUG=False in production. Use environment variables to control debug mode: DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'.",
    ("CWE-489", "javascript_typescript"): "Set NODE_ENV=production in deployment. Remove console.log/debug statements. Use a logging library with configurable log levels.",

    # Code integrity (CWE-494)
    ("CWE-494", "javascript_typescript"): "Use Subresource Integrity (SRI) for CDN scripts: <script src='...' integrity='sha384-...' crossorigin='anonymous'>. Verify npm package checksums.",
    ("CWE-494", "dotnet"): "Verify assembly signatures using strong naming. Validate checksums of downloaded assemblies before loading.",

    # CORS (CWE-942)
    ("CWE-942", "javascript_typescript"): "Set specific allowed origins instead of '*'. Use the cors middleware with a whitelist: cors({ origin: ['https://trusted.example.com'] }).",

    # File path control (CWE-73)
    ("CWE-73", "javascript_typescript"): "Validate file paths against an allowlist. Use path.resolve() and verify the result is within the allowed directory. Reject paths with '..' components.",

    # Android exported components (CWE-926)
    ("CWE-926", "kotlin"): "Set android:exported='false' in AndroidManifest.xml for internal components. Add permission checks for exported components.",

    # Weak password hashing (CWE-916)
    ("CWE-916", "python"): "Use bcrypt (bcrypt.hashpw), argon2 (argon2-cffi), or scrypt (hashlib.scrypt) instead of MD5/SHA for password hashing.",

    # Eval injection (CWE-95)
    ("CWE-95", "python"): "Remove eval()/exec() with user input. Use ast.literal_eval() for safe Python literal parsing. Use a sandboxed environment if dynamic code execution is needed.",

    # Remote file inclusion (CWE-98)
    ("CWE-98", "php"): "Set allow_url_include=Off in php.ini. Validate file paths against an allowlist. Use basename() to strip directory components from user input.",

    # IDOR (CWE-639)
    ("CWE-639", "python"): "Verify user authorization before accessing resources. Use the authenticated user's ID from the session, not from request parameters.",
    ("CWE-639", "javascript_typescript"): "Verify user authorization before accessing resources. Use the authenticated user's ID from the session, not from request parameters.",
    ("CWE-639", "php"): "Verify user authorization before accessing resources. Use the authenticated user's session ID, not user-supplied IDs for resource access.",

    # Cookie security (CWE-614)
    ("CWE-614", "python"): "Set cookie flags: response.set_cookie(key, value, secure=True, httponly=True, samesite='Lax'). Use SESSION_COOKIE_SECURE=True in Django.",
    ("CWE-614", "javascript_typescript"): "Set cookie flags: res.cookie(name, value, { secure: true, httpOnly: true, sameSite: 'lax' }). Use helmet for Express security headers.",

    # Missing auth (CWE-862)
    ("CWE-862", "python"): "Add authorization decorators or middleware to protected endpoints. Use @login_required (Django) or @jwt_required (Flask-JWT) on all protected routes.",
    ("CWE-862", "javascript_typescript"): "Add authentication middleware to protected routes. Use passport.authenticate() or a custom auth middleware before route handlers.",
    ("CWE-862", "dotnet"): "Add [Authorize] attribute to controller actions. Configure authorization policies in Startup.cs. Use role-based or policy-based authorization.",

    # File permissions (CWE-732)
    ("CWE-732", "python"): "Set restrictive permissions with os.chmod(path, 0o600) for sensitive files. Use os.umask(0o077) to restrict default permissions.",

    # Cleartext storage (CWE-312)
    ("CWE-312", "objective-c"): "Use Keychain Services (SecItemAdd) for storing secrets instead of NSUserDefaults or plist files. Encrypt sensitive data with CommonCrypto.",
    ("CWE-312", "swift"): "Use Keychain Services or SwiftKeychainWrapper for storing secrets. Never store sensitive data in UserDefaults or plist files.",

    # Privilege escalation (CWE-250)
    ("CWE-250", "objective-c"): "Drop elevated privileges as soon as possible. Use the principle of least privilege. Avoid running with root/admin unless absolutely necessary.",
    ("CWE-250", "swift"): "Drop elevated privileges as soon as possible. Use the principle of least privilege. Use Authorization Services for privileged operations.",

    # Authorization issues (CWE-863)
    ("CWE-863", "dotnet"): "Review authorization logic for bypass conditions. Use policy-based authorization with IAuthorizationHandler. Test authorization with different user roles.",

    # Authentication issues (CWE-287)
    ("CWE-287", "dotnet"): "Use ASP.NET Core Identity or a proven authentication library. Implement multi-factor authentication. Use strong password hashing (BCrypt/Argon2).",

    # Key exchange (CWE-322)
    ("CWE-322", "go"): "Use authenticated key exchange protocols (TLS 1.3, SSH with host key verification). Never skip host key verification in SSH connections.",

    # Password requirements (CWE-521)
    ("CWE-521", "go"): "Enforce minimum password length of 12 characters. Require complexity rules. Check passwords against breached password lists (Have I Been Pwned API).",

    # XPath injection (CWE-91)
    ("CWE-91", "dotnet"): "Use parameterized XPath queries with XPathNavigator.Compile(). Escape special characters in user input before XPath queries.",

    # Memory safety
    ("CWE-120", "c_cpp"): "Use strncpy/strncat with explicit size limits instead of strcpy/strcat. Use snprintf instead of sprintf. Check input length before copying.",
    ("CWE-120", "rust"): "Use safe Rust APIs that enforce bounds checking. Minimize unsafe blocks. Use Vec<u8> and slice methods instead of raw pointers.",
    ("CWE-120", "objective-c"): "Use NSString and NSData instead of C string functions. If C buffers are required, always validate sizes. Use strlcpy/strlcat instead of strcpy/strcat.",
    ("CWE-134", "c_cpp"): "Never pass user input as the format string. Use printf(\"%s\", user_input) instead of printf(user_input). Use -Wformat-security compiler flag.",
    ("CWE-134", "erlang"): "Never use user input as the format string in io:format/2. Always use a static format string: io:format(\"~s\", [UserInput]).",
    ("CWE-190", "c_cpp"): "Check for overflow before arithmetic: if (a > INT_MAX - b) { error; }. Use compiler built-ins like __builtin_add_overflow() or SafeInt library.",
    ("CWE-415", "c_cpp"): "Set pointers to NULL after freeing. Use RAII in C++ (unique_ptr, shared_ptr). Check for double-free with AddressSanitizer (-fsanitize=address).",
    ("CWE-416", "c_cpp"): "Set pointers to NULL after freeing. Use smart pointers (unique_ptr, shared_ptr) in C++. Enable AddressSanitizer for detection.",
    ("CWE-416", "rust"): "Avoid unsafe blocks with raw pointers. Use Rust's ownership system and borrowing rules. If unsafe is required, ensure lifetimes are properly managed.",
    ("CWE-476", "c_cpp"): "Always check pointers for NULL before dereferencing. Initialize pointers to NULL. Use static analysis tools to detect null dereference paths.",
    ("CWE-704", "c_cpp"): "Use explicit casts with bounds checking. In C++, prefer static_cast over C-style casts. Validate value ranges before narrowing conversions.",

    # Broken access control (CWE-119)
    ("CWE-119", "rust"): "Minimize unsafe blocks. Use safe Rust APIs with bounds checking. If unsafe is required, carefully validate all buffer sizes and indices.",
    ("CWE-119", "dotnet"): "Use safe managed code. Avoid Marshal.Copy and unsafe fixed buffers. Use Span<T> with bounds checking for performance-critical buffer operations.",

    # Open redirect (CWE-601)
    ("CWE-601", "elixir"): "Validate redirect URLs against an allowlist of trusted paths or domains. Use relative paths for internal redirects. Reject external URLs.",
    ("CWE-601", "erlang"): "Validate redirect URLs against an allowlist of trusted paths or domains. Use relative paths for internal redirects. Reject external URLs.",
    ("CWE-601", "ruby"): "Validate redirect URLs against an allowlist. Use relative paths for internal redirects. Use URI.parse to check the host before redirecting.",
    ("CWE-601", "php"): "Validate redirect URLs against an allowlist of trusted domains. Use relative paths for internal redirects. Parse URLs and check the host component.",
}

# ---------------------------------------------------------------------------
# CWE -> generic fix (fallback when language-specific fix not available)
# Extracted from the "How to fix it" sentence of CWE_MESSAGES.
# ---------------------------------------------------------------------------

GENERIC_FIX_BY_CWE = {
    "CWE-89": "Use parameterized queries or an ORM instead of string concatenation for SQL queries.",
    "CWE-78": "Use safe APIs with argument lists instead of shell execution. Never pass user input to shell commands.",
    "CWE-79": "Sanitize or escape all user input before rendering in HTML output.",
    "CWE-502": "Use safe serialization formats like JSON. Validate and restrict types before deserializing untrusted data.",
    "CWE-798": "Use environment variables or a secrets manager instead of hard-coding credentials in source code.",
    "CWE-327": "Use modern cryptographic algorithms like AES-256, SHA-256, or Ed25519 instead of broken or outdated algorithms.",
    "CWE-338": "Use a cryptographically secure random generator for security-sensitive operations.",
    "CWE-295": "Always validate TLS/SSL certificates in production. Never disable certificate verification.",
    "CWE-22": "Validate and canonicalize file paths before use. Verify resolved paths are within the allowed directory.",
    "CWE-319": "Use HTTPS for all communications containing sensitive data.",
    "CWE-532": "Redact sensitive values (passwords, tokens, PII) before logging.",
    "CWE-601": "Validate redirect targets against an allowlist of trusted domains or paths.",
    "CWE-434": "Validate file type, size, and content before storing uploaded files.",
    "CWE-862": "Add authorization checks to all protected endpoints.",
    "CWE-352": "Implement CSRF tokens on all state-changing operations.",
    "CWE-611": "Disable external entity processing in XML parsers.",
    "CWE-918": "Validate and restrict URL targets. Block requests to private IP ranges and internal services.",
    "CWE-94": "Avoid eval/exec with user input. Use safe alternatives like expression parsers or sandboxed environments.",
    "CWE-489": "Disable debug mode before deploying to production. Use environment variables to control debug settings.",
    "CWE-400": "Implement rate limiting and resource caps to prevent denial-of-service attacks.",
    "CWE-200": "Remove or restrict access to sensitive information in error responses and API outputs.",
    "CWE-209": "Use generic error messages in production. Never expose stack traces or internal details to users.",
    "CWE-732": "Apply the principle of least privilege. Set restrictive permissions on files and resources.",
    "CWE-614": "Set the Secure, HttpOnly, and SameSite flags on all sensitive cookies.",
    "CWE-347": "Always verify cryptographic signatures before trusting signed data.",
    "CWE-90": "Escape special characters in LDAP filter values. Never concatenate user input into LDAP queries.",
    "CWE-703": "Catch specific exceptions and handle them gracefully. Avoid empty catch blocks.",
    "CWE-943": "Use parameterized queries and validate input types for NoSQL queries.",
    "CWE-755": "Add proper exception handling for all expected failure modes.",
    "CWE-377": "Use secure temp file creation functions (e.g., mkstemp, tempfile.NamedTemporaryFile).",
    "CWE-1333": "Simplify the regular expression to avoid catastrophic backtracking, or set a timeout.",
    "CWE-409": "Set maximum decompression size limits when processing compressed data.",
    "CWE-20": "Validate all inputs against expected format, type, and range.",
    "CWE-307": "Implement account lockout or rate limiting on authentication endpoints.",
    "CWE-384": "Regenerate session IDs after successful authentication.",
    "CWE-521": "Require minimum password length, complexity, and check against breached password lists.",
    "CWE-287": "Implement proper authentication mechanisms. Use a proven authentication library.",
    "CWE-916": "Use bcrypt, scrypt, or Argon2 for password hashing instead of fast hash algorithms.",
    "CWE-190": "Validate arithmetic operands and use safe math functions to prevent integer overflow.",
    "CWE-120": "Always validate input length before buffer operations. Use bounds-checked copy functions.",
    "CWE-119": "Use bounds-checked functions and validate buffer sizes before read/write operations.",
    "CWE-416": "Nullify pointers after free and use smart pointers (RAII) where possible.",
    "CWE-415": "Track allocation state and nullify freed pointers. Use RAII or smart pointers.",
    "CWE-476": "Check pointers for null before dereferencing. Initialize pointers to null on declaration.",
    "CWE-134": "Never pass user input as a format string argument. Use a static format string.",
    "CWE-242": "Replace the dangerous function with a safe alternative.",
    "CWE-401": "Free all dynamically allocated memory when no longer needed. Use RAII in C++.",
    "CWE-362": "Use proper locking or atomic operations for concurrent access to shared resources.",
    "CWE-367": "Perform check and use atomically. Use file locks or atomic filesystem operations.",
    "CWE-667": "Ensure locks are acquired and released in consistent order to prevent deadlocks.",
    "CWE-697": "Use strict equality and proper type checking in security-sensitive comparisons.",
    "CWE-704": "Validate types before conversion and handle edge cases for narrowing conversions.",
    "CWE-248": "Catch and handle all expected exception types. Provide fallback behavior.",
    "CWE-396": "Catch specific exception types instead of broad catch-all handlers.",
    "CWE-693": "Verify all security mechanisms are active and properly configured.",
    "CWE-494": "Verify checksums or digital signatures before executing downloaded code.",
    "CWE-345": "Validate data origin using cryptographic signatures or MACs.",
    "CWE-353": "Implement checksums or HMACs to verify integrity of sensitive data.",
    "CWE-312": "Encrypt sensitive data at rest. Never store secrets in plaintext.",
    "CWE-522": "Use strong encryption and secure transport channels for credentials.",
    "CWE-276": "Set restrictive permissions explicitly on resource creation.",
    "CWE-250": "Apply the principle of least privilege. Drop elevated privileges as soon as possible.",
    "CWE-639": "Verify user permissions for every resource access. Use session-based user IDs instead of request parameters.",
    "CWE-477": "Replace deprecated or obsolete functions with their recommended modern alternatives.",
    "CWE-1104": "Update to a maintained version of the component or find an actively maintained alternative.",
    "CWE-1059": "Document security-sensitive code sections with clear comments.",
    "CWE-778": "Log authentication, authorization, and data access events for security monitoring.",
    "CWE-926": "Set android:exported=false for internal components. Add permission checks for exported components.",
    "CWE-942": "Restrict CORS to trusted origins only. Never use wildcard (*) for Access-Control-Allow-Origin.",
    "CWE-915": "Use an allowlist of permitted attributes for mass assignment.",
    "CWE-74": "Sanitize or parameterize all user-controlled data before passing to interpreters.",
    "CWE-95": "Avoid eval with user input. Use safe parsing functions.",
    "CWE-98": "Validate file paths against an allowlist. Disable remote file inclusion.",
    "CWE-88": "Validate and escape all command arguments derived from user input.",
    "CWE-91": "Use parameterized XPath queries. Escape special characters in user input.",
    "CWE-863": "Review and test authorization logic for bypass conditions.",
    "CWE-73": "Validate paths against an allowlist and canonicalize before use.",
    "CWE-259": "Use environment variables or a secrets manager instead of hard-coded passwords.",
    "CWE-208": "Use constant-time comparison functions for security-sensitive value checks.",
    "CWE-1321": "Freeze prototypes or validate input keys. Use Map instead of plain objects for user data.",
    "CWE-1336": "Sandbox templates and validate user input. Never pass user input to template compilation.",
    "CWE-470": "Use an allowlist of permitted class names for dynamic class loading.",
    "CWE-131": "Double-check size arithmetic and use safe allocation wrappers.",
    "CWE-117": "Sanitize newlines and special characters before logging user input.",
    "CWE-479": "Only call async-signal-safe functions in signal handlers.",
    "CWE-310": "Use well-tested crypto libraries with recommended configurations.",
    "CWE-322": "Use authenticated key exchange protocols (TLS 1.3, SSH with host key verification).",
    "CWE-326": "Use at least 128-bit symmetric keys or 2048-bit RSA keys.",
    "CWE-330": "Use a cryptographically secure random generator instead of predictable PRNGs.",
    "CWE-16": "Review and harden security-relevant configuration settings.",
}


def get_language_key(filename):
    """Derive language key from YAML filename."""
    return filename.replace(".yml", "")


def get_fix_text(cwe, lang_key):
    """Get fix text for a CWE+language combo, falling back to generic."""
    key = (cwe, lang_key)
    if key in FIX_BY_CWE_LANG:
        return FIX_BY_CWE_LANG[key]
    if cwe in GENERIC_FIX_BY_CWE:
        return GENERIC_FIX_BY_CWE[cwe]
    return None


def escape_yaml_double_quoted(s):
    """Escape a string for use in YAML double-quoted context."""
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("\n", "\\n")
    return s


def rewrite_file(filepath, stats):
    """Rewrite messages and add fix metadata in a single YAML file."""
    with open(filepath) as f:
        content = f.read()

    # Parse with PyYAML to get structured data
    with open(filepath) as f:
        data = yaml.safe_load(f)

    rules = data.get("rules", [])
    lang_key = get_language_key(os.path.basename(filepath))

    lines = content.split("\n")
    # We'll track modifications as (line_index, action, data)
    # Process rules by finding their message lines and metadata blocks

    # Build a mapping of rule index -> info we need
    rule_infos = []
    for rule in rules:
        meta = rule.get("metadata", {})
        rule_infos.append({
            "id": rule.get("id", ""),
            "message": rule.get("message", ""),
            "severity": rule.get("severity", ""),
            "cwe": str(meta.get("cwe", "")),
            "has_fix": "fix" in meta,
        })

    # Find all message lines and metadata blocks
    # We process the file line by line to find:
    # 1. message: "..." lines (for replacement)
    # 2. metadata: blocks (for fix insertion)

    # First pass: find all rule boundaries (lines that start with "  - id:")
    rule_starts = []
    for i, line in enumerate(lines):
        if re.match(r"^  - id:\s+", line):
            rule_starts.append(i)

    if len(rule_starts) != len(rule_infos):
        print(f"  WARNING: {filepath}: found {len(rule_starts)} rule starts but "
              f"{len(rule_infos)} rules from YAML. Skipping file.")
        return content

    # For each rule, find its message line and metadata block end
    modifications = []  # list of (line_idx, 'replace_message', new_line) or (line_idx, 'insert_fix', fix_lines)

    for rule_idx, rule_info in enumerate(rule_infos):
        rule_start = rule_starts[rule_idx]
        rule_end = rule_starts[rule_idx + 1] if rule_idx + 1 < len(rule_starts) else len(lines)

        # Find message line within this rule
        message_line_idx = None
        for i in range(rule_start, rule_end):
            if re.match(r"^\s+message:\s+\"", lines[i]):
                message_line_idx = i
                break

        # Find metadata block within this rule
        meta_start_idx = None
        meta_end_idx = None
        meta_indent = None
        for i in range(rule_start, rule_end):
            m = re.match(r"^(\s+)metadata:\s*$", lines[i])
            if m:
                meta_start_idx = i
                meta_indent = m.group(1)
                field_indent = meta_indent + "  "
                # Find end of metadata block
                j = i + 1
                while j < rule_end:
                    fline = lines[j]
                    if fline.strip() == "":
                        break
                    fm = re.match(r"^" + re.escape(field_indent) + r"(\w[\w_-]*):", fline)
                    if fm:
                        j += 1
                        # Skip list items under this field
                        while j < rule_end:
                            list_line = lines[j]
                            if re.match(r"^" + re.escape(field_indent) + r"  - ", list_line):
                                j += 1
                            else:
                                break
                        continue
                    else:
                        break
                meta_end_idx = j
                break

        cwe = rule_info["cwe"]
        msg = rule_info["message"]
        severity = rule_info["severity"]

        # 1. Message rewrite: if message < 60 chars and CWE has expanded message
        if message_line_idx is not None and len(msg) < 60 and cwe in CWE_MESSAGES:
            new_msg = CWE_MESSAGES[cwe]
            escaped_msg = escape_yaml_double_quoted(new_msg)
            # Preserve the original indentation
            indent_match = re.match(r"^(\s+)message:", lines[message_line_idx])
            indent = indent_match.group(1) if indent_match else "    "
            new_line = f'{indent}message: "{escaped_msg}"'
            modifications.append(("replace", message_line_idx, new_line))
            stats["messages_rewritten"] += 1

        # 2. Fix insertion: if CRITICAL/HIGH, no fix field, and we have fix text
        if (severity in ("CRITICAL", "HIGH") and not rule_info["has_fix"]
                and meta_end_idx is not None and meta_indent is not None):
            fix_text = get_fix_text(cwe, lang_key)
            if fix_text:
                field_indent = meta_indent + "  "
                escaped_fix = escape_yaml_double_quoted(fix_text)
                fix_line = f'{field_indent}fix: "{escaped_fix}"'
                modifications.append(("insert", meta_end_idx, [fix_line]))
                stats["fixes_added"] += 1

    if not modifications:
        return content

    # Sort modifications by line index in reverse order so insertions don't shift
    # line numbers for earlier modifications.
    # For same line index, replacements before insertions (replace doesn't shift)
    modifications.sort(key=lambda x: (x[1], 0 if x[0] == "replace" else 1), reverse=True)

    for mod in modifications:
        if mod[0] == "replace":
            _, line_idx, new_line = mod
            lines[line_idx] = new_line
        elif mod[0] == "insert":
            _, line_idx, new_lines = mod
            lines[line_idx:line_idx] = new_lines

    return "\n".join(lines)


def main():
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "socket_basics", "rules")

    if not os.path.isdir(rules_dir):
        print(f"ERROR: Rules directory not found: {rules_dir}")
        sys.exit(1)

    stats = {
        "messages_rewritten": 0,
        "fixes_added": 0,
        "files_processed": 0,
        "rules_processed": 0,
    }

    yml_files = sorted(f for f in os.listdir(rules_dir) if f.endswith(".yml"))
    print(f"Found {len(yml_files)} YAML files in {rules_dir}")

    for fname in yml_files:
        filepath = os.path.join(rules_dir, fname)
        with open(filepath) as f:
            data = yaml.safe_load(f)
        rule_count = len(data.get("rules", []))
        stats["rules_processed"] += rule_count

        rewritten = rewrite_file(filepath, stats)
        with open(filepath, "w") as f:
            f.write(rewritten)
        stats["files_processed"] += 1
        print(f"  Processed {fname} ({rule_count} rules)")

    print(f"\n{'='*60}")
    print(f"Phase 3 complete!")
    print(f"{'='*60}")
    print(f"Files processed:      {stats['files_processed']}")
    print(f"Rules processed:      {stats['rules_processed']}")
    print(f"Messages rewritten:   {stats['messages_rewritten']}")
    print(f"Fix fields added:     {stats['fixes_added']}")

    # Verify all files still parse
    print(f"\nVerifying YAML syntax...")
    errors = 0
    for fname in yml_files:
        filepath = os.path.join(rules_dir, fname)
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)
            if not data or "rules" not in data:
                print(f"  WARNING: {fname} has no 'rules' key")
                errors += 1
        except yaml.YAMLError as e:
            print(f"  ERROR: {fname} failed to parse: {e}")
            errors += 1

    if errors:
        print(f"\n{errors} file(s) had issues!")
        sys.exit(1)
    else:
        print(f"All {len(yml_files)} files parse successfully.")

    # Check remaining short messages
    print(f"\nRemaining short messages (<60 chars):")
    remaining = 0
    for fname in yml_files:
        filepath = os.path.join(rules_dir, fname)
        with open(filepath) as f:
            data = yaml.safe_load(f)
        for rule in data.get("rules", []):
            msg = rule.get("message", "")
            if len(msg) < 60:
                remaining += 1
                cwe = str(rule.get("metadata", {}).get("cwe", ""))
                print(f"  [{rule['severity']}] [{cwe}] ({len(msg)} chars) {rule['id']}: {msg[:80]}")
    if remaining == 0:
        print("  None! All messages are >= 60 characters.")
    else:
        print(f"  {remaining} rules still have short messages.")

    # Count fix fields
    print(f"\nFix field coverage:")
    total_rules = 0
    fix_count = 0
    crit_high_total = 0
    crit_high_with_fix = 0
    for fname in yml_files:
        filepath = os.path.join(rules_dir, fname)
        with open(filepath) as f:
            data = yaml.safe_load(f)
        for rule in data.get("rules", []):
            total_rules += 1
            meta = rule.get("metadata", {})
            if "fix" in meta:
                fix_count += 1
            if rule.get("severity") in ("CRITICAL", "HIGH"):
                crit_high_total += 1
                if "fix" in meta:
                    crit_high_with_fix += 1

    print(f"  Total rules: {total_rules}")
    print(f"  Rules with fix: {fix_count}/{total_rules}")
    print(f"  CRITICAL+HIGH with fix: {crit_high_with_fix}/{crit_high_total}")


if __name__ == "__main__":
    main()
