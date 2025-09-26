import java.sql.Connection
import java.sql.DriverManager
import java.sql.Statement
import java.util.*
import java.security.MessageDigest
import java.io.ObjectInputStream
import java.io.ByteArrayInputStream
import java.lang.Runtime
import kotlin.random.Random

// Hardcoded credentials
const val SECRET_KEY = "kotlin_super_secret_2023"
const val API_TOKEN = "kt_1234567890abcdef"
const val DB_PASSWORD = "admin123!@#"

class VulnerableApp {
    
    fun main() {
        println("=== Vulnerable Kotlin Application ===")
        println("Secret Key: $SECRET_KEY")
        
        println("\n1. Testing SQL Injection...")
        sqlInjectionDemo()
        
        println("\n2. Testing Command Injection...")
        commandInjectionDemo()
        
        println("\n3. Testing Weak Cryptography...")
        weakCryptographyDemo()
        
        println("\n4. Testing Insecure Deserialization...")
        insecureDeserializationDemo()
        
        println("\n5. Testing Path Traversal...")
        pathTraversalDemo()
        
        println("\n6. Testing Information Disclosure...")
        informationDisclosureDemo()
        
        println("\n7. Testing Unsafe Reflection...")
        unsafeReflectionDemo()
    }
    
    fun sqlInjectionDemo() {
        print("Enter user ID: ")
        val userId = readLine() ?: ""
        
        // SQL Injection vulnerability
        val query = "SELECT * FROM users WHERE id = $userId"
        println("Executing vulnerable query: $query")
        
        try {
            // Simulated database connection
            val connectionString = "jdbc:mysql://localhost:3306/testdb?user=admin&password=$DB_PASSWORD"
            println("Connection string: $connectionString")
        } catch (e: Exception) {
            println("SQL Error: ${e.message}")
        }
    }
    
    fun commandInjectionDemo() {
        print("Enter filename to process: ")
        val filename = readLine() ?: ""
        
        try {
            // Command injection vulnerability
            val command = "ls -la $filename"
            println("Executing command: $command")
            
            val process = Runtime.getRuntime().exec(command)
            val output = process.inputStream.bufferedReader().readText()
            println("Command output: $output")
        } catch (e: Exception) {
            println("Command execution error: ${e.message}")
        }
    }
    
    fun weakCryptographyDemo() {
        val plaintext = "Sensitive user data"
        
        // Weak cryptography - MD5 is broken
        val md5Digest = MessageDigest.getInstance("MD5")
        val md5Hash = md5Digest.digest(plaintext.toByteArray())
        println("MD5 Hash: ${md5Hash.joinToString("") { "%02x".format(it) }}")
        
        // Weak random number generation
        val weakRandom = Random(12345) // Fixed seed
        val sessionToken = weakRandom.nextInt()
        println("Predictable Session Token: $sessionToken")
        
        // Hardcoded encryption key
        val hardcodedKey = "1234567890123456"
        println("Using hardcoded key: $hardcodedKey")
    }
    
    fun insecureDeserializationDemo() {
        print("Enter serialized object (Base64): ")
        val serializedInput = readLine() ?: ""
        
        try {
            // Insecure deserialization vulnerability
            val decodedBytes = Base64.getDecoder().decode(serializedInput)
            val objectInputStream = ObjectInputStream(ByteArrayInputStream(decodedBytes))
            val deserializedObject = objectInputStream.readObject()
            
            println("Deserialized object: $deserializedObject")
            objectInputStream.close()
        } catch (e: Exception) {
            println("Deserialization error: ${e.message}")
        }
    }
    
    fun pathTraversalDemo() {
        print("Enter file path to read: ")
        val filePath = readLine() ?: ""
        
        try {
            // Path traversal vulnerability - no validation
            val file = java.io.File(filePath)
            val content = file.readText()
            val preview = if (content.length > 200) content.substring(0, 200) + "..." else content
            println("File content: $preview")
        } catch (e: Exception) {
            println("File read error: ${e.message}")
        }
    }
    
    fun informationDisclosureDemo() {
        try {
            // Simulating a database connection error with sensitive information
            throw Exception("Database connection failed: host=localhost, user=admin, password=$DB_PASSWORD")
        } catch (e: Exception) {
            // Information disclosure through error messages
            println("Full error details: ${e.stackTrace.contentToString()}")
            println("API Token for debugging: $API_TOKEN")
            println("Exception message with sensitive data: ${e.message}")
        }
    }
    
    fun unsafeReflectionDemo() {
        print("Enter class name to instantiate: ")
        val className = readLine() ?: ""
        
        try {
            // Unsafe reflection - allows instantiation of arbitrary classes
            val clazz = Class.forName(className)
            val instance = clazz.getDeclaredConstructor().newInstance()
            println("Created instance of: ${instance.javaClass.name}")
            
            // Potentially dangerous method invocation
            print("Enter method name to invoke: ")
            val methodName = readLine() ?: ""
            
            val method = clazz.getDeclaredMethod(methodName)
            method.isAccessible = true // Bypasses access controls
            val result = method.invoke(instance)
            println("Method invocation result: $result")
        } catch (e: Exception) {
            println("Reflection error: ${e.message}")
        }
    }
    
    // Vulnerable data class with mutable collections
    data class VulnerableUser(
        val id: String,
        val password: String = "default123", // Default weak password
        val permissions: MutableList<String> = mutableListOf()
    ) {
        // Vulnerable method that exposes internal state
        fun getPermissions(): MutableList<String> = permissions
        
        // Timing attack vulnerability
        fun authenticate(inputPassword: String): Boolean {
            Thread.sleep(100) // Fixed delay regardless of password correctness
            return password == inputPassword
        }
    }
    
    // Singleton with thread safety issues
    object VulnerableConfig {
        private var apiKey: String? = null
        private var isInitialized = false
        
        fun initialize(key: String) {
            // Race condition vulnerability - not thread safe
            if (!isInitialized) {
                Thread.sleep(10) // Simulate initialization delay
                apiKey = key
                isInitialized = true
            }
        }
        
        fun getApiKey(): String? = apiKey
    }
    
    // Vulnerable extension function
    fun String.executeDangerously(): String {
        // Potential command injection through extension function
        return Runtime.getRuntime().exec(this).inputStream.bufferedReader().readText()
    }
}

// Vulnerable sealed class hierarchy
sealed class UserAction {
    data class ExecuteCommand(val command: String) : UserAction()
    data class ReadFile(val path: String) : UserAction()
    data class WriteFile(val path: String, val content: String) : UserAction()
}

class ActionProcessor {
    fun processAction(action: UserAction): String {
        return when (action) {
            is UserAction.ExecuteCommand -> {
                // Vulnerable: executes arbitrary commands
                Runtime.getRuntime().exec(action.command).inputStream.bufferedReader().readText()
            }
            is UserAction.ReadFile -> {
                // Vulnerable: reads arbitrary files
                java.io.File(action.path).readText()
            }
            is UserAction.WriteFile -> {
                // Vulnerable: writes to arbitrary locations
                java.io.File(action.path).writeText(action.content)
                "File written successfully"
            }
        }
    }
}

// Main function
fun main() {
    val app = VulnerableApp()
    app.main()
    
    println("\n=== Additional Vulnerabilities ===")
    
    // Demonstrate vulnerable user class
    val user = VulnerableApp.VulnerableUser("user123")
    user.getPermissions().add("admin") // External code can modify internal state
    println("User permissions modified externally: ${user.permissions}")
    
    // Demonstrate config race condition
    VulnerableApp.VulnerableConfig.initialize(API_TOKEN)
    println("Config API Key: ${VulnerableApp.VulnerableConfig.getApiKey()}")
    
    // Demonstrate action processor vulnerability
    val processor = ActionProcessor()
    print("Enter command to execute: ")
    val command = readLine() ?: "echo 'safe command'"
    try {
        val result = processor.processAction(UserAction.ExecuteCommand(command))
        println("Command result: $result")
    } catch (e: Exception) {
        println("Action processing error: ${e.message}")
    }
}
