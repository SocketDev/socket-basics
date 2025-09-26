import Foundation
import Security

// Hardcoded credentials
let SECRET_KEY = "swift_super_secret_2023"
let API_TOKEN = "sw_1234567890abcdef"
let DB_PASSWORD = "admin123!@#"

class VulnerableApp {
    
    func main() {
        print("=== Vulnerable Swift Application ===")
        print("Secret Key: \(SECRET_KEY)")
        
        print("\n1. Testing memory safety issues...")
        memorySafetyDemo()
        
        print("\n2. Testing command injection...")
        commandInjectionDemo()
        
        print("\n3. Testing path traversal...")
        pathTraversalDemo()
        
        print("\n4. Testing weak cryptography...")
        weakCryptographyDemo()
        
        print("\n5. Testing information disclosure...")
        informationDisclosureDemo()
        
        print("\n6. Testing unsafe pointer operations...")
        unsafePointerDemo()
        
        print("\n7. Testing race conditions...")
        raceConditionDemo()
    }
    
    func memorySafetyDemo() {
        print("Enter buffer size: ", terminator: "")
        guard let input = readLine(), let size = Int(input) else {
            print("Invalid input")
            return
        }
        
        // Potential memory issues with unsafe operations
        let pointer = UnsafeMutablePointer<Int>.allocate(capacity: size)
        defer { pointer.deallocate() }
        
        // Initialize memory
        pointer.initialize(repeating: 42, count: size)
        
        // Potential buffer overflow - accessing beyond allocated memory
        for i in 0..<(size + 10) {  // Accessing beyond allocated size
            if i < size {
                pointer[i] = i
            } else {
                // This could cause a crash or memory corruption
                print("Accessing beyond bounds: index \(i)")
            }
        }
        
        print("Memory operations completed")
    }
    
    func commandInjectionDemo() {
        print("Enter filename to process: ", terminator: "")
        guard let filename = readLine() else { return }
        
        // Command injection vulnerability
        let command = "ls -la \(filename)"
        print("Executing command: \(command)")
        
        let process = Process()
        process.launchPath = "/bin/sh"
        process.arguments = ["-c", command]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                print("Command output: \(output)")
            }
        } catch {
            print("Command execution error: \(error)")
        }
    }
    
    func pathTraversalDemo() {
        print("Enter file path to read: ", terminator: "")
        guard let filePath = readLine() else { return }
        
        // Path traversal vulnerability - no validation
        do {
            let content = try String(contentsOfFile: filePath, encoding: .utf8)
            let preview = String(content.prefix(200))
            print("File content: \(preview)...")
        } catch {
            print("File read error: \(error)")
        }
    }
    
    func weakCryptographyDemo() {
        let plaintext = "Sensitive user data"
        
        // Weak cryptography - MD5 is broken
        if let data = plaintext.data(using: .utf8) {
            let md5Hash = data.md5
            print("MD5 Hash: \(md5Hash)")
        }
        
        // Weak random number generation
        srand48(12345)  // Fixed seed
        let sessionToken = Int(drand48() * 1000000)
        print("Predictable Session Token: \(sessionToken)")
        
        // Hardcoded encryption parameters
        let hardcodedKey = "1234567890123456"
        let hardcodedIV = Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        print("Using hardcoded key: \(hardcodedKey)")
        print("Using hardcoded IV: \(hardcodedIV.base64EncodedString())")
    }
    
    func informationDisclosureDemo() {
        // Information disclosure through error messages and logging
        let databaseConfig = [
            "host": "localhost",
            "user": "admin",
            "password": DB_PASSWORD,
            "api_key": API_TOKEN
        ]
        
        print("Database configuration: \(databaseConfig)")
        
        // Simulating an error with sensitive information
        do {
            try simulateDatabaseConnection()
        } catch {
            print("Database connection failed with full details: \(error)")
            print("Connection string: host=localhost, user=admin, password=\(DB_PASSWORD)")
            print("API Token for debugging: \(API_TOKEN)")
        }
    }
    
    func simulateDatabaseConnection() throws {
        throw NSError(domain: "DatabaseError", 
                     code: 1001, 
                     userInfo: [NSLocalizedDescriptionKey: "Connection failed: Invalid credentials for user 'admin' with password '\(DB_PASSWORD)'"])
    }
    
    func unsafePointerDemo() {
        // Unsafe pointer operations
        let data = Data([1, 2, 3, 4, 5])
        
        data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            guard let baseAddress = bytes.baseAddress else { return }
            
            // Potentially unsafe pointer arithmetic
            for i in 0..<10 {  // May access beyond the data bounds
                let byte = baseAddress.advanced(by: i).assumingMemoryBound(to: UInt8.self).pointee
                print("Byte \(i): \(byte)")
            }
        }
        
        // Dangling pointer example
        var pointer: UnsafePointer<Int>?
        do {
            let buffer = UnsafeMutablePointer<Int>.allocate(capacity: 5)
            buffer.initialize(repeating: 42, count: 5)
            pointer = UnsafePointer(buffer)
            buffer.deallocate()  // Memory deallocated, pointer becomes dangling
        }
        
        // Using dangling pointer (undefined behavior)
        if let p = pointer {
            print("Dangling pointer value: \(p.pointee)")  // Dangerous!
        }
    }
    
    func raceConditionDemo() {
        // Race condition vulnerability with shared mutable state
        var sharedCounter = 0
        let queue = DispatchQueue.global(qos: .default)
        let group = DispatchGroup()
        
        for i in 1...10 {
            group.enter()
            queue.async {
                for _ in 1...100 {
                    // Race condition - non-atomic increment
                    let temp = sharedCounter
                    Thread.sleep(forTimeInterval: 0.001) // Simulate some processing
                    sharedCounter = temp + 1
                }
                print("Task \(i) finished, counter: \(sharedCounter)")
                group.leave()
            }
        }
        
        group.wait()
        print("Final counter value (should be 1000, but likely less due to race condition): \(sharedCounter)")
    }
}

// Vulnerable data structures
class VulnerableUser {
    let id: String
    var password: String = "default123"  // Default weak password
    private(set) var permissions: [String] = []
    
    init(id: String) {
        self.id = id
    }
    
    // Vulnerable method that allows external modification
    func getPermissions() -> UnsafeMutablePointer<[String]> {
        return withUnsafeMutablePointer(to: &permissions) { $0 }
    }
    
    // Timing attack vulnerability
    func authenticate(inputPassword: String) -> Bool {
        Thread.sleep(forTimeInterval: 0.1)  // Fixed delay regardless of password correctness
        return password == inputPassword
    }
}

// Singleton with thread safety issues
class VulnerableConfig {
    static let shared = VulnerableConfig()
    private var apiKey: String?
    private var isInitialized = false
    
    private init() {}
    
    func initialize(key: String) {
        // Race condition vulnerability - not thread safe
        if !isInitialized {
            Thread.sleep(forTimeInterval: 0.01)  // Simulate initialization delay
            apiKey = key
            isInitialized = true
        }
    }
    
    func getApiKey() -> String? {
        return apiKey
    }
}

// Vulnerable networking class
class VulnerableNetworking {
    func makeUnsafeRequest(url: String) {
        // URL injection vulnerability - no validation
        guard let requestUrl = URL(string: url) else {
            print("Invalid URL")
            return
        }
        
        var request = URLRequest(url: requestUrl)
        request.setValue("Bearer \(API_TOKEN)", forHTTPHeaderField: "Authorization")  // Exposed token
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                // Information disclosure through error logging
                print("Network error with full details: \(error)")
                print("Request URL: \(url)")
                print("API Token: \(API_TOKEN)")
                return
            }
            
            if let data = data {
                print("Response data: \(String(data: data, encoding: .utf8) ?? "Unable to decode")")
            }
        }
        
        task.resume()
    }
}

// Extension with crypto vulnerabilities
extension Data {
    var md5: String {
        // Using deprecated and broken MD5
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        self.withUnsafeBytes { bytes in
            CC_MD5(bytes.baseAddress, CC_LONG(self.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

// Unsafe C interop
func unsafeCInterop() {
    print("Enter data to process with C functions: ", terminator: "")
    guard let input = readLine() else { return }
    
    // Unsafe string conversion
    input.withCString { cString in
        // Potential buffer overflow if C function doesn't handle long strings
        let length = strlen(cString)
        print("String length: \(length)")
        
        // Unsafe memory copying
        let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: 64)  // Fixed size buffer
        strcpy(buffer, cString)  // Potential buffer overflow
        
        print("Copied string: \(String(cString: buffer))")
        buffer.deallocate()
    }
}

// Main execution
let app = VulnerableApp()
app.main()

print("\n=== Additional Vulnerability Demonstrations ===")

// Vulnerable user demonstration
let user = VulnerableUser(id: "user123")
let permissionsPointer = user.getPermissions()
// External code can modify internal state through unsafe pointer
print("User created with ID: \(user.id)")

// Config race condition demonstration
VulnerableConfig.shared.initialize(key: API_TOKEN)
print("Config API Key: \(VulnerableConfig.shared.getApiKey() ?? "nil")")

// Unsafe C interop demonstration
unsafeCInterop()

// Networking vulnerability demonstration
let networking = VulnerableNetworking()
print("Enter URL to request: ", terminator: "")
if let url = readLine() {
    networking.makeUnsafeRequest(url: url)
}

print("\nVulnerable Swift application completed.")
