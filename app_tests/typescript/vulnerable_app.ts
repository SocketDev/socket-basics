// Note: In a real Node.js environment, these would be:
// import * as fs from 'fs';
// import * as path from 'path';
// import { execSync } from 'child_process';
// import * as crypto from 'crypto';

// Simulated Node.js modules for demonstration
const fs = {
    readFileSync: (_path: string, _encoding: string) => "simulated file content"
};

const path = {
    join: (...paths: string[]) => paths.join('/')
};

const execSync = (command: string, _options?: any) => {
    return `simulated output for: ${command}`;
};

const crypto = {
    createHash: (_algorithm: string) => ({
        update: (_data: string) => ({
            digest: (_encoding: string) => "simulated_hash"
        })
    })
};

// Simulated Node.js globals
const __dirname = "/simulated/directory";
const Buffer = {
    from: (_data: string) => ({
        toString: (_encoding: string) => "simulated_buffer_string"
    })
};

// Hardcoded credentials
const SECRET_KEY: string = "typescript_super_secret_2023";
const API_TOKEN: string = "ts_1234567890abcdef";
const DB_PASSWORD: string = "admin123!@#";

class VulnerableApp {
    
    public main(): void {
        console.log("=== Vulnerable TypeScript Application ===");
        console.log(`Secret Key: ${SECRET_KEY}`);
        
        console.log("\n1. Testing SQL Injection...");
        this.sqlInjectionDemo();
        
        console.log("\n2. Testing Command Injection...");
        this.commandInjectionDemo();
        
        console.log("\n3. Testing Path Traversal...");
        this.pathTraversalDemo();
        
        console.log("\n4. Testing Weak Cryptography...");
        this.weakCryptographyDemo();
        
        console.log("\n5. Testing Information Disclosure...");
        this.informationDisclosureDemo();
        
        console.log("\n6. Testing Type Coercion Vulnerabilities...");
        this.typeCoercionDemo();
        
        console.log("\n7. Testing Prototype Pollution...");
        this.prototypePollutionDemo();
        
        console.log("\n8. Testing Unsafe Deserialization...");
        this.unsafeDeserializationDemo();
    }
    
    private sqlInjectionDemo(): void {
        // Simulated user input
        const userId: string = "1' OR '1'='1' --";
        
        // SQL Injection vulnerability - string concatenation
        const query: string = `SELECT * FROM users WHERE id = ${userId}`;
        console.log(`Executing vulnerable query: ${query}`);
        
        // Template literal injection
        const userRole: string = "admin'; DROP TABLE users; --";
        const templateQuery: string = `SELECT * FROM permissions WHERE role = '${userRole}'`;
        console.log(`Template query: ${templateQuery}`);
    }
    
    private commandInjectionDemo(): void {
        const filename: string = "; rm -rf / #";
        
        try {
            // Command injection vulnerability
            const command: string = `ls -la ${filename}`;
            console.log(`Executing command: ${command}`);
            
            const output = execSync(command, { encoding: 'utf8', timeout: 5000 });
            console.log(`Command output: ${output}`);
        } catch (error: any) {
            console.log(`Command execution error: ${error.message}`);
        }
    }
    
    private pathTraversalDemo(): void {
        const filePath: string = "../../../etc/passwd";
        
        try {
            // Path traversal vulnerability - no validation
            const fullPath = path.join(__dirname, filePath);
            const content = fs.readFileSync(fullPath, 'utf8');
            
            const preview = content.length > 200 ? content.substring(0, 200) + "..." : content;
            console.log(`File content: ${preview}`);
        } catch (error: any) {
            console.log(`File read error: ${error.message}`);
        }
    }
    
    private weakCryptographyDemo(): void {
        const plaintext: string = "Sensitive user data";
        
        // Weak cryptography - MD5 is broken
        const md5Hash = crypto.createHash('md5').update(plaintext).digest('hex');
        console.log(`MD5 Hash: ${md5Hash}`);
        
        // Weak random number generation
        // Math.seedrandom('12345'); // If seedrandom library was used with fixed seed
        // Simulating weak randomness with fixed seed concept
        const weakSeed = 12345;
        const sessionToken: number = Math.floor((weakSeed / 12345) * 1000000);
        console.log(`Predictable Session Token: ${sessionToken}`);
        
        // Hardcoded encryption parameters
        const hardcodedKey: string = "1234567890123456";
        const hardcodedIV = Buffer.from("abcdefghijklmnop");
        console.log(`Using hardcoded key: ${hardcodedKey}`);
        console.log(`Using hardcoded IV: ${hardcodedIV.toString('base64')}`);
    }
    
    private informationDisclosureDemo(): void {
        try {
            // Simulating a database connection error with sensitive information
            throw new Error(`Database connection failed: host=localhost, user=admin, password=${DB_PASSWORD}`);
        } catch (error: any) {
            // Information disclosure through error messages
            console.log(`Full error details: ${error.stack}`);
            console.log(`API Token for debugging: ${API_TOKEN}`);
            console.log(`Exception message with sensitive data: ${error.message}`);
        }
    }
    
    private typeCoercionDemo(): void {
        // Type coercion vulnerabilities specific to JavaScript/TypeScript
        const userInput: any = "1"; // Should be number but received as string
        
        // Dangerous type coercion
        if (userInput == 1) {  // Using == instead of === allows type coercion
            console.log("Authentication bypassed due to type coercion");
        }
        
        // Array coercion issues
        const ids: any = "1,2,3";
        const processedIds = ids.split ? ids.split(',') : [ids]; // Type guard, but unsafe
        console.log(`Processed IDs: ${processedIds}`);
        
        // Boolean coercion vulnerabilities
        const isAdmin: any = "false"; // String instead of boolean
        if (isAdmin) {  // String "false" is truthy
            console.log("Admin access granted due to truthy string");
        }
        
        // Number coercion issues
        const amount: any = "100.50extra";
        const parsedAmount = parseInt(amount as string); // Partial parsing
        console.log(`Parsed amount: ${parsedAmount}`); // Will be 100, not 100.50
    }
    
    private prototypePollutionDemo(): void {
        // Prototype pollution vulnerability
        const userInput = {
            "__proto__": {
                "isAdmin": true,
                "polluted": "This pollutes the prototype"
            }
        };
        
        // Unsafe merge that enables prototype pollution
        const config: any = {};
        this.unsafeMerge(config, userInput);
        
        // Check if prototype was polluted
        const testObj: any = {};
        console.log(`Prototype polluted - isAdmin: ${testObj.isAdmin}`);
        console.log(`Prototype polluted - polluted: ${testObj.polluted}`);
    }
    
    private unsafeMerge(target: any, source: any): void {
        for (const key in source) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (!target[key]) target[key] = {};
                this.unsafeMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    
    private unsafeDeserializationDemo(): void {
        const maliciousJson = '{"__proto__":{"polluted":true},"eval":"console.log(\\"Code executed\\")"}';
        
        try {
            // Unsafe deserialization
            const obj = JSON.parse(maliciousJson);
            
            // If the application processes 'eval' property
            if (obj.eval && typeof obj.eval === 'string') {
                console.log("Potentially dangerous: eval property found in deserialized object");
                // In a real attack, this might be: eval(obj.eval);
            }
            
            console.log(`Deserialized object: ${JSON.stringify(obj)}`);
        } catch (error: any) {
            console.log(`Deserialization error: ${error.message}`);
        }
    }
}

// Vulnerable class with type safety issues
class VulnerableUser {
    public id: string;
    private password: string = "default123"; // Default weak password
    private permissions: string[] = [];
    
    constructor(id: string) {
        this.id = id;
    }
    
    // Type-unsafe method that exposes internal state
    public getPermissions(): any {
        return this.permissions; // Returns actual array, not a copy
    }
    
    // Method with weak type checking
    public updatePassword(newPassword: any): boolean {
        // Doesn't validate that newPassword is actually a string
        this.password = newPassword; // Could be assigned any type
        return true;
    }
    
    // Timing attack vulnerability
    public authenticate(inputPassword: string): boolean {
        // Fixed delay regardless of password correctness
        const start = Date.now();
        while (Date.now() - start < 100) {} // Busy wait for 100ms
        
        return this.password === inputPassword;
    }
}

// Vulnerable singleton with type issues
class VulnerableConfig {
    private static instance: VulnerableConfig;
    private apiKey?: any; // Should be string, but allows any type
    private isInitialized: boolean = false;
    
    public static getInstance(): VulnerableConfig {
        if (!VulnerableConfig.instance) {
            VulnerableConfig.instance = new VulnerableConfig();
        }
        return VulnerableConfig.instance;
    }
    
    public initialize(key: any): void { // Should be string
        // Race condition vulnerability - not thread safe
        if (!this.isInitialized) {
            setTimeout(() => {
                this.apiKey = key; // Could be any type
                this.isInitialized = true;
            }, 10);
        }
    }
    
    public getApiKey(): any {
        return this.apiKey;
    }
}

// Vulnerable generic class
class VulnerableProcessor<T> {
    private data: T[] = [];
    
    // Unsafe generic method
    public process(item: any): T { // Should use proper type constraints
        this.data.push(item as T); // Unsafe type assertion
        return item as T;
    }
    
    // Method that doesn't properly handle generic constraints
    public execute(code: T): void {
        if (typeof code === 'string') {
            // Potential code execution if T is string
            console.log(`Would execute: ${code}`);
            // In a real scenario: eval(code as string);
        }
    }
}

// Interface with security implications
interface UserAction {
    type: string;
    payload: any; // Too permissive
}

class ActionHandler {
    public handleAction(action: UserAction): void {
        // Type-unsafe action handling
        switch (action.type) {
            case 'EXECUTE_COMMAND':
                // Dangerous: executing commands from user input
                const command = action.payload as string;
                console.log(`Would execute command: ${command}`);
                break;
            case 'READ_FILE':
                // Path traversal potential
                const filePath = action.payload as string;
                console.log(`Would read file: ${filePath}`);
                break;
            case 'EVAL_CODE':
                // Code injection potential
                const code = action.payload as string;
                console.log(`Would evaluate code: ${code}`);
                break;
        }
    }
}

// Vulnerable async/Promise handling
class VulnerableAsyncHandler {
    public async processData(data: any): Promise<any> {
        return new Promise((resolve, reject) => {
            // Unsafe promise handling without proper error boundaries
            setTimeout(() => {
                try {
                    // Potentially dangerous operation
                    const result = this.dangerousOperation(data);
                    resolve(result);
                } catch (error) {
                    // Information disclosure in error handling
                    reject({
                        error: error,
                        sensitiveData: {
                            apiKey: API_TOKEN,
                            dbPassword: DB_PASSWORD
                        }
                    });
                }
            }, Math.floor(Math.random() * 1000)); // Race condition potential
        });
    }
    
    private dangerousOperation(data: any): any {
        // Unsafe operation that could throw with sensitive information
        if (data.triggerError) {
            throw new Error(`Operation failed with API key: ${API_TOKEN}`);
        }
        return data;
    }
}

// Main execution
const app = new VulnerableApp();
app.main();

console.log("\n=== Additional TypeScript Vulnerability Demonstrations ===");

// Vulnerable user demonstration
const user = new VulnerableUser("user123");
const permissions = user.getPermissions();
permissions.push("admin"); // External code can modify internal state
console.log(`User permissions modified externally`);

// Unsafe password update
user.updatePassword(12345); // Should be string, but accepts number
user.updatePassword(null);  // Should be string, but accepts null

// Config demonstration
const config = VulnerableConfig.getInstance();
config.initialize({malicious: "object"}); // Should be string
console.log(`Config API Key: ${config.getApiKey()}`);

// Generic processor vulnerability
const processor = new VulnerableProcessor<string>();
processor.process(123); // Should be string, but accepts number
processor.execute("console.log('potential code execution')");

// Action handler vulnerability
const actionHandler = new ActionHandler();
actionHandler.handleAction({
    type: "EXECUTE_COMMAND",
    payload: "rm -rf /"
});

// Async vulnerability demonstration
const asyncHandler = new VulnerableAsyncHandler();
asyncHandler.processData({triggerError: true}).catch((error) => {
    console.log("Async error with sensitive data:", error);
});

console.log("Vulnerable TypeScript application completed.");

// Export for potential module usage (another vulnerability vector)
export { VulnerableApp, VulnerableUser, VulnerableConfig };
