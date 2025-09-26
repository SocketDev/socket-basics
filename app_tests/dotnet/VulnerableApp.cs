using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Web;
using System.Security.Cryptography;
using System.Text;

namespace VulnerableApp
{
    class Program
    {
        // Hardcoded credentials
        private static readonly string ConnectionString = "Server=localhost;Database=TestDB;User Id=admin;Password=password123;";
        private static readonly string ApiKey = "sk-1234567890abcdefghij";
        private static readonly string SecretKey = "MySuper$ecretKey2023!";

        static void Main(string[] args)
        {
            Console.WriteLine("=== Vulnerable .NET Application ===");
            Console.WriteLine($"Using API Key: {ApiKey}");

            Console.WriteLine("\n1. Testing SQL Injection...");
            SqlInjectionDemo();

            Console.WriteLine("\n2. Testing Command Injection...");
            CommandInjectionDemo();

            Console.WriteLine("\n3. Testing Path Traversal...");
            PathTraversalDemo();

            Console.WriteLine("\n4. Testing Weak Cryptography...");
            WeakCryptographyDemo();

            Console.WriteLine("\n5. Testing Insecure Deserialization...");
            InsecureDeserializationDemo();

            Console.WriteLine("\n6. Testing Information Disclosure...");
            InformationDisclosureDemo();
        }

        static void SqlInjectionDemo()
        {
            try
            {
                Console.Write("Enter user ID: ");
                string userId = Console.ReadLine();

                // SQL Injection vulnerability
                string query = $"SELECT * FROM Users WHERE Id = {userId}";
                
                using (var connection = new SqlConnection(ConnectionString))
                {
                    using (var command = new SqlCommand(query, connection))
                    {
                        // This would execute the vulnerable query
                        Console.WriteLine($"Executing query: {query}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SQL Error: {ex.Message}");
            }
        }

        static void CommandInjectionDemo()
        {
            Console.Write("Enter filename to process: ");
            string filename = Console.ReadLine();

            try
            {
                // Command injection vulnerability
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/C type {filename}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                };

                using (Process process = Process.Start(startInfo))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    Console.WriteLine($"Command output: {output}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Command execution error: {ex.Message}");
            }
        }

        static void PathTraversalDemo()
        {
            Console.Write("Enter file path to read: ");
            string filePath = Console.ReadLine();

            try
            {
                // Path traversal vulnerability - no validation
                string content = File.ReadAllText(filePath);
                Console.WriteLine($"File content: {content.Substring(0, Math.Min(200, content.Length))}...");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"File read error: {ex.Message}");
            }
        }

        static void WeakCryptographyDemo()
        {
            string plaintext = "Sensitive user data";

            // Weak cryptography - MD5 is broken
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(plaintext));
                string md5Hash = Convert.ToBase64String(hash);
                Console.WriteLine($"MD5 Hash: {md5Hash}");
            }

            // Weak random number generation
            Random weakRandom = new Random();
            int sessionToken = weakRandom.Next();
            Console.WriteLine($"Session Token: {sessionToken}");

            // Hardcoded IV for encryption
            byte[] hardcodedIV = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            Console.WriteLine($"Using hardcoded IV: {Convert.ToBase64String(hardcodedIV)}");
        }

        static void InsecureDeserializationDemo()
        {
            try
            {
                // Simulated insecure deserialization
                string serializedData = Console.ReadLine();
                
                // This would be vulnerable to deserialization attacks
                // In a real scenario, this could lead to remote code execution
                Console.WriteLine($"Deserializing user input: {serializedData}");
                
                // Simulating unsafe deserialization process
                if (serializedData?.Contains("System.") == true)
                {
                    Console.WriteLine("WARNING: Potentially dangerous type detected in serialized data!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Deserialization error: {ex.Message}");
            }
        }

        static void InformationDisclosureDemo()
        {
            try
            {
                // Information disclosure through error messages
                throw new Exception($"Database connection failed. ConnectionString: {ConnectionString}");
            }
            catch (Exception ex)
            {
                // Exposing sensitive information in error messages
                Console.WriteLine($"Full error details: {ex.ToString()}");
                Console.WriteLine($"Secret key for debugging: {SecretKey}");
            }

            // Logging sensitive information
            Console.WriteLine($"User session started with token: {Guid.NewGuid()}");
            Console.WriteLine($"Database password: password123");
        }

        // Vulnerable method with potential buffer issues (unsafe context)
        unsafe static void UnsafeMemoryOperations()
        {
            byte[] data = Encoding.UTF8.GetBytes("Sensitive data");
            
            fixed (byte* ptr = data)
            {
                // Potentially unsafe memory operations
                for (int i = 0; i < 100; i++) // Potential buffer overflow
                {
                    *(ptr + i) = 0x41; // Could write beyond buffer bounds
                }
            }
        }
    }

    // Vulnerable class with weak access controls
    public class UserManager
    {
        public string AdminPassword = "admin123"; // Public field with sensitive data
        
        public bool AuthenticateUser(string username, string password)
        {
            // Weak authentication logic
            if (username == "admin" && password == AdminPassword)
            {
                return true;
            }
            
            // Timing attack vulnerability
            System.Threading.Thread.Sleep(100);
            return false;
        }
    }
}
