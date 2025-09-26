import scala.sys.process._
import java.sql.DriverManager
import java.security.MessageDigest
import java.io.{ObjectInputStream, ByteArrayInputStream, File}
import java.util.{Base64, Random}
import scala.util.{Try, Success, Failure}
import scala.io.Source

// Hardcoded credentials
object VulnerableApp {
  private val SECRET_KEY = "scala_super_secret_2023"
  private val API_TOKEN = "sc_1234567890abcdef"
  private val DB_PASSWORD = "admin123!@#"
  
  def main(args: Array[String]): Unit = {
    println("=== Vulnerable Scala Application ===")
    println(s"Secret Key: $SECRET_KEY")
    
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
    
    println("\n8. Testing Race Conditions...")
    raceConditionDemo()
  }
  
  def sqlInjectionDemo(): Unit = {
    print("Enter user ID: ")
    val userId = scala.io.StdIn.readLine()
    
    // SQL Injection vulnerability
    val query = s"SELECT * FROM users WHERE id = $userId"
    println(s"Executing vulnerable query: $query")
    
    Try {
      // Simulated database connection with exposed credentials
      val connectionString = s"jdbc:mysql://localhost:3306/testdb?user=admin&password=$DB_PASSWORD"
      println(s"Connection string: $connectionString")
      
      // In a real scenario, this would execute the vulnerable query
      Class.forName("com.mysql.cj.jdbc.Driver")
      val connection = DriverManager.getConnection(connectionString)
      val statement = connection.createStatement()
      // statement.executeQuery(query) // This would be vulnerable
      statement.close()
      connection.close()
    } match {
      case Success(_) => println("Query executed successfully")
      case Failure(exception) => println(s"SQL Error: ${exception.getMessage}")
    }
  }
  
  def commandInjectionDemo(): Unit = {
    print("Enter filename to process: ")
    val filename = scala.io.StdIn.readLine()
    
    // Command injection vulnerability
    val command = s"ls -la $filename"
    println(s"Executing command: $command")
    
    Try {
      val result = command.!!
      println(s"Command output: $result")
    } match {
      case Success(_) => // Output already printed
      case Failure(exception) => println(s"Command execution error: ${exception.getMessage}")
    }
  }
  
  def weakCryptographyDemo(): Unit = {
    val plaintext = "Sensitive user data"
    
    // Weak cryptography - MD5 is broken
    val md5Digest = MessageDigest.getInstance("MD5")
    val md5Hash = md5Digest.digest(plaintext.getBytes())
    val md5Hex = md5Hash.map("%02x".format(_)).mkString
    println(s"MD5 Hash: $md5Hex")
    
    // Weak random number generation
    val weakRandom = new Random(12345) // Fixed seed
    val sessionToken = weakRandom.nextInt()
    println(s"Predictable Session Token: $sessionToken")
    
    // Hardcoded encryption parameters
    val hardcodedKey = "1234567890123456"
    val hardcodedIV = "abcdefghijklmnop"
    println(s"Using hardcoded key: $hardcodedKey")
    println(s"Using hardcoded IV: $hardcodedIV")
  }
  
  def insecureDeserializationDemo(): Unit = {
    print("Enter serialized object (Base64): ")
    val serializedInput = scala.io.StdIn.readLine()
    
    Try {
      // Insecure deserialization vulnerability
      val decodedBytes = Base64.getDecoder.decode(serializedInput)
      val objectInputStream = new ObjectInputStream(new ByteArrayInputStream(decodedBytes))
      val deserializedObject = objectInputStream.readObject()
      
      println(s"Deserialized object: $deserializedObject")
      objectInputStream.close()
    } match {
      case Success(_) => // Object successfully deserialized
      case Failure(exception) => println(s"Deserialization error: ${exception.getMessage}")
    }
  }
  
  def pathTraversalDemo(): Unit = {
    print("Enter file path to read: ")
    val filePath = scala.io.StdIn.readLine()
    
    // Path traversal vulnerability - no validation
    Try {
      val source = Source.fromFile(filePath)
      val content = source.mkString
      source.close()
      
      val preview = if (content.length > 200) content.substring(0, 200) + "..." else content
      println(s"File content: $preview")
    } match {
      case Success(_) => // Content already printed
      case Failure(exception) => println(s"File read error: ${exception.getMessage}")
    }
  }
  
  def informationDisclosureDemo(): Unit = {
    Try {
      // Simulating a database connection error with sensitive information
      throw new Exception(s"Database connection failed: host=localhost, user=admin, password=$DB_PASSWORD")
    } match {
      case Success(_) => // Won't reach here
      case Failure(exception) =>
        // Information disclosure through error messages
        println(s"Full error details: ${exception.getStackTrace.mkString("\n")}")
        println(s"API Token for debugging: $API_TOKEN")
        println(s"Exception message with sensitive data: ${exception.getMessage}")
    }
  }
  
  def unsafeReflectionDemo(): Unit = {
    print("Enter class name to instantiate: ")
    val className = scala.io.StdIn.readLine()
    
    Try {
      // Unsafe reflection - allows instantiation of arbitrary classes
      val clazz = Class.forName(className)
      val instance = clazz.getDeclaredConstructor().newInstance()
      println(s"Created instance of: ${instance.getClass.getName}")
      
      print("Enter method name to invoke: ")
      val methodName = scala.io.StdIn.readLine()
      
      val method = clazz.getDeclaredMethod(methodName)
      method.setAccessible(true) // Bypasses access controls
      val result = method.invoke(instance)
      println(s"Method invocation result: $result")
    } match {
      case Success(_) => // Result already printed
      case Failure(exception) => println(s"Reflection error: ${exception.getMessage}")
    }
  }
  
  def raceConditionDemo(): Unit = {
    // Race condition vulnerability with mutable shared state
    var sharedCounter = 0
    val threads = (1 to 10).map { i =>
      new Thread(new Runnable {
        def run(): Unit = {
          for (_ <- 1 to 100) {
            // Race condition - non-atomic increment
            val temp = sharedCounter
            Thread.sleep(1) // Simulate some processing
            sharedCounter = temp + 1
          }
          println(s"Thread $i finished, counter: $sharedCounter")
        }
      })
    }
    
    threads.foreach(_.start())
    threads.foreach(_.join())
    println(s"Final counter value (should be 1000, but likely less due to race condition): $sharedCounter")
  }
  
  // Vulnerable case class with mutable collections
  case class VulnerableUser(
    id: String,
    password: String = "default123", // Default weak password
    permissions: scala.collection.mutable.ListBuffer[String] = scala.collection.mutable.ListBuffer()
  ) {
    // Vulnerable method that exposes internal mutable state
    def getPermissions: scala.collection.mutable.ListBuffer[String] = permissions
    
    // Timing attack vulnerability
    def authenticate(inputPassword: String): Boolean = {
      Thread.sleep(100) // Fixed delay regardless of password correctness
      password == inputPassword
    }
  }
  
  // Vulnerable singleton object with mutable state
  object VulnerableConfig {
    private var apiKey: Option[String] = None
    private var isInitialized = false
    
    def initialize(key: String): Unit = {
      // Race condition vulnerability - not thread safe
      if (!isInitialized) {
        Thread.sleep(10) // Simulate initialization delay
        apiKey = Some(key)
        isInitialized = true
      }
    }
    
    def getApiKey: Option[String] = apiKey
  }
  
  // Vulnerable implicit conversion
  implicit class StringExecutor(command: String) {
    def executeDangerously(): String = {
      // Potential command injection through implicit conversion
      Try(command.!!) match {
        case Success(output) => output
        case Failure(exception) => s"Execution failed: ${exception.getMessage}"
      }
    }
  }
  
  // Vulnerable actor-like pattern (without proper actor framework)
  class VulnerableProcessor {
    private val messageQueue = scala.collection.mutable.Queue[Any]()
    private var isRunning = true
    
    def sendMessage(message: Any): Unit = {
      messageQueue.synchronized {
        messageQueue.enqueue(message)
      }
    }
    
    def processMessages(): Unit = {
      while (isRunning) {
        messageQueue.synchronized {
          if (messageQueue.nonEmpty) {
            val message = messageQueue.dequeue()
            message match {
              case command: String if command.startsWith("exec:") =>
                // Vulnerable: executes arbitrary commands from messages
                val cmd = command.substring(5)
                println(s"Executing: $cmd")
                Try(cmd.!!) match {
                  case Success(output) => println(s"Output: $output")
                  case Failure(ex) => println(s"Error: ${ex.getMessage}")
                }
              case data: String if data.startsWith("eval:") =>
                // Vulnerable: evaluates Scala code
                val code = data.substring(5)
                println(s"Evaluating Scala code: $code")
                // Note: Scala doesn't have built-in eval, but this represents the concept
                println("Code evaluation would be dangerous here")
              case _ =>
                println(s"Processing message: $message")
            }
          }
        }
        Thread.sleep(100)
      }
    }
    
    def stop(): Unit = {
      isRunning = false
    }
  }
  
  // Additional demonstration of vulnerabilities
  def additionalVulnerabilityDemo(): Unit = {
    println("\n=== Additional Vulnerability Demonstrations ===")
    
    // Vulnerable user demonstration
    val user = VulnerableUser("user123")
    user.getPermissions += "admin" // External code can modify internal state
    println(s"User permissions modified externally: ${user.permissions}")
    
    // Config race condition demonstration
    VulnerableConfig.initialize(API_TOKEN)
    println(s"Config API Key: ${VulnerableConfig.getApiKey}")
    
    // String executor vulnerability
    print("Enter command to execute: ")
    val command = scala.io.StdIn.readLine()
    val result = command.executeDangerously()
    println(s"Command result: $result")
    
    // Vulnerable processor
    val processor = new VulnerableProcessor()
    val processorThread = new Thread(() => processor.processMessages())
    processorThread.start()
    
    processor.sendMessage("exec:echo 'This is dangerous'")
    processor.sendMessage("eval:println(\"This would be code execution\")")
    
    Thread.sleep(1000)
    processor.stop()
    processorThread.interrupt()
  }
}
