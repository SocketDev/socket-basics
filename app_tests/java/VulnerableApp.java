import java.sql.*;
import java.util.Scanner;

public class VulnerableApp {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter user ID: ");
        String userId = scanner.nextLine();
        
        // SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE id = " + userId;
        
        // Command injection vulnerability  
        try {
            Runtime.getRuntime().exec("ls -la " + userId);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // Hardcoded password
        String password = "admin123";
        
        // Weak random
        java.util.Random rand = new java.util.Random();
        int token = rand.nextInt();
        
        System.out.println("Query: " + query);
    }
}
