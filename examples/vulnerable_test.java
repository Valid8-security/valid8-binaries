// Java test file with intentional vulnerabilities for testing

import java.io.*;
import java.sql.*;
import javax.servlet.http.*;

public class VulnerableApp {
    
    // CWE-78: Command Injection
    public void executeCommand(String userInput) {
        try {
            Runtime.getRuntime().exec("ls -la " + userInput);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // CWE-89: SQL Injection
    public void queryDatabase(String username) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            ResultSet rs = stmt.executeQuery(query);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    // CWE-22: Path Traversal
    public void readFile(HttpServletRequest request) {
        String filename = request.getParameter("file");
        try {
            File file = new File("/var/www/files/" + filename);
            BufferedReader reader = new BufferedReader(new FileReader(file));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // CWE-327: Weak Cryptography
    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            return new String(hash);
        } catch (Exception e) {
            return null;
        }
    }
    
    // CWE-798: Hardcoded Credentials
    public void connectToDatabase() {
        String password = "SuperSecret123!";
        String apiKey = "AIzaSyD1234567890abcdefghijk";
        // Use credentials...
    }
}


