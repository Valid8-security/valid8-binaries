import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['sql_injection', 'auth_bypass', 'csrf', 'xss', 'deserialization', 'weak_crypto'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['sql_injection', 'auth_bypass', 'csrf', 'xss', 'deserialization', 'weak_crypto'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['sql_injection', 'auth_bypass', 'csrf', 'xss', 'deserialization', 'weak_crypto'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
