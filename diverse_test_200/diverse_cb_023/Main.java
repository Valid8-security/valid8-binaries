import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['hardcoded_credentials', 'command_injection', 'idor', 'sql_injection', 'csrf', 'deserialization', 'auth_bypass', 'weak_crypto'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['hardcoded_credentials', 'command_injection', 'idor', 'sql_injection', 'csrf', 'deserialization', 'auth_bypass', 'weak_crypto'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['hardcoded_credentials', 'command_injection', 'idor', 'sql_injection', 'csrf', 'deserialization', 'auth_bypass', 'weak_crypto'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
