import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['info_disclosure', 'auth_bypass', 'hardcoded_credentials', 'ssrf', 'xxe', 'xss'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['info_disclosure', 'auth_bypass', 'hardcoded_credentials', 'ssrf', 'xxe', 'xss'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['info_disclosure', 'auth_bypass', 'hardcoded_credentials', 'ssrf', 'xxe', 'xss'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
