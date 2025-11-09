import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['deserialization', 'weak_crypto', 'xxe', 'hardcoded_credentials', 'file_upload'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['deserialization', 'weak_crypto', 'xxe', 'hardcoded_credentials', 'file_upload'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['deserialization', 'weak_crypto', 'xxe', 'hardcoded_credentials', 'file_upload'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
