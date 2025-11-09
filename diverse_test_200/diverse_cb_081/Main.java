import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['auth_bypass', 'file_upload', 'xxe', 'hardcoded_credentials'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['auth_bypass', 'file_upload', 'xxe', 'hardcoded_credentials'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['auth_bypass', 'file_upload', 'xxe', 'hardcoded_credentials'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
