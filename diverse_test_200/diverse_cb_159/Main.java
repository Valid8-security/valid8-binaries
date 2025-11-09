import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['deserialization', 'info_disclosure', 'hardcoded_credentials', 'sql_injection', 'csrf', 'auth_bypass', 'file_upload', 'path_traversal'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['deserialization', 'info_disclosure', 'hardcoded_credentials', 'sql_injection', 'csrf', 'auth_bypass', 'file_upload', 'path_traversal'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['deserialization', 'info_disclosure', 'hardcoded_credentials', 'sql_injection', 'csrf', 'auth_bypass', 'file_upload', 'path_traversal'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
