import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['deserialization', 'hardcoded_credentials', 'weak_crypto', 'ssrf', 'file_upload', 'sql_injection', 'xxe'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['deserialization', 'hardcoded_credentials', 'weak_crypto', 'ssrf', 'file_upload', 'sql_injection', 'xxe'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['deserialization', 'hardcoded_credentials', 'weak_crypto', 'ssrf', 'file_upload', 'sql_injection', 'xxe'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
