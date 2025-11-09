import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['weak_crypto', 'sql_injection', 'xss', 'file_upload', 'ssrf', 'path_traversal', 'auth_bypass'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['weak_crypto', 'sql_injection', 'xss', 'file_upload', 'ssrf', 'path_traversal', 'auth_bypass'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['weak_crypto', 'sql_injection', 'xss', 'file_upload', 'ssrf', 'path_traversal', 'auth_bypass'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
