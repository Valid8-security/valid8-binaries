import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['xss', 'auth_bypass', 'file_upload', 'csrf', 'hardcoded_credentials', 'command_injection', 'ssrf', 'path_traversal'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['xss', 'auth_bypass', 'file_upload', 'csrf', 'hardcoded_credentials', 'command_injection', 'ssrf', 'path_traversal'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['xss', 'auth_bypass', 'file_upload', 'csrf', 'hardcoded_credentials', 'command_injection', 'ssrf', 'path_traversal'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
