import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['deserialization', 'xss', 'path_traversal', 'hardcoded_credentials', 'csrf', 'command_injection', 'ssrf', 'xxe'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['deserialization', 'xss', 'path_traversal', 'hardcoded_credentials', 'csrf', 'command_injection', 'ssrf', 'xxe'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['deserialization', 'xss', 'path_traversal', 'hardcoded_credentials', 'csrf', 'command_injection', 'ssrf', 'xxe'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
