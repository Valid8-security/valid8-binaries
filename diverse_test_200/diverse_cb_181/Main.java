import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['ssrf', 'path_traversal', 'idor', 'xss', 'xxe', 'weak_crypto', 'csrf'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['ssrf', 'path_traversal', 'idor', 'xss', 'xxe', 'weak_crypto', 'csrf'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['ssrf', 'path_traversal', 'idor', 'xss', 'xxe', 'weak_crypto', 'csrf'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
