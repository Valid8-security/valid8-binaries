import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['path_traversal', 'command_injection', 'file_upload', 'idor', 'xxe', 'csrf', 'ssrf'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['path_traversal', 'command_injection', 'file_upload', 'idor', 'xxe', 'csrf', 'ssrf'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['path_traversal', 'command_injection', 'file_upload', 'idor', 'xxe', 'csrf', 'ssrf'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
