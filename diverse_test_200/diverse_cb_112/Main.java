import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['info_disclosure', 'deserialization', 'command_injection', 'weak_crypto', 'ssrf', 'xss'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['info_disclosure', 'deserialization', 'command_injection', 'weak_crypto', 'ssrf', 'xss'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['info_disclosure', 'deserialization', 'command_injection', 'weak_crypto', 'ssrf', 'xss'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
