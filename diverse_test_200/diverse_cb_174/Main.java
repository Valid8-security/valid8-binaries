import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['xss', 'command_injection', 'ssrf', 'sql_injection', 'weak_crypto'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['xss', 'command_injection', 'ssrf', 'sql_injection', 'weak_crypto'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['xss', 'command_injection', 'ssrf', 'sql_injection', 'weak_crypto'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
