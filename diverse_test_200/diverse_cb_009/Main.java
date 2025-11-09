import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['xss', 'path_traversal', 'xxe', 'command_injection', 'sql_injection', 'auth_bypass'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['xss', 'path_traversal', 'xxe', 'command_injection', 'sql_injection', 'auth_bypass'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['xss', 'path_traversal', 'xxe', 'command_injection', 'sql_injection', 'auth_bypass'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
