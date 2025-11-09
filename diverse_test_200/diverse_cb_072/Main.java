import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['sql_injection', 'xxe', 'info_disclosure', 'xss', 'csrf'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['sql_injection', 'xxe', 'info_disclosure', 'xss', 'csrf'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['sql_injection', 'xxe', 'info_disclosure', 'xss', 'csrf'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
