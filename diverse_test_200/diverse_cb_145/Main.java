import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['weak_crypto', 'idor', 'sql_injection', 'hardcoded_credentials', 'info_disclosure', 'xxe'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['weak_crypto', 'idor', 'sql_injection', 'hardcoded_credentials', 'info_disclosure', 'xxe'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['weak_crypto', 'idor', 'sql_injection', 'hardcoded_credentials', 'info_disclosure', 'xxe'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
