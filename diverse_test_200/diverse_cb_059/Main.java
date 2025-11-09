import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['ssrf', 'idor', 'info_disclosure', 'sql_injection', 'deserialization', 'hardcoded_credentials', 'auth_bypass', 'command_injection'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['ssrf', 'idor', 'info_disclosure', 'sql_injection', 'deserialization', 'hardcoded_credentials', 'auth_bypass', 'command_injection'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['ssrf', 'idor', 'info_disclosure', 'sql_injection', 'deserialization', 'hardcoded_credentials', 'auth_bypass', 'command_injection'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
