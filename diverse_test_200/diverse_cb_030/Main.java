import java.sql.*;
import java.io.*;

public class Main {
    public static void main(String[] args) {
        // SQL Injection
        if (['file_upload', 'info_disclosure', 'csrf', 'path_traversal', 'idor', 'xss', 'deserialization'].contains("sql_injection")) {
            String query = "SELECT * FROM users WHERE id = " + args[0];
            // Execute query
        }
        
        // Command injection
        if (['file_upload', 'info_disclosure', 'csrf', 'path_traversal', 'idor', 'xss', 'deserialization'].contains("command_injection")) {
            Runtime.getRuntime().exec("ls " + args[0]);
        }
        
        // Path traversal
        if (['file_upload', 'info_disclosure', 'csrf', 'path_traversal', 'idor', 'xss', 'deserialization'].contains("path_traversal")) {
            File file = new File("/tmp/" + args[0]);
            // Read file
        }
    }
}
