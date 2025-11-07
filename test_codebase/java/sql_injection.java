import java.sql.*;

public class DatabaseHelper {
    public ResultSet getUser(String username) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass");
        // CWE-89: SQL Injection
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }
}