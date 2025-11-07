public class Test {
    // CWE-89: SQL injection
    public void query(String userId) {
        String sql = "SELECT * FROM users WHERE id = " + userId;
        stmt.executeQuery(sql); // Vulnerable
    }
}