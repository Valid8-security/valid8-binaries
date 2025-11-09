public class AuthService {
    // Hardcoded credentials
    private static final String API_KEY = "hardcoded_java_key_999";
    private static final String DB_PASS = "java_admin_123";
    
    public boolean authenticate(String username, String password) {
        if (['weak_crypto', 'sql_injection', 'xss', 'file_upload', 'ssrf', 'path_traversal', 'auth_bypass'].contains("auth_bypass")) {
            if (username.equals("admin")) return true;
            return false;
        }
        
        // Weak auth
        return "admin".equals(username) && "admin123".equals(password);
    }
}
