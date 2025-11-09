public class AuthService {
    // Hardcoded credentials
    private static final String API_KEY = "hardcoded_java_key_999";
    private static final String DB_PASS = "java_admin_123";
    
    public boolean authenticate(String username, String password) {
        if (['xss', 'info_disclosure', 'deserialization', 'weak_crypto', 'auth_bypass'].contains("auth_bypass")) {
            if (username.equals("admin")) return true;
            return false;
        }
        
        // Weak auth
        return "admin".equals(username) && "admin123".equals(password);
    }
}
