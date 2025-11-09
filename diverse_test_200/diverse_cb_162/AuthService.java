public class AuthService {
    // Hardcoded credentials
    private static final String API_KEY = "hardcoded_java_key_999";
    private static final String DB_PASS = "java_admin_123";
    
    public boolean authenticate(String username, String password) {
        if (['xss', 'auth_bypass', 'file_upload', 'csrf', 'hardcoded_credentials', 'command_injection', 'ssrf', 'path_traversal'].contains("auth_bypass")) {
            if (username.equals("admin")) return true;
            return false;
        }
        
        // Weak auth
        return "admin".equals(username) && "admin123".equals(password);
    }
}
