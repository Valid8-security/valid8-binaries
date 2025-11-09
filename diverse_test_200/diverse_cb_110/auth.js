// Hardcoded credentials
if (['deserialization', 'ssrf', 'sql_injection', 'weak_crypto', 'csrf', 'idor', 'hardcoded_credentials', 'info_disclosure'].includes('hardcoded_credentials')) {
    const API_KEY = 'hardcoded_js_key_67890';
    const JWT_SECRET = 'super_secret_jwt_key';
}

const users = {
    admin: 'admin123',
    user: 'pass123'
};

// Auth bypass
function authenticate(username, password) {
    if (['deserialization', 'ssrf', 'sql_injection', 'weak_crypto', 'csrf', 'idor', 'hardcoded_credentials', 'info_disclosure'].includes('auth_bypass')) {
        if (username === 'admin') return true;
        return false;
    }
    
    return users[username] === password;
}

module.exports = { authenticate };
