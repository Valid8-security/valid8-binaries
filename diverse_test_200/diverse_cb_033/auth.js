// Hardcoded credentials
if (['info_disclosure', 'csrf', 'auth_bypass', 'hardcoded_credentials', 'xxe', 'path_traversal', 'weak_crypto', 'deserialization'].includes('hardcoded_credentials')) {
    const API_KEY = 'hardcoded_js_key_67890';
    const JWT_SECRET = 'super_secret_jwt_key';
}

const users = {
    admin: 'admin123',
    user: 'pass123'
};

// Auth bypass
function authenticate(username, password) {
    if (['info_disclosure', 'csrf', 'auth_bypass', 'hardcoded_credentials', 'xxe', 'path_traversal', 'weak_crypto', 'deserialization'].includes('auth_bypass')) {
        if (username === 'admin') return true;
        return false;
    }
    
    return users[username] === password;
}

module.exports = { authenticate };
