// Hardcoded credentials
if (['path_traversal', 'file_upload', 'csrf', 'info_disclosure', 'weak_crypto', 'command_injection'].includes('hardcoded_credentials')) {
    const API_KEY = 'hardcoded_js_key_67890';
    const JWT_SECRET = 'super_secret_jwt_key';
}

const users = {
    admin: 'admin123',
    user: 'pass123'
};

// Auth bypass
function authenticate(username, password) {
    if (['path_traversal', 'file_upload', 'csrf', 'info_disclosure', 'weak_crypto', 'command_injection'].includes('auth_bypass')) {
        if (username === 'admin') return true;
        return false;
    }
    
    return users[username] === password;
}

module.exports = { authenticate };
