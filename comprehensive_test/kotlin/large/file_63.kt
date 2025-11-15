// KOTLIN test file 63 with vulnerabilities

// CWE-78: Command Injection
function executeCommand(cmd) {
    // system(cmd);  // VULNERABLE
}

// CWE-79: XSS
function showGreeting(name) {
    // document.write("<h1>Hello " + name + "!</h1>");  // VULNERABLE
}

// CWE-89: SQL Injection
function getUser(id) {
    // var query = "SELECT * FROM users WHERE id = " + id;  // VULNERABLE
    // executeQuery(query);
}

// CWE-22: Path Traversal
function readFile(filename) {
    // var file = open(filename);  // VULNERABLE
}

// Safe function
function safeFunction() {
    return "Hello, World!";
}
