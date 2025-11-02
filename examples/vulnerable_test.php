<?php
// PHP test file with intentional vulnerabilities

// CWE-78: Command Injection
function executeCommand($userInput) {
    shell_exec("ls -la " . $userInput);
}

// CWE-89: SQL Injection
function queryUser($username) {
    $conn = mysqli_connect("localhost", "user", "pass", "db");
    $query = "SELECT * FROM users WHERE name = '" . $_GET['username'] . "'";
    mysqli_query($conn, $query);
}

// CWE-79: XSS
function displayGreeting() {
    echo "Hello, " . $_GET['name'];
}

// CWE-22: Path Traversal
function readFile() {
    $filename = $_GET['file'];
    $content = file_get_contents("/var/www/" . $filename);
    echo $content;
}

// CWE-327: Weak Crypto
function hashPassword($password) {
    return md5($password);
}

// CWE-798: Hardcoded Credentials
$password = "admin123";
$apiKey = "pk_live_1234567890abcdef";

// CWE-502: Unsafe Deserialization
function deserializeData() {
    $data = unserialize($_POST['data']);
    return $data;
}
?>


