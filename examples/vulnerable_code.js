// Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
/**
 * Example vulnerable JavaScript code for testing Parry scanner
 * This file contains intentional security vulnerabilities for demonstration purposes
 * to validate that the Parry scanner can detect common web application security flaws
 */

// Import the Express web framework for creating HTTP server routes
const express = require('express');
// Import the MySQL database driver for connecting to MySQL databases
const mysql = require('mysql');
// Import the exec function from child_process module to execute shell commands
const { exec } = require('child_process');
// Import the file system module for reading and writing files
const fs = require('fs');

// Create a new Express application instance that will handle HTTP requests
const app = express();

// CWE-798: Hardcoded Credentials vulnerability
// This is a security flaw where sensitive credentials are stored directly in the source code
// Define a hardcoded database password that should never be in source code
const DB_PASSWORD = 'mySecretPassword123';
// Define a hardcoded AWS access key which poses a severe security risk if exposed
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';

// CWE-89: SQL Injection vulnerability demonstration
// Define a GET route that retrieves user information by ID from the database
app.get('/user/:id', (req, res) => {
    // Extract the user ID parameter from the URL path
    const userId = req.params.id;
    // Create a new MySQL database connection with hardcoded credentials
    const connection = mysql.createConnection({
        host: 'localhost',  // Database server hostname
        user: 'root',       // Database username
        password: DB_PASSWORD  // Using the hardcoded password (security issue)
    });
    
    // Vulnerable: String concatenation in SQL query allows SQL injection attacks
    // An attacker could pass "1 OR 1=1" to retrieve all users
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    // Execute the vulnerable SQL query against the database
    connection.query(query, (error, results) => {
        // Send the query results back to the client as JSON
        res.json(results);
    });
});

// CWE-79: Cross-Site Scripting (XSS) vulnerability demonstration
// Define a GET route that handles search functionality
app.get('/search', (req, res) => {
    // Extract the search term from the query string parameters
    const searchTerm = req.query.q;
    // Vulnerable: Directly inserting user input into HTML without sanitization
    // An attacker could inject malicious JavaScript code through the search parameter
    document.getElementById('results').innerHTML = `Results for: ${searchTerm}`;
});

// CWE-78: OS Command Injection vulnerability demonstration
// Define a GET route that executes system commands
app.get('/execute', (req, res) => {
    // Extract the command parameter from the query string
    const command = req.query.cmd;
    // Vulnerable: Executing user input as a shell command without validation
    // An attacker could pass "; rm -rf /" to delete files or execute arbitrary code
    exec(`ls ${command}`, (error, stdout, stderr) => {
        // Send the command output back to the client
        res.send(stdout);
    });
});

// CWE-22: Path Traversal vulnerability demonstration
// Define a GET route that serves files from the filesystem
app.get('/file', (req, res) => {
    // Extract the filename parameter from the query string
    const filename = req.query.name;
    // Vulnerable: No path validation or sanitization
    // An attacker could use "../../../etc/passwd" to read sensitive system files
    fs.readFile(filename, 'utf8', (err, data) => {
        // Send the file contents back to the client
        res.send(data);
    });
});

// CWE-918: Server-Side Request Forgery (SSRF) vulnerability demonstration
// Define a GET route that acts as a proxy to fetch external URLs
app.get('/proxy', (req, res) => {
    // Extract the target URL from the query string parameters
    const url = req.query.url;
    // Vulnerable: No URL validation or whitelist checking
    // An attacker could access internal services like "http://localhost:8080/admin"
    fetch(url)
        // Parse the response as text
        .then(response => response.text())
        // Send the fetched content back to the client
        .then(data => res.send(data));
});

// CWE-327: Weak Cryptographic Algorithm vulnerability demonstration
// Import the Node.js crypto module for cryptographic operations
const crypto = require('crypto');
// Define a function to hash passwords using a weak algorithm
function hashPassword(password) {
    // Vulnerable: Using MD5 for passwords which is cryptographically broken
    // MD5 is fast to compute and vulnerable to rainbow table attacks
    // Should use bcrypt, scrypt, or Argon2 instead for password hashing
    return crypto.createHash('md5').update(password).digest('hex');
}

// Start the Express HTTP server on port 3000
app.listen(3000, () => {
    // Log a message to the console indicating the server is running
    console.log('Server running on port 3000');
});


