/**
 * Example vulnerable JavaScript code for testing Parry scanner
 * This file contains intentional security vulnerabilities for demonstration
 */

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();

// CWE-798: Hardcoded Credentials
const DB_PASSWORD = 'mySecretPassword123';
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';

// CWE-89: SQL Injection
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: DB_PASSWORD
    });
    
    // Vulnerable: String concatenation in SQL query
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (error, results) => {
        res.json(results);
    });
});

// CWE-79: Cross-Site Scripting (XSS)
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    // Vulnerable: Directly inserting user input into HTML
    document.getElementById('results').innerHTML = `Results for: ${searchTerm}`;
});

// CWE-78: OS Command Injection
app.get('/execute', (req, res) => {
    const command = req.query.cmd;
    // Vulnerable: Executing user input as shell command
    exec(`ls ${command}`, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// CWE-22: Path Traversal
app.get('/file', (req, res) => {
    const filename = req.query.name;
    // Vulnerable: No path validation
    fs.readFile(filename, 'utf8', (err, data) => {
        res.send(data);
    });
});

// CWE-918: Server-Side Request Forgery (SSRF)
app.get('/proxy', (req, res) => {
    const url = req.query.url;
    // Vulnerable: No URL validation
    fetch(url)
        .then(response => response.text())
        .then(data => res.send(data));
});

// CWE-327: Weak Cryptographic Algorithm
const crypto = require('crypto');
function hashPassword(password) {
    // Vulnerable: Using MD5 for passwords
    return crypto.createHash('md5').update(password).digest('hex');
}

app.listen(3000, () => {
    console.log('Server running on port 3000');
});


