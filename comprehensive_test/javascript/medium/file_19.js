// JavaScript test file 19 with vulnerabilities

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();
app.use(express.json());

// CWE-78: Command Injection
app.post('/execute', (req, res) => {
    const cmd = req.body.cmd || 'ls';
    exec(cmd, (error, stdout, stderr) => {  // VULNERABLE
        if (error) {
            res.status(500).send(error.message);
            return;
        }
        res.send(stdout);
    });
});

// CWE-79: XSS
app.get('/greet', (req, res) => {
    const name = req.query.name || 'World';
    const html = `<h1>Hello ${name}!</h1>`;  // VULNERABLE
    res.send(html);
});

// CWE-89: SQL Injection
app.get('/users', (req, res) => {
    const userId = req.query.id;
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'test'
    });

    const query = `SELECT * FROM users WHERE id = ${userId}`;  // VULNERABLE
    connection.query(query, (error, results) => {
        if (error) throw error;
        res.json(results);
        connection.end();
    });
});

// CWE-22: Path Traversal
app.get('/readfile', (req, res) => {
    const filename = req.query.file || 'default.txt';
    fs.readFile(filename, 'utf8', (err, data) => {  // VULNERABLE
        if (err) {
            res.status(500).send('Error');
            return;
        }
        res.send(data);
    });
});

app.listen(3000, () => {
    console.log('Server running');
});
