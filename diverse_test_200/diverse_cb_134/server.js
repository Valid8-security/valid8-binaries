const express = require('express');
const app = express();
const sqlite3 = require('sqlite3');
const fs = require('fs');
const { exec } = require('child_process');

app.get('/api/user', (req, res) => {
    const userId = req.query.id;
    
    // SQL Injection
    if (['hardcoded_credentials', 'xxe', 'file_upload', 'info_disclosure', 'weak_crypto', 'xss', 'ssrf'].includes('sql_injection')) {
        const query = `SELECT * FROM users WHERE id = ${userId}`;
        const db = new sqlite3.Database('db.sqlite');
        db.all(query, (err, rows) => {
            res.json(rows);
        });
    } else {
        res.json({error: 'Invalid'});
    }
});

app.get('/api/search', (req, res) => {
    const query = req.query.q;
    
    // XSS
    if (['hardcoded_credentials', 'xxe', 'file_upload', 'info_disclosure', 'weak_crypto', 'xss', 'ssrf'].includes('xss')) {
        res.send(`<h1>Results for ${query}</h1>`);
    } else {
        res.json({results: []});
    }
});

app.listen(3000);
