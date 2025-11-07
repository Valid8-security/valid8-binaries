#!/usr/bin/env python3
"""
Setup Benchmark Codebases for Security Scanner Testing

Creates vulnerable applications commonly used for benchmarking security tools.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import requests
import zipfile
import tarfile

class BenchmarkSetup:
    def __init__(self):
        self.benchmark_dir = Path("/Users/sathvikkurapati/Downloads/parry-benchmarks")
        self.benchmark_dir.mkdir(exist_ok=True)

    def setup_all_benchmarks(self):
        """Setup all benchmark applications"""
        print("🚀 SETTING UP SECURITY SCANNER BENCHMARKS")
        print("=" * 60)

        benchmarks = [
            self.setup_juice_shop,
            self.setup_dvwa,
            self.setup_vulnerable_nodejs,
            self.setup_vulnerable_python,
            self.setup_heartbleed_demo,
            self.setup_rails_goat
        ]

        for i, setup_func in enumerate(benchmarks, 1):
            try:
                print(f"\n📦 [{i}/{len(benchmarks)}] Setting up {setup_func.__name__.replace('setup_', '').replace('_', ' ').title()}")
                setup_func()
                print("✅ Setup complete")
            except Exception as e:
                print(f"❌ Failed to setup: {e}")

        self.create_benchmark_summary()

    def setup_juice_shop(self):
        """OWASP Juice Shop - Node.js vulnerable web app"""
        juice_dir = self.benchmark_dir / "juice-shop"
        if juice_dir.exists():
            print("  Already exists, skipping...")
            return

        # Clone OWASP Juice Shop
        subprocess.run([
            "git", "clone", "--depth", "1",
            "https://github.com/juice-shop/juice-shop.git",
            str(juice_dir)
        ], check=True, capture_output=True)

        print("  📊 OWASP Juice Shop: Node.js e-commerce app with 100+ vulnerabilities")

    def setup_dvwa(self):
        """Damn Vulnerable Web Application - PHP vulnerable app"""
        dvwa_dir = self.benchmark_dir / "dvwa"
        if dvwa_dir.exists():
            print("  Already exists, skipping...")
            return

        # Clone DVWA
        subprocess.run([
            "git", "clone", "--depth", "1",
            "https://github.com/digininja/DVWA.git",
            str(dvwa_dir)
        ], check=True, capture_output=True)

        print("  📊 DVWA: PHP web app with common vulnerabilities")

    def setup_vulnerable_nodejs(self):
        """Vulnerable Node.js application"""
        node_dir = self.benchmark_dir / "vulnerable-nodejs"
        if node_dir.exists():
            print("  Already exists, skipping...")
            return

        # Create a vulnerable Node.js app
        node_dir.mkdir()

        # Package.json with vulnerable dependencies
        package_json = {
            "name": "vulnerable-nodejs-app",
            "version": "1.0.0",
            "dependencies": {
                "express": "4.17.1",
                "mongoose": "5.13.14",  # Vulnerable version
                "lodash": "4.17.20",    # Vulnerable version
                "axios": "0.21.1"       # Vulnerable version
            }
        }

        import json
        with open(node_dir / "package.json", "w") as f:
            json.dump(package_json, f, indent=2)

        # Create vulnerable server.js
        server_js = '''
const express = require('express');
const mongoose = require('mongoose');
const _ = require('lodash');
const axios = require('axios');

const app = express();
app.use(express.json());

// CWE-798: Hardcoded credentials
const DB_PASSWORD = "super_secret_password_123";

// CWE-89: SQL Injection (NoSQL)
app.get('/users/:id', async (req, res) => {
    const userId = req.params.id;
    // Dangerous: Direct user input in query
    const user = await mongoose.model('User').find({ id: userId });
    res.json(user);
});

// CWE-79: XSS vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;
    // Dangerous: Unescaped user input in HTML
    res.send(`<h1>Search results for: ${query}</h1>`);
});

// CWE-502: Unsafe deserialization
app.post('/import', (req, res) => {
    const data = req.body.data;
    // Dangerous: eval of user input
    const result = eval(data);
    res.json({ result });
});

// CWE-319: Cleartext transmission
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // Simulate authentication
    if (username === 'admin' && password === 'password') {
        res.json({ token: 'fake_jwt_token' });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.listen(3000, () => {
    console.log('Vulnerable Node.js app running on port 3000');
});
'''
        with open(node_dir / "server.js", "w") as f:
            f.write(server_js)

        print("  📊 Vulnerable Node.js: Express app with common vulnerabilities")

    def setup_vulnerable_python(self):
        """Vulnerable Python application"""
        python_dir = self.benchmark_dir / "vulnerable-python"
        if python_dir.exists():
            print("  Already exists, skipping...")
            return

        python_dir.mkdir()

        # Create vulnerable Flask app
        app_py = '''
from flask import Flask, request, jsonify
import pickle
import os
import subprocess

app = Flask(__name__)

# CWE-798: Hardcoded secret
SECRET_KEY = "hardcoded_secret_key_12345"

# CWE-79: XSS in template (simplified)
@app.route('/greet/<name>')
def greet(name):
    # Dangerous: Direct user input in HTML
    return f"<h1>Hello {name}!</h1>"

# CWE-89: SQL Injection
@app.route('/user/<int:user_id>')
def get_user(user_id):
    # Dangerous: String formatting with user input
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # Simulate query execution
    return jsonify({"query": query, "user_id": user_id})

# CWE-502: Unsafe pickle deserialization
@app.route('/load', methods=['POST'])
def load_data():
    data = request.get_data()
    # Dangerous: Unpickle user input
    try:
        result = pickle.loads(data)
        return jsonify({"loaded": str(result)})
    except Exception as e:
        return jsonify({"error": str(e)})

# CWE-78: Command injection
@app.route('/ping/<host>')
def ping_host(host):
    # Dangerous: User input in command
    result = subprocess.run(['ping', '-c', '1', host],
                          capture_output=True, text=True)
    return jsonify({"output": result.stdout})

# CWE-327: Weak cryptography
import hashlib
@app.route('/hash/<data>')
def weak_hash(data):
    # Dangerous: MD5 hash
    hashed = hashlib.md5(data.encode()).hexdigest()
    return jsonify({"hash": hashed, "algorithm": "MD5"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
'''
        with open(python_dir / "app.py", "w") as f:
            f.write(app_py)

        # Requirements.txt with vulnerable packages
        requirements = '''
Flask==2.0.1
requests==2.25.1
Django==3.1.0
'''
        with open(python_dir / "requirements.txt", "w") as f:
            f.write(requirements)

        print("  📊 Vulnerable Python: Flask app with common vulnerabilities")

    def setup_heartbleed_demo(self):
        """Heartbleed vulnerability demo"""
        heartbleed_dir = self.benchmark_dir / "heartbleed-demo"
        if heartbleed_dir.exists():
            print("  Already exists, skipping...")
            return

        heartbleed_dir.mkdir()

        # Create C code demonstrating Heartbleed-like vulnerability
        heartbleed_c = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// CWE-119: Buffer overflow (Heartbleed-like)
void process_request(char *request, int length) {
    char buffer[1024];

    // Dangerous: No bounds checking
    memcpy(buffer, request, length);

    printf("Processed request: %s\\n", buffer);
}

int main() {
    char *request = malloc(2048);

    // Simulate large input that overflows buffer
    memset(request, 'A', 2047);
    request[2047] = '\\0';

    process_request(request, 2048);  // Buffer overflow!

    free(request);
    return 0;
}
'''
        with open(heartbleed_dir / "heartbleed.c", "w") as f:
            f.write(heartbleed_c)

        print("  📊 Heartbleed Demo: C code with buffer overflow vulnerability")

    def setup_rails_goat(self):
        """Rails Goat - Ruby on Rails vulnerable app"""
        rails_dir = self.benchmark_dir / "rails-goat"
        if rails_dir.exists():
            print("  Already exists, skipping...")
            return

        # Clone Rails Goat
        subprocess.run([
            "git", "clone", "--depth", "1",
            "https://github.com/OWASP/railsgoat.git",
            str(rails_dir)
        ], check=True, capture_output=True)

        print("  📊 Rails Goat: Ruby on Rails app with common vulnerabilities")

    def create_benchmark_summary(self):
        """Create a summary of all benchmarks"""
        summary = f"""
# Security Scanner Benchmarks
# Created by Parry Setup Script

## Available Benchmarks:

1. **OWASP Juice Shop** ({self.benchmark_dir}/juice-shop)
   - Node.js e-commerce application
   - 100+ known vulnerabilities
   - Used by: Snyk, Semgrep, commercial scanners

2. **DVWA** ({self.benchmark_dir}/dvwa)
   - Damn Vulnerable Web Application
   - PHP application with common vulnerabilities
   - Used by: Most security scanners for testing

3. **Vulnerable Node.js** ({self.benchmark_dir}/vulnerable-nodejs)
   - Custom Node.js app with known vulnerabilities
   - Includes: XSS, SQLi, Deserialization, Command Injection
   - Package.json with vulnerable dependencies

4. **Vulnerable Python** ({self.benchmark_dir}/vulnerable-python)
   - Flask application with security issues
   - Includes: XSS, SQLi, Weak crypto, Command injection
   - Requirements.txt with vulnerable packages

5. **Heartbleed Demo** ({self.benchmark_dir}/heartbleed-demo)
   - C code demonstrating buffer overflow
   - Classic Heartbleed-style vulnerability

6. **Rails Goat** ({self.benchmark_dir}/rails-goat)
   - Ruby on Rails vulnerable application
   - Comprehensive Rails security issues

## Testing Commands:

# Test all benchmarks with Parry
for dir in juice-shop dvwa vulnerable-nodejs vulnerable-python heartbleed-demo rails-goat; do
    echo "Testing $dir..."
    parry scan {self.benchmark_dir}/$dir --mode hybrid --format json
done

# Compare with commercial tools
# Snyk: snyk test {self.benchmark_dir}/juice-shop
# Semgrep: semgrep --config auto {self.benchmark_dir}/juice-shop
"""

        with open(self.benchmark_dir / "README.md", "w") as f:
            f.write(summary)

        print(f"\n📋 Benchmark summary created: {self.benchmark_dir}/README.md")
        print(f"📊 Total benchmarks available: 6")
        print(f"📁 Location: {self.benchmark_dir}")

if __name__ == "__main__":
    setup = BenchmarkSetup()
    setup.setup_all_benchmarks()
