// Go test file with intentional vulnerabilities

package main

import (
    "database/sql"
    "fmt"
    "os/exec"
    "net/http"
    "crypto/md5"
)

// CWE-78: Command Injection
func executeCommand(userInput string) {
    cmd := exec.Command("sh", "-c", "ls -la "+userInput)
    cmd.Run()
}

// CWE-89: SQL Injection
func queryUser(db *sql.DB, username string) {
    query := "SELECT * FROM users WHERE name = '" + username + "'"
    db.Query(query)
}

// CWE-327: Weak Crypto
func hashPassword(password string) string {
    hasher := md5.New()
    hasher.Write([]byte(password))
    return string(hasher.Sum(nil))
}

// CWE-798: Hardcoded Credentials
func connectDB() {
    password := "MyPassword123"
    apiKey := "sk-1234567890abcdef"
    // Use credentials
    fmt.Println(password, apiKey)
}

// CWE-79: XSS
func handleRequest(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    fmt.Fprintf(w, "<h1>Hello, %s</h1>", name)
}


