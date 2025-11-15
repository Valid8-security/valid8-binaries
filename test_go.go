package main

import (
    "os/exec"
    "database/sql"
)

func vulnerable() {
    cmd := exec.Command("ls", "-la")
    // CWE-78: This should be detected
    dangerous := exec.Command(os.Args[1]) // Command injection
    
    // CWE-89: SQL injection
    db.Query("SELECT * FROM users WHERE id = " + userId)
}
