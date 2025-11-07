package main

import (
    "database/sql"
    "fmt"
)

func getUser(db *sql.DB, username string) (*sql.Row, error) {
    // CWE-89: SQL Injection
    query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
    return db.QueryRow(query), nil
}