package main

import (
    "crypto/md5"
    "fmt"
)

func hashPassword(password string) string {
    // CWE-327: Weak Cryptography
    hash := md5.Sum([]byte(password))
    return fmt.Sprintf("%x", hash)
}