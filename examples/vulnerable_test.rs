// Rust test file with intentional vulnerabilities

use std::process::Command;
use std::fs::File;

// CWE-78: Command Injection
fn execute_command(user_input: &str) {
    let cmd = format!("ls -la {}", user_input);
    Command::new("sh").arg("-c").arg(&cmd).output();
}

// CWE-327: Weak Crypto
fn hash_password(password: &str) -> String {
    use md5::{Md5, Digest};
    let mut hasher = Md5::new();
    hasher.update(password);
    format!("{:x}", hasher.finalize())
}

// CWE-798: Hardcoded Credentials
fn connect_database() {
    let password = "MyPassword123";
    let api_key = "sk_test_1234567890";
    // Use credentials
}

// CWE-676: Unsafe code
fn unsafe_memory_operation() {
    unsafe {
        let mut x = 5;
        let raw = &mut x as *mut i32;
        *raw = 10;
    }
}

// CWE-22: Path Traversal
fn read_file(filename: String) {
    let path = format!("/var/www/{}", filename);
    File::open(path);
}


