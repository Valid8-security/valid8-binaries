fn read_file(filename: &str) -> String {
    // CWE-22: Path Traversal (simplified example)
    std::fs::read_to_string(filename).unwrap()
}

fn weak_hash(password: &str) -> String {
    // CWE-327: Weak Cryptography
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    password.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}