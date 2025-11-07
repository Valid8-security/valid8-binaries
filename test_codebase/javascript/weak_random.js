function generateToken() {
    // CWE-338: Weak Random Number Generation
    return Math.random().toString(36);
}