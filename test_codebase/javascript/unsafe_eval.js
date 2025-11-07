function executeCode(code) {
    // CWE-95: Eval Injection
    eval(code);
}