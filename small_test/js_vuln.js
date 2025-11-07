// CWE-79: DOM XSS
function updateUI(data) {
    const userData = data.userInput;
    document.getElementById('result').innerHTML = userData; // XSS vulnerability
    
    // CWE-95: Eval injection
    const code = data.codeSnippet;
    eval(code); // Dangerous
}