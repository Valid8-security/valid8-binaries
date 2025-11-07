function updateContent(data) {
    // CWE-79: XSS via innerHTML
    document.getElementById('content').innerHTML = data;
}