<?php
function getUser($username) {
    $conn = mysqli_connect("localhost", "user", "pass", "db");
    // CWE-89: SQL Injection
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    return mysqli_query($conn, $query);
}
?>