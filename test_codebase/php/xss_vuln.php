<?php
$search = $_GET['q'];
// CWE-79: Cross-Site Scripting
echo "<h1>Search: " . $search . "</h1>";
?>