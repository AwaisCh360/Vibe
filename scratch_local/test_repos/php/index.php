<?php
$secret = "my_db_password_123";
$id = $_GET['id'];
$conn = new mysqli("localhost", "user", $secret, "db");
$conn->query("SELECT * FROM users WHERE id = " . $id); // SQLi
echo "Hello " . $_GET['name']; // XSS
?>