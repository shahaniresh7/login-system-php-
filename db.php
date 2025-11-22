<?php
$servername = "localhost";
$username = "root"; // XAMPP / WAMP නම් root
$password = ""; // DB එකේ password තියෙනවා නම් එය දාන්න
$dbname = "user_system";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
