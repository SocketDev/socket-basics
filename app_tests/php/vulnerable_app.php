<?php
// Vulnerable PHP application for testing

if ($_POST['username']) {
    $username = $_POST['username'];
    
    // SQL injection vulnerability
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    mysql_query($query);
    
    // Command injection vulnerability
    $command = "ls -la " . $_GET['dir'];
    exec($command);
    
    // XSS vulnerability
    echo "<div>Hello " . $_POST['name'] . "</div>";
    
    // File inclusion vulnerability
    include($_GET['page'] . '.php');
    
    // Hardcoded password
    $db_password = "admin123";
    
    // Weak random
    $session_id = rand();
    
    // Directory traversal
    $filename = $_GET['file'];
    readfile("/uploads/" . $filename);
    
    // Eval vulnerability
    eval($_POST['code']);
    
    // Unvalidated redirect
    header('Location: ' . $_GET['redirect']);
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable App</title>
</head>
<body>
    <form method="post">
        <input type="text" name="username" placeholder="Username">
        <input type="text" name="name" placeholder="Name">
        <textarea name="code" placeholder="PHP Code"></textarea>
        <input type="submit" value="Submit">
    </form>
</body>
</html>
