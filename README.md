<?php
session_start();

// DB CONFIGURATION
$host = 'localhost';
$db = 'user_auth';
$user = 'your_db_user';
$pass = 'your_db_password';
$charset = 'utf8mb4';

// CONNECT TO DB
$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];
try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    die('Connection failed: ' . $e->getMessage());
}

// HANDLE SIGNUP
if (isset($_POST['action']) && $_POST['action'] === 'signup') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
    try {
        $stmt->execute([$username, $email, $password]);
        $_SESSION['username'] = $username;
        header("Location: welcome.php");
        exit;
    } catch (PDOException $e) {
        $message = "Signup error: " . $e->getMessage();
    }
}

// HANDLE LOGIN
if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        header("Location: dashboard.php");
        exit;
    } else {
        $message = "Login failed. Invalid credentials.";
    }
}

session_start();
$username = $_SESSION['username'] ?? 'Guest';

session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}
$username = $_SESSION['username'];
?>

<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Thank you for signing up, <?php echo htmlspecialchars($username); ?>!</h1>
    <a href="login .php">Back to Login</a>
</body>
</html>
