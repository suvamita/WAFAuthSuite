<?php
session_start();

// Change this to your connection info.
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'root';
$DATABASE_PASS = '';
$DATABASE_NAME = 'wafauthsuite';

// Establish database connection
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);

// Check the connection
if (!$con) {
    die('Database connection failed: ' . mysqli_connect_error());
}

// Function to check Boolean, Error, Union based SqlInjection
function checkSqlInjection($username, $password, $con) {
    // Check for SQL injection delimiters in username
    $delimiters = [";", "--", "'", '"', "`", "/*", "*/", "="];
    foreach ($delimiters as $delimiter) {
        if (strpos($username, $delimiter) !== false || strpos($password, $delimiter) !== false) {
            // Detected SQL Injection attempt
            echo '<script>alert("SQL Injection attempt!"); window.location.href = "login.html";</script>';
            return false; // Return false to indicate the SQL injection attempt
        }
    }

    $sql_keywords = ["AND", "OR", "NOT", "and", "or", "not","SELECT","select","union","UNION"];
    foreach ($sql_keywords as $keyword) {
        if (stripos($username, $keyword) !== false || stripos($password, $keyword) !== false) {
            // Log or handle the detection of SQL keyword in the username or password
            echo '<script>alert("SQL Injection attempt!"); window.location.href = "login.html";</script>';
            return false;
        }
    }

// Generating query and verifying credientials
    $query = "SELECT id, username, email, password FROM accounts WHERE username = ?";
    
    $stmt = mysqli_prepare($con, $query);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, 's', $username);

        if (mysqli_stmt_execute($stmt)) {
            mysqli_stmt_store_result($stmt);

            if (mysqli_stmt_num_rows($stmt) > 0) {
                mysqli_stmt_bind_result($stmt, $userID, $dbUsername, $dbEmail, $dbPassword);
                mysqli_stmt_fetch($stmt);

                if (password_verify($password, $dbPassword)) {
                    $_SESSION['username'] = $dbUsername;
                    $_SESSION['email'] = $dbEmail;

                    mysqli_stmt_close($stmt);
                    return true;
                } else {
                    mysqli_stmt_close($stmt);
                    return false;
                }
            }
        }

        mysqli_stmt_close($stmt);
    }
    return false;
}
// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'], $_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    if (checkSqlInjection($username, $password, $con)) {
        // Password is correct
        // Redirect or perform further actions
        
    } else {
        // Incorrect password or other error
        echo '<script>alert("Incorrect password or username!"); window.location.href = "login.html";</script>';
    }
}

// Close the database connection
mysqli_close($con);
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Profile Page</title>
    <link href="style.css" rel="stylesheet" type="text/css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css"
        integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A=="
        crossorigin="anonymous" referrerpolicy="no-referrer">
</head>

<body class="loggedin">
    <nav class="navtop">
        <div>
            <h1>Website Title</h1>
            <a href="logout.php"><i class="fas fa-sign-out-alt"></i>Logout</a>
        </div>
    </nav>
    <div class="content">
        <h2>Profile Page</h2>
        <div>
            <p>Your account details are below:</p>
            <table>
                <tr>
                    <td>Username:</td>
                    <td><?php echo isset($_SESSION['username']) ? $_SESSION['username'] : 'Not available'; ?></td>
                </tr>
                <tr>
                    <td>Email:</td>
                    <td><?php echo isset($_SESSION['email']) ? $_SESSION['email'] : 'Not available'; ?></td>
                </tr>
            </table>
        </div>
    </div>
</body>
</html>