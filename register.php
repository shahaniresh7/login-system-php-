<?php
include 'db.php';
session_start();

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
 
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
 
$errors = [];
$success = false;

if (isset($_POST['register'])) {
   
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = "Security validation failed. Please try again.";
    } else {
       
        $fullname = trim(htmlspecialchars($_POST['fullname'], ENT_QUOTES, 'UTF-8'));
        $username = trim(htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8'));
        $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
        $pass_raw = $_POST['password'];
        $cpassword = $_POST['cpassword'];
      
        if (empty($fullname) || empty($username) || empty($email) || empty($pass_raw)) {
            $errors[] = "All fields are required.";
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Invalid email format.";
        }
        
        if (strlen($pass_raw) < 8) {
            $errors[] = "Password must be at least 8 characters long.";
        }
        
        if (!preg_match('/[A-Z]/', $pass_raw) || !preg_match('/[a-z]/', $pass_raw) || !preg_match('/[0-9]/', $pass_raw)) {
            $errors[] = "Password must contain uppercase, lowercase letters and a number.";
        }
        
        if ($pass_raw !== $cpassword) {
            $errors[] = "Passwords do not match!";
        }
      
        if (empty($errors)) {
            $fullname = $conn->real_escape_string($fullname);
            $username = $conn->real_escape_string($username);
            $email = $conn->real_escape_string($email);
            
            $check_sql = "SELECT id FROM users WHERE username = '$username' OR email = '$email' LIMIT 1";
            $result = $conn->query($check_sql);
            
            if ($result && $result->num_rows > 0) {
                $errors[] = "Username or email already exists.";
            } else {
             
                $password = password_hash($pass_raw, PASSWORD_DEFAULT);
                
                $stmt = $conn->prepare("INSERT INTO users (fullname, username, email, password) VALUES (?, ?, ?, ?)");
                $stmt->bind_param("ssss", $fullname, $username, $email, $password);
                
                if ($stmt->execute()) {
                    $success = true;
                    
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                } else {
                    $errors[] = "Error: " . $conn->error;
                }
                $stmt->close();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Secure Registration</title>
  <link href='https://unpkg.com/boxicons@2.1.4/css/boxicons.min.css' rel='stylesheet'>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;700&display=swap');

    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
        font-family: "Poppins", serif;
    }

    body {
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      background: linear-gradient(to right, #ebc5c5, #a3b8fd);
      color: #333;
      padding: 20px;
    }

    .wrapper {
      position: relative;
      width: 100%;
      max-width: 400px;
      height: auto;
      background: rgba(255, 255, 255, 0);
      border: 2px solid rgba(255, 255, 255, 0.5);
      border-radius: 20px;
      backdrop-filter: blur(20px);
      box-shadow: 0 0 30px rgba(0, 0, 0, 0.2);
      display: flex;
      justify-content: center;
      align-items: center;
      overflow: hidden;
      opacity: 0;
      transform: scale(0.9);
      animation: fadeIn 0.5s forwards;
      padding: 20px;
    }

    @keyframes fadeIn {
      to {
        opacity: 1;
        transform: scale(1);
      }
    }

    .form-box {
      width: 100%;
      padding: 20px;
    }

    .icon-close {
      position: absolute;
      top: 0;
      right: 0;
      width: 45px;
      height: 45px;
      background: #162938;
      font-size: 2em;
      color: #fff;
      display: flex;
      justify-content: center;
      align-items: center;
      border-bottom-left-radius: 20px;
      cursor: pointer;
      z-index: 1;
    }

    .form-box h2 {
      font-size: 2em;
      color: #162938;
      text-align: center;
      margin-bottom: 20px;
    }

    .input-box {
      position: relative;
      width: 100%;
      height: 50px;
      border-bottom: 2px solid #162938;
      margin: 25px 0;
    }

    .input-box label {
      position: absolute;
      top: 50%;
      left: 5px;
      transform: translateY(-50%);
      font-size: 1em;
      color: #162938;
      font-weight: 500;
      pointer-events: none;
      transition: .5s;
    }

    .input-box input:focus ~ label,
    .input-box input:valid ~ label {
      top: -5px;
    }
      
    .input-box input {
      width: 100%;
      height: 100%;
      background: transparent;
      border: none;
      outline: none;
      font-size: 1em;
      color: #162938;
      font-weight: 600;
      padding: 0 35px 0 5px;
    }

    .input-box .icon {
      position: absolute;
      right: 8px;
      font-size: 1.2em;
      color: #162938;
      line-height: 57px;
    }

    .btn {
      width: 100%;
      height: 45px;
      background: #162938;
      border: none;
      outline: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 1em;
      color: #fff;
      font-weight: 500;
      transition: all 0.3s ease;
    }

    .btn:hover {
      background: #1e3447;
      transform: translateY(-2px);
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
    }

    .login-register {
      font-size: .9em;
      color: #162938;
      text-align: center;
      font-weight: 500;
      margin: 25px 0 10px;
    }

    .login-register p a {
      color: #162938;
      text-decoration: none;
      font-weight: 600;
      transition: all 0.3s ease;
    }

    .login-register p a:hover {
      text-decoration: underline;
      color: #2a4561;
    }

    .msg {
      text-align: center; 
      font-size: 14px; 
      padding: 10px;
      margin: 10px 0;
      border-radius: 5px;
      animation: slideIn 0.5s forwards;
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateY(-10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .error { 
      color: #721c24; 
      background-color: #f8d7da;
      border: 1px solid #f5c6cb;
    }

    .ok { 
      color: #155724; 
      background-color: #d4edda;
      border: 1px solid #c3e6cb;
    }

    .password-strength {
      margin-top: 5px;
      height: 5px;
      border-radius: 5px;
      background: #eee;
      overflow: hidden;
    }

    .password-strength-bar {
      height: 100%;
      border-radius: 5px;
      width: 0;
      transition: width 0.3s ease, background 0.3s ease;
    }

    .password-rules {
      font-size: 12px;
      color: #666;
      margin-bottom: 10px;
    }

    @media (max-width: 480px) {
      .wrapper {
        padding: 15px;
      }
      
      .form-box {
        padding: 10px;
      }
      
      .form-box h2 {
        font-size: 1.7em;
      }
    }
  </style>
</head>
<body>
<div class="wrapper">
  <div class="form-box register">
    <h2>Registration</h2>
    <form method="POST" autocomplete="off" id="registerForm">
      <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
      
      <div class="input-box">
        <input type="text" name="fullname" required>
        <label>Full Name</label>
        <i class='bx bxs-user icon'></i>
      </div>
      
      <div class="input-box">
        <input type="text" name="username" required>
        <label>Username</label>
        <i class='bx bxs-user-circle icon'></i>
      </div>
      
      <div class="input-box">
        <input type="email" name="email" required>
        <label>Email</label>
        <i class='bx bxs-envelope icon'></i>
      </div>
      
      <div class="input-box">
        <input type="password" name="password" id="password" required>
        <label>Password</label>
        <i class='bx bxs-lock-alt icon'></i>
        <div class="password-strength">
          <div class="password-strength-bar" id="passwordStrengthBar"></div>
        </div>
      </div>
      <div class="password-rules" id="passwordRules">
        Must be at least 8 characters with uppercase, lowercase, and number
      </div>
      
      <div class="input-box">
        <input type="password" name="cpassword" required>
        <label>Confirm Password</label>
        <i class='bx bxs-lock icon'></i>
      </div>
      
      <button type="submit" name="register" class="btn">Register</button>
      
      <div class="login-register">
        <p>Already have an account? <a href="login.php">Login</a></p>
      </div>
    </form>
    
    <?php
    if (!empty($errors)) {
        foreach ($errors as $error) {
            echo "<p class='msg error'>$error</p>";
        }
    }
    
    if ($success) {
        echo "<p class='msg ok'>Registration successful! <a href='login.php'>Login now</a></p>";
    }
    ?>
  </div>
</div>

<script>
function checkPasswordStrength() {
    const password = document.getElementById('password').value;
    const strengthBar = document.getElementById('passwordStrengthBar');
    let strength = 0;
    
    if (password.length >= 8) strength += 25;
    if (/[A-Z]/.test(password)) strength += 25;
    if (/[a-z]/.test(password)) strength += 25;
    if (/[0-9]/.test(password)) strength += 25;
    
    strengthBar.style.width = strength + '%';
    
    if (strength < 50) {
        strengthBar.style.backgroundColor = '#dc3545';
    } else if (strength < 100) {
        strengthBar.style.backgroundColor = '#ffc107';
    } else {
        strengthBar.style.backgroundColor = '#28a745';
    }
}

document.getElementById('password').addEventListener('input', checkPasswordStrength);

document.getElementById('registerForm').addEventListener('submit', function(e) {
    const password = document.getElementById('password').value;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    
    if (password.length < 8 || !hasUpperCase || !hasLowerCase || !hasNumber) {
        e.preventDefault();
        alert('Password must be at least 8 characters with uppercase, lowercase, and number');
    }
});

// Animate inputs on page load
document.addEventListener('DOMContentLoaded', function() {
    const inputs = document.querySelectorAll('.input-box');
    inputs.forEach((input, index) => {
        setTimeout(() => {
            input.style.opacity = '1';
            input.style.transform = 'translateY(0)';
        }, 100 * index);
    });
});
</script>
</body>
</html>