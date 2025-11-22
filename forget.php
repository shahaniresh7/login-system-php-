<?php 
include 'db.php'; 
session_start();
 
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
 
$errors = [];
$success = false;

if (isset($_POST['reset'])) {
  
    $user = trim($conn->real_escape_string($_POST['username']));
    $newpass = $_POST['newpass'];
    $cpass = $_POST['cpass'];
 
    if (empty($user) || empty($newpass) || empty($cpass)) {
        $errors[] = "All fields are required.";
    }
    
    if ($newpass !== $cpass) {
        $errors[] = "Passwords do not match!";
    }
    
    if (strlen($newpass) < 8) {
        $errors[] = "Password must be at least 8 characters long.";
    }
    
    if (!preg_match('/[A-Z]/', $newpass) || !preg_match('/[a-z]/', $newpass) || !preg_match('/[0-9]/', $newpass)) {
        $errors[] = "Password must contain uppercase, lowercase letters and a number.";
    }
    
    if (empty($errors)) {
       
        $check = $conn->query("SELECT * FROM users WHERE username='$user' OR email='$user'");
        if ($check && $check->num_rows > 0) {
          
            $hash = password_hash($newpass, PASSWORD_DEFAULT);
 
            $stmt = $conn->prepare("UPDATE users SET password=? WHERE username=? OR email=?");
            $stmt->bind_param("sss", $hash, $user, $user);
            
            if ($stmt->execute()) {
                $success = true;
            } else {
                $errors[] = "Error updating password!";
            }
            $stmt->close();
        } else {
            $errors[] = "User not found!";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Reset Password</title>
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
      max-width: 450px;
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
      padding: 25px;
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
      color: #161838ff;
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
      cursor: pointer;
    }

    .btn {
      width: 100%;
      height: 45px;
      background: #e67e22;
      border: none;
      outline: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 1em;
      color: #fff;
      font-weight: 500;
      transition: all 0.3s ease;
      margin-top: 10px;
    }

    .btn:hover {
      background: #d35400;
      transform: translateY(-2px);
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
    }

    .login-link {
      font-size: .9em;
      color: #162938;
      text-align: center;
      font-weight: 500;
      margin: 25px 0 10px;
    }

    .login-link a {
      color: #162938;
      text-decoration: none;
      font-weight: 600;
      transition: all 0.3s ease;
    }

    .login-link a:hover {
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
  <div class="form-box">
    <h2>Reset Password</h2>
    <form method="POST" autocomplete="off" id="resetForm">
      <div class="input-box">
        <input type="text" name="username" required>
        <label>Username or Email</label>
        <i class='bx bxs-user icon'></i>
      </div>
      
      <div class="input-box">
        <input type="password" name="newpass" id="newpass" required>
        <label>New Password</label>
        <i class='bx bx-hide show-hide icon' id="toggleNewPassword"></i>
        <div class="password-strength">
          <div class="password-strength-bar" id="passwordStrengthBar"></div>
        </div>
      </div>
      <div class="password-rules" id="passwordRules">
        Must be at least 8 characters with uppercase, lowercase, and number
      </div>
      
      <div class="input-box">
        <input type="password" name="cpass" id="cpass" required>
        <label>Confirm Password</label>
        <i class='bx bx-hide show-hide icon' id="toggleConfirmPassword"></i>
      </div>
      
      <button type="submit" name="reset" class="btn">Reset Password</button>
      
      <div class="login-link">
        <a href="login.php">Back to Login</a>
      </div>
    </form>
    
    <?php
    if (!empty($errors)) {
        foreach ($errors as $error) {
            echo "<p class='msg error'>$error</p>";
        }
    }
    
    if ($success) {
        echo "<p class='msg ok'>Password updated successfully! <a href='login.php'>Login now</a></p>";
    }
    ?>
  </div>
</div>

<script>
// Toggle password visibility
document.getElementById('toggleNewPassword').addEventListener('click', function() {
    const passwordInput = document.getElementById('newpass');
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    
    // Toggle eye icon
    this.classList.toggle('bx-hide');
    this.classList.toggle('bx-show');
});

document.getElementById('toggleConfirmPassword').addEventListener('click', function() {
    const passwordInput = document.getElementById('cpass');
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    
    // Toggle eye icon
    this.classList.toggle('bx-hide');
    this.classList.toggle('bx-show');
});

// Password strength meter
function checkPasswordStrength() {
    const password = document.getElementById('newpass').value;
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

document.getElementById('newpass').addEventListener('input', checkPasswordStrength);

// Form validation
document.getElementById('resetForm').addEventListener('submit', function(e) {
    const password = document.getElementById('newpass').value;
    const confirmPassword = document.getElementById('cpass').value;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    
    if (password.length < 8 || !hasUpperCase || !hasLowerCase || !hasNumber) {
        e.preventDefault();
        alert('Password must be at least 8 characters with uppercase, lowercase, and number');
        return false;
    }
    
    if (password !== confirmPassword) {
        e.preventDefault();
        alert('Passwords do not match!');
        return false;
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