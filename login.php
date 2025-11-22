<?php 
include 'db.php'; 
session_start();

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");

$error = '';

if (isset($_POST['login'])) {
    
    $user = trim($conn->real_escape_string($_POST['username']));
    $password = $_POST['password'];

    if (empty($user) || empty($password)) {
        $error = "Please enter both username and password.";
    } else {
         
        $sql = "SELECT * FROM users WHERE username=? OR email=? LIMIT 1";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $user, $user);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result && $result->num_rows > 0) {
            $row = $result->fetch_assoc();
            if (password_verify($password, $row['password'])) {
                 
                session_regenerate_id(true);
                
                $_SESSION['user_id'] = $row['id'];
                $_SESSION['username'] = $row['username'];
                $_SESSION['logged_in'] = true;
                
                 
                header("Location: ../frontend/home.php");
                exit();
            } else {
                $error = "Invalid password!";
            }
        } else {
            $error = "No user found with that username or email!";
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login</title>
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
      cursor: pointer;
    }

    .remember-forgot {
      font-size: .9em;
      color: #162938;
      font-weight: 500;
      margin: -15px 0 15px;
      display: flex;
      justify-content: space-between;
    }

    .remember-forgot label {
      display: flex;
      align-items: center;
    }

    .remember-forgot label input {
      accent-color: #162938;
      margin-right: 5px;
    }

    .remember-forgot a {
      color: #162938;
      text-decoration: none;
      transition: all 0.3s ease;
    }

    .remember-forgot a:hover {
      text-decoration: underline;
      color: #2a4561;
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
      
      .remember-forgot {
        flex-direction: column;
        gap: 10px;
        align-items: flex-start;
      }
    }
  </style>
</head>
<body>
<div class="wrapper">
  <div class="form-box login">
    <h2>Login</h2>
    <form method="POST" autocomplete="off" id="loginForm">
      <div class="input-box">
        <input type="text" name="username" required>
        <label>Username or Email</label>
        <i class='bx bxs-user icon'></i>
      </div>
      
      <div class="input-box">
        <input type="password" name="password" id="password" required>
        <label>Password</label>
        <i class='bx bx-hide show-hide icon' id="togglePassword"></i>
      </div>
      
      <div class="remember-forgot">
        <label>
          <input type="checkbox" name="remember"> Remember me
        </label>
        <a href="forgot.php">Forgot Password?</a>
      </div>
      
      <button type="submit" name="login" class="btn">Login</button>
      
      <div class="login-register">
        <p>Don't have an account? <a href="register.php">Register</a></p>
      </div>
    </form>
    
    <?php
    if (!empty($error)) {
        echo "<p class='msg error'>$error</p>";
    }
    ?>
  </div>
</div>

<script>
 
document.getElementById('togglePassword').addEventListener('click', function() {
    const passwordInput = document.getElementById('password');
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
   
    this.classList.toggle('bx-hide');
    this.classList.toggle('bx-show');
});
 
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