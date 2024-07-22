// Toggle password visibility
function togglePasswordVisibility() {
  const passwordField = document.getElementById("password");
  const toggleIcon = document.getElementById("toggleIcon");
  const isPassword = passwordField.getAttribute("type") === "password";
  passwordField.setAttribute("type", isPassword ? "text" : "password");
  toggleIcon.classList.toggle("fa-eye");
  toggleIcon.classList.toggle("fa-eye-slash");
}

// Show loading spinner and disable submit button on form submit
function disableSubmitButton(event) {
  const submitButton = document.getElementById("submitButton");
  submitButton.disabled = true;
  submitButton.querySelector('.spinner-border').style.display = 'inline-block';
  submitButton.querySelector('.sr-only').style.display = 'inline-block';
}

document.getElementById('loginForm').addEventListener('submit', disableSubmitButton);
