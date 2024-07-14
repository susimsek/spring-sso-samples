// Toggle password visibility
function togglePasswordVisibility() {
  const passwordField = document.getElementById("password");
  const toggleIcon = document.getElementById("toggleIcon");
  const type = passwordField.getAttribute("type") === "password" ? "text" : "password";
  passwordField.setAttribute("type", type);
  toggleIcon.classList.toggle("fa-eye");
  toggleIcon.classList.toggle("fa-eye-slash");
}

// Show loading spinner and disable submit button on form submit
function disableSubmitButton() {
  const submitButton = document.getElementById("submitButton");
  submitButton.disabled = true;
  submitButton.querySelector('.spinner-border').style.display = 'inline-block';
  submitButton.querySelector('.sr-only').style.display = 'inline-block';
}

document.getElementById('loginForm').addEventListener(
  'submit', disableSubmitButton);
