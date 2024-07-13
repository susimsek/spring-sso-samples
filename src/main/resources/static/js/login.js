function togglePasswordVisibility() {
  const passwordField = document.getElementById("password");
  const type = passwordField.getAttribute("type") === "password" ? "text" : "password";
  passwordField.setAttribute("type", type);
  const showHideText = passwordField.nextElementSibling.querySelector('.input-group-text');
  showHideText.textContent = type === "password" ? "Show" : "Hide";
}
