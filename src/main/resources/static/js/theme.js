function toggleTheme() {
  const themeSwitch = document.getElementById("themeSwitch");
  themeSwitch.checked = !themeSwitch.checked; // Toggle the checked state

  if (themeSwitch.checked) {
    document.body.classList.add("dark-mode");
  } else {
    document.body.classList.remove("dark-mode");
  }
}
