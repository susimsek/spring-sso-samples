function toggleTheme() {
  const themeSwitch = document.getElementById("themeSwitch");
  themeSwitch.checked = !themeSwitch.checked; // Toggle the checked state

  if (themeSwitch.checked) {
    document.body.classList.add("dark-mode");
    localStorage.setItem("theme", "dark");
  } else {
    document.body.classList.remove("dark-mode");
    localStorage.setItem("theme", "light");
  }
}

function applySavedTheme() {
  const savedTheme = localStorage.getItem("theme");
  const themeSwitch = document.getElementById("themeSwitch");

  if (savedTheme === "dark") {
    document.body.classList.add("dark-mode");
    themeSwitch.checked = true;
  } else {
    document.body.classList.remove("dark-mode");
    themeSwitch.checked = false;
  }
}

// Apply the saved theme on page load
document.addEventListener("DOMContentLoaded", applySavedTheme);
