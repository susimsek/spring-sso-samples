// Disable the submit button and show a spinner when the form is submitted
function disableSubmitButton() {
  const submitButton = document.getElementById('submitConsent');
  submitButton.disabled = true;
  submitButton.querySelector('.spinner-border').style.display = 'inline-block';
  submitButton.querySelector('.sr-only').style.display = 'inline-block';
}

// Function to handle the cancel button click event
function cancelConsent() {
  const consentForm = document.getElementById('consentForm');
  consentForm.reset();
  consentForm.submit();
}

// Attach the disableSubmitButton function to the form submit event
document.addEventListener('DOMContentLoaded', function () {
  const consentForm = document.getElementById('consentForm');
  consentForm.addEventListener('submit', disableSubmitButton);
});
