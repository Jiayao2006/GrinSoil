// Password validation
const passwordInput = document.getElementById('signup-password');
const lengthCheck = document.getElementById('length-check');
const uppercaseCheck = document.getElementById('uppercase-check');
const numberCheck = document.getElementById('number-check');
const specialCheck = document.getElementById('special-check');
const submitButton = document.getElementById('signup-submit');

function validatePassword() {
    const password = passwordInput.value;
    const minLength = password.length >= 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecialChar = /[!@#$%^&*]/.test(password);

    // Update check marks
    lengthCheck.innerHTML = `${minLength ? '✅' : '❌'} Minimum 8 characters`;
    uppercaseCheck.innerHTML = `${hasUpperCase ? '✅' : '❌'} At least one uppercase letter`;
    numberCheck.innerHTML = `${hasNumber ? '✅' : '❌'} At least one number`;
    specialCheck.innerHTML = `${hasSpecialChar ? '✅' : '❌'} At least one special character (!@#$%^&*)`;

    // Check if all requirements are met
    const isValid = minLength && hasUpperCase && hasNumber && hasSpecialChar;

    if (isValid) {
        passwordInput.classList.add('is-valid');
        passwordInput.classList.remove('is-invalid');
    } else {
        passwordInput.classList.add('is-invalid');
        passwordInput.classList.remove('is-valid');
    }

    return isValid;
}

// Add event listener for password input
passwordInput.addEventListener('input', validatePassword);