// Enhanced form validation
class FormValidator {
    constructor(formId) {
        this.form = document.getElementById(formId);
        if (!this.form) {
            console.error(`Form with ID "${formId}" not found!`);
            return;
        }
        
        this.submitButton = document.getElementById('signup-submit');
        if (!this.submitButton) {
            console.error('Submit button not found!');
            return;
        }
        
        this.isPhoneVerified = false;
        this.validationState = {
            username: false,
            password: false,
            phone: false,
            email: true, // Optional field starts as true
            role: false
        };
        
        console.log('FormValidator initialized with elements:', {
            form: this.form,
            submitButton: this.submitButton
        });
        
        this.init();
    }

    init() {
        // Initialize all field validators
        this.initUsernameValidation();
        this.initPasswordValidation();
        this.initPhoneValidation();
        this.initEmailValidation();
        this.initRoleValidation();
        this.initFormSubmission();
    }

    initUsernameValidation() {
        const usernameInput = document.getElementById('signup-username');

        usernameInput.addEventListener('input', () => {
            const username = usernameInput.value.trim();
            const isValid = this.validateUsername(username);
            this.validationState.username = isValid;
            this.updateSubmitButton();
        });
    }

    validateUsername(username) {
        // Username requirements:
        // - At least 3 characters
        // - Only alphanumeric characters and underscores
        // - Must start with a letter
        const usernameRegex = /^[a-zA-Z][a-zA-Z0-9_]{2,}$/;
        const isValid = usernameRegex.test(username);

        const input = document.getElementById('signup-username');
        const feedback = input.nextElementSibling;

        if (isValid) {
            input.classList.add('is-valid');
            input.classList.remove('is-invalid');
            feedback.textContent = 'Username is valid';
        } else {
            input.classList.add('is-invalid');
            input.classList.remove('is-valid');
            feedback.textContent = 'Username must start with a letter and contain only letters, numbers, and underscores';
        }

        return isValid;
    }

    initPasswordValidation() {
        const passwordInput = document.getElementById('signup-password');
        const lengthCheck = document.getElementById('length-check');
        const uppercaseCheck = document.getElementById('uppercase-check');
        const numberCheck = document.getElementById('number-check');
        const specialCheck = document.getElementById('special-check');

        passwordInput.addEventListener('input', () => {
            const isValid = this.validatePassword(passwordInput, {
                lengthCheck,
                uppercaseCheck,
                numberCheck,
                specialCheck
            });
            this.validationState.password = isValid;
            this.updateSubmitButton();
        });
    }

    validatePassword(input, checks) {
        const password = input.value;
        const minLength = password.length >= 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecialChar = /[!@#$%^&*]/.test(password);

        // Update check marks with animation
        checks.lengthCheck.innerHTML = `${minLength ? '✅' : '❌'} Minimum 8 characters`;
        checks.uppercaseCheck.innerHTML = `${hasUpperCase ? '✅' : '❌'} At least one uppercase letter`;
        checks.numberCheck.innerHTML = `${hasNumber ? '✅' : '❌'} At least one number`;
        checks.specialCheck.innerHTML = `${hasSpecialChar ? '✅' : '❌'} At least one special character (!@#$%^&*)`;

        const isValid = minLength && hasUpperCase && hasNumber && hasSpecialChar;

        if (isValid) {
            input.classList.add('is-valid');
            input.classList.remove('is-invalid');
        } else {
            input.classList.add('is-invalid');
            input.classList.remove('is-valid');
        }

        return isValid;
    }

    initPhoneValidation() {
        const phoneInput = document.getElementById('signup-phone');
        const countryCode = document.getElementById('country-code');
        const sendOtpBtn = document.getElementById('send-otp-btn');

        // Phone patterns by country code
        this.phonePatterns = {
            '+65': /^[689]\d{7}$/, // Singapore
            '+60': /^1\d{8,9}$/, // Malaysia
            '+62': /^[1-9]\d{8,11}$/, // Indonesia
            '+66': /^[689]\d{8}$/, // Thailand
            '+84': /^[3-9]\d{8}$/, // Vietnam
            '+63': /^[89]\d{9}$/ // Philippines
        };

        const validatePhone = () => {
            const isValid = this.validatePhoneNumber(phoneInput, countryCode, sendOtpBtn);
            this.validationState.phone = this.isPhoneVerified;
            this.updateSubmitButton();
        };

        phoneInput.addEventListener('input', validatePhone);
        countryCode.addEventListener('change', validatePhone);
    }

    validatePhoneNumber(phoneInput, countryCode, sendOtpBtn) {
        const selectedCode = countryCode.value;
        const phone = phoneInput.value.trim();

        if (!selectedCode || !phone) {
            sendOtpBtn.disabled = true;
            return false;
        }

        const pattern = this.phonePatterns[selectedCode];
        if (!pattern) {
            sendOtpBtn.disabled = true;
            return false;
        }

        const isValid = pattern.test(phone);

        if (isValid) {
            phoneInput.classList.add('is-valid');
            phoneInput.classList.remove('is-invalid');
            sendOtpBtn.disabled = false;
        } else {
            phoneInput.classList.add('is-invalid');
            phoneInput.classList.remove('is-valid');
            sendOtpBtn.disabled = true;
        }

        return isValid;
    }

    initEmailValidation() {
        const emailInput = document.getElementById('signup-email');

        emailInput.addEventListener('input', () => {
            const isValid = this.validateEmail(emailInput);
            this.validationState.email = isValid || !emailInput.value.trim();
            this.updateSubmitButton();
        });
    }

    // Update the validateEmail method in the FormValidator class
    validateEmail(input) {
        const email = input.value.trim();
        const emailFormatCheck = document.getElementById('email-format-check');
        const emailDomainCheck = document.getElementById('email-domain-check');
        const emailValidIcon = document.getElementById('email-valid-icon');
        const emailInvalidIcon = document.getElementById('email-invalid-icon');

        // If email is empty (optional field), consider it valid
        if (!email) {
            input.classList.remove('is-valid', 'is-invalid');
            emailValidIcon.classList.add('d-none');
            emailInvalidIcon.classList.add('d-none');
            emailFormatCheck.innerHTML = '❔ Valid email format (e.g., user@domain.com)';
            emailDomainCheck.innerHTML = '❔ Valid domain extension (.com, .net, etc.)';
            return true;
        }

        // Email format validation
        const formatRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const hasValidFormat = formatRegex.test(email);
        emailFormatCheck.innerHTML = `${hasValidFormat ? '✅' : '❌'} Valid email format`;

        // Domain validation
        const domainRegex = /\.[a-z]{2,}$/i;
        const hasValidDomain = domainRegex.test(email);
        emailDomainCheck.innerHTML = `${hasValidDomain ? '✅' : '❌'} Valid domain extension`;

        const isValid = hasValidFormat && hasValidDomain;

        // Update visual feedback
        if (isValid) {
            input.classList.add('is-valid');
            input.classList.remove('is-invalid');
            emailValidIcon.classList.remove('d-none');
            emailInvalidIcon.classList.add('d-none');
        } else {
            input.classList.add('is-invalid');
            input.classList.remove('is-valid');
            emailValidIcon.classList.add('d-none');
            emailInvalidIcon.classList.remove('d-none');
        }

        return isValid;
    }

    initRoleValidation() {
        const roleInputs = document.querySelectorAll('input[name="role"]');

        roleInputs.forEach(input => {
            input.addEventListener('change', () => {
                this.validationState.role = true;
                this.updateSubmitButton();
            });
        });
    }

    updateSubmitButton() {
        const isValid = Object.values(this.validationState).every(state => state === true);
        this.submitButton.disabled = !isValid;
        
        // Debug logging
        console.log('Validation State:', {
            ...this.validationState,
            isPhoneVerified: this.isPhoneVerified,
            allValid: isValid
        });
    }

    // Update the initFormSubmission method in the FormValidator class
    initFormSubmission() {
        this.form.addEventListener('submit', (event) => {
            event.preventDefault();

            // Final validation check before submission
            const isValid = Object.values(this.validationState).every(state => state === true);

            if (isValid && this.isPhoneVerified) {
                // Update hidden phone input before submission
                const fullPhone = document.getElementById('country-code').value +
                    document.getElementById('signup-phone').value;

                // Create hidden input if it doesn't exist
                let fullPhoneInput = document.querySelector('input[name="full_phone"]');
                if (!fullPhoneInput) {
                    fullPhoneInput = document.createElement('input');
                    fullPhoneInput.type = 'hidden';
                    fullPhoneInput.name = 'full_phone';
                    this.form.appendChild(fullPhoneInput);
                }
                fullPhoneInput.value = fullPhone;

                // Submit the form
                console.log('Form is valid, submitting...');
                event.preventDefault(); // Prevent default form submission
                this.form.submit(); // Explicitly submit the form
            } else {
                console.log('Form validation failed:', {
                    validationState: this.validationState,
                    isPhoneVerified: this.isPhoneVerified
                });
                alert('Please complete all required fields and verify your phone number.');
            }
        });
    }

    // Method to be called when OTP is verified
    verifyOTPSuccess() {
        this.isPhoneVerified = true;
        this.validationState.phone = true;
        this.updateSubmitButton();
    }

    // Method to be called when resending OTP
    resetOTPVerification() {
        this.isPhoneVerified = false;
        this.validationState.phone = false;
        this.updateSubmitButton();
    }
}

// Initialize form validation when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const formValidator = new FormValidator('signupForm');

    // Make the validator instance available globally for OTP handling
    window.formValidator = formValidator;

    // Update the window methods to use the validator instance
    window.verifyOTPSuccess = () => formValidator.verifyOTPSuccess();
    window.resetOTPVerification = () => formValidator.resetOTPVerification();
});