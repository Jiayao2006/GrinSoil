// Enhanced form validation
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
        
        this.isEmailVerified = false;
        this.validationState = {
            username: false,
            password: false,
            email: false,
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
        this.initEmailValidation();
        this.initPhoneValidation(); // Now optional
        this.initRoleValidation();
        this.initFormSubmission();
    }

    initUsernameValidation() {
        const usernameInput = document.getElementById('signup-username');
        if (!usernameInput) {
            console.error('Username input element not found!');
            return;
        }

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
        if (!input) return false;
        
        const feedback = input.nextElementSibling;

        if (isValid) {
            input.classList.add('is-valid');
            input.classList.remove('is-invalid');
            if (feedback) feedback.textContent = 'Username is valid';
        } else {
            input.classList.add('is-invalid');
            input.classList.remove('is-valid');
            if (feedback) feedback.textContent = 'Username must start with a letter and contain only letters, numbers, and underscores';
        }

        return isValid;
    }

    initPasswordValidation() {
        const passwordInput = document.getElementById('signup-password');
        if (!passwordInput) {
            console.error('Password input element not found!');
            return;
        }
        
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
        if (!input) return false;
        
        const password = input.value;
        const minLength = password.length >= 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecialChar = /[!@#$%^&*]/.test(password);

        // Update check marks if elements exist
        if (checks.lengthCheck) 
            checks.lengthCheck.innerHTML = `${minLength ? '✅' : '❌'} Minimum 8 characters`;
        if (checks.uppercaseCheck)
            checks.uppercaseCheck.innerHTML = `${hasUpperCase ? '✅' : '❌'} At least one uppercase letter`;
        if (checks.numberCheck)
            checks.numberCheck.innerHTML = `${hasNumber ? '✅' : '❌'} At least one number`;
        if (checks.specialCheck)
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

    // Now phone validation is optional
    initPhoneValidation() {
        const phoneInput = document.getElementById('signup-phone');
        if (!phoneInput) {
            console.warn('Phone input element not found or not required');
            return;
        }
        
        // Phone is now optional, so we don't update validation state from here
        phoneInput.addEventListener('input', () => {
            this.validatePhoneNumber(phoneInput);
            // No validation state update since it's optional
        });
    }

    validatePhoneNumber(phoneInput) {
        if (!phoneInput) return true; // Phone is optional
        
        const phone = phoneInput.value.trim();
        // If empty, it's valid (since it's optional)
        if (!phone) {
            phoneInput.classList.remove('is-valid', 'is-invalid');
            return true;
        }
        
        // If not empty, validate format
        const phoneRegex = /^\d{8,12}$/;
        const isValid = phoneRegex.test(phone);

        if (isValid) {
            phoneInput.classList.add('is-valid');
            phoneInput.classList.remove('is-invalid');
        } else {
            phoneInput.classList.add('is-invalid');
            phoneInput.classList.remove('is-valid');
        }

        return isValid;
    }

    initEmailValidation() {
        const emailInput = document.getElementById('signup-email');
        if (!emailInput) {
            console.error('Email input element not found!');
            return;
        }

        emailInput.addEventListener('input', () => {
            const isValid = this.validateEmail(emailInput);
            this.validationState.email = isValid && this.isEmailVerified;
            this.updateSubmitButton();
            
            // Enable/disable verification button based on email validity
            const verifyBtn = document.getElementById('send-otp-btn');
            if (verifyBtn) {
                verifyBtn.disabled = !isValid;
            }
        });
    }

    validateEmail(input) {
        if (!input) return false;
        
        const email = input.value.trim();
        const emailFormatCheck = document.getElementById('email-format-check');
        const emailDomainCheck = document.getElementById('email-domain-check');
        
        // If email is empty, it's invalid (required field)
        if (!email) {
            input.classList.add('is-invalid');
            input.classList.remove('is-valid');
            return false;
        }

        // Email format validation
        const formatRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const hasValidFormat = formatRegex.test(email);
        if (emailFormatCheck) {
            emailFormatCheck.innerHTML = `${hasValidFormat ? '✅' : '❌'} Valid email format`;
        }

        // Domain validation
        const domainRegex = /\.[a-z]{2,}$/i;
        const hasValidDomain = domainRegex.test(email);
        if (emailDomainCheck) {
            emailDomainCheck.innerHTML = `${hasValidDomain ? '✅' : '❌'} Valid domain extension`;
        }

        const isValid = hasValidFormat && hasValidDomain;

        // Update visual feedback
        if (isValid) {
            input.classList.add('is-valid');
            input.classList.remove('is-invalid');
        } else {
            input.classList.add('is-invalid');
            input.classList.remove('is-valid');
        }

        return isValid;
    }

    initRoleValidation() {
        const roleInputs = document.querySelectorAll('input[name="role"]');
        if (!roleInputs || roleInputs.length === 0) {
            console.error('Role input elements not found!');
            return;
        }

        roleInputs.forEach(input => {
            input.addEventListener('change', () => {
                this.validationState.role = true;
                this.updateSubmitButton();
            });
        });
    }

    updateSubmitButton() {
        const isValid = Object.values(this.validationState).every(state => state === true);
        if (this.submitButton) {
            this.submitButton.disabled = !isValid;
        }
        
        // Debug logging
        console.log('Validation State:', {
            ...this.validationState,
            isEmailVerified: this.isEmailVerified,
            allValid: isValid
        });
    }

    initFormSubmission() {
        if (!this.form) return;
        
        this.form.addEventListener('submit', (event) => {
            event.preventDefault();

            // Final validation check before submission
            const isValid = Object.values(this.validationState).every(state => state === true);

            if (isValid && this.isEmailVerified) {
                // Get validated email
                const emailInput = document.getElementById('signup-email');
                const verifiedEmailInput = document.getElementById('verified_email');
                
                if (emailInput && verifiedEmailInput) {
                    verifiedEmailInput.value = emailInput.value.trim();
                }
                
                // Optional: Handle phone number if provided
                const countryCode = document.getElementById('country-code');
                const phoneInput = document.getElementById('signup-phone');
                if (countryCode && phoneInput && countryCode.value && phoneInput.value) {
                    const fullPhone = countryCode.value + phoneInput.value;
                    
                    // Create hidden input if it doesn't exist
                    let fullPhoneInput = document.querySelector('input[name="full_phone"]');
                    if (!fullPhoneInput) {
                        fullPhoneInput = document.createElement('input');
                        fullPhoneInput.type = 'hidden';
                        fullPhoneInput.name = 'full_phone';
                        this.form.appendChild(fullPhoneInput);
                    }
                    fullPhoneInput.value = fullPhone;
                }

                // Submit the form
                console.log('Form is valid, submitting...');
                this.form.submit();
            } else {
                console.log('Form validation failed:', {
                    validationState: this.validationState,
                    isEmailVerified: this.isEmailVerified
                });
                
                if (!this.isEmailVerified) {
                    alert('Please verify your email address before submitting.');
                } else {
                    alert('Please complete all required fields correctly.');
                }
            }
        });
    }

    // Method to be called when OTP is verified
    verifyOTPSuccess() {
        this.isEmailVerified = true;
        this.validationState.email = true;
        this.updateSubmitButton();
    }

    // Method to be called when resending OTP
    resetOTPVerification() {
        this.isEmailVerified = false;
        this.validationState.email = false;
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