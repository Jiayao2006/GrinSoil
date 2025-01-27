// Form validation
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('signupForm');
    const submitButton = document.getElementById('signup-submit');
    let isPhoneVerified = false;

    // Function to check if all required fields are valid
    function validateForm() {
        const username = document.getElementById('signup-username').value.trim();
        const password = document.getElementById('signup-password').value;
        const phone = document.getElementById('signup-phone').value.trim();
        const countryCode = document.getElementById('country-code').value;
        const role = document.querySelector('input[name="role"]:checked');
        const email = document.getElementById('signup-email').value.trim();

        // Debug log
        console.log('Validating form:', {
            username: !!username,
            password: !!password,
            phone: !!phone,
            countryCode: !!countryCode,
            role: !!role,
            isPhoneVerified: isPhoneVerified
        });

        // Check required fields
        if (!username || !password || !phone || !countryCode || !role) {
            console.log('Missing required fields');
            return false;
        }

        // Check password requirements
        const passwordValid = validatePassword();
        if (!passwordValid) {
            console.log('Password validation failed');
            return false;
        }

        // Check phone verification
        if (!isPhoneVerified) {
            console.log('Phone not verified');
            return false;
        }

        // Check email if provided
        if (email && !validateEmail()) {
            console.log('Email validation failed');
            return false;
        }

        console.log('Form validation passed');
        return true;
    }

    // Prevent form submission if validation fails
    form.addEventListener('submit', function(event) {
        event.preventDefault(); // Always prevent default first
        
        const isValid = validateForm();
        console.log('Form submission attempt - Valid:', isValid);
        
        if (isValid) {
            console.log('Submitting form');
            form.submit();
        } else {
            alert('Please fill in all required fields and complete phone verification.');
        }
    });

    // Update submit button state when form changes
    form.addEventListener('change', function() {
        submitButton.disabled = !validateForm();
    });

    // Add input event listeners to update submit button state
    form.querySelectorAll('input, select').forEach(input => {
        input.addEventListener('input', function() {
            submitButton.disabled = !validateForm();
        });
    });

    // Update phone verification status
    window.verifyOTPSuccess = function() {
        console.log('OTP verified successfully');
        isPhoneVerified = true;
        submitButton.disabled = !validateForm();
    };

    // Reset phone verification status when sending new OTP
    window.resetOTPVerification = function() {
        console.log('Resetting OTP verification');
        isPhoneVerified = false;
        submitButton.disabled = true;
    };
});