// Email validation
const emailInput = document.getElementById('signup-email');
const emailFormatCheck = document.getElementById('email-format-check');
const emailDomainCheck = document.getElementById('email-domain-check');
const emailValidIcon = document.getElementById('email-valid-icon');
const emailInvalidIcon = document.getElementById('email-invalid-icon');

function validateEmail() {
    const email = emailInput.value.trim();
    
    // If email is empty (since it's optional), remove all validation states
    if (!email) {
        emailInput.classList.remove('is-valid', 'is-invalid');
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

    // Overall validation
    const isValid = hasValidFormat && hasValidDomain;

    // Update UI
    if (isValid) {
        emailInput.classList.add('is-valid');
        emailInput.classList.remove('is-invalid');
        emailValidIcon.classList.remove('d-none');
        emailInvalidIcon.classList.add('d-none');
    } else {
        emailInput.classList.add('is-invalid');
        emailInput.classList.remove('is-valid');
        emailValidIcon.classList.add('d-none');
        emailInvalidIcon.classList.remove('d-none');
    }

    return isValid;
}

// Add event listener for email input
emailInput.addEventListener('input', validateEmail);

// Function to show tooltip with validation message
function showEmailTooltip(message) {
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = message;
    
    // Position the tooltip
    const rect = emailInput.getBoundingClientRect();
    tooltip.style.top = `${rect.bottom + 5}px`;
    tooltip.style.left = `${rect.left}px`;
    
    document.body.appendChild(tooltip);
    setTimeout(() => tooltip.remove(), 3000); // Remove after 3 seconds
}

// Add helpful tooltips on focus
emailInput.addEventListener('focus', () => {
    if (!emailInput.value) {
        showEmailTooltip('Optional: Enter a valid email address');
    }
});