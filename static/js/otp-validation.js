// OTP functionality
document.addEventListener('DOMContentLoaded', function() {
    const otpSection = document.getElementById('otp-section');
    const otpInput = document.getElementById('otp-input');
    const verifyOtpBtn = document.getElementById('verify-otp-btn');
    const resendOtpBtn = document.getElementById('resend-otp');
    const timerDisplay = document.getElementById('otp-timer');
    const sendOtpBtn = document.getElementById('send-otp-btn');
    let otpTimer;
    let resendTimer;
    let isVerified = false;

    // Send OTP via Email
    if (sendOtpBtn) {
        sendOtpBtn.addEventListener('click', async function() {
            const emailInput = document.getElementById('signup-email');
            const email = emailInput.value.trim();
            
            // More robust email validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$/;
            
            if (!email) {
                alert('Please enter an email address');
                return;
            }
            
            if (!emailRegex.test(email)) {
                alert('Please enter a valid email address (e.g., user@example.com)');
                return;
            }
            
            // Disable button and show loading state
            this.disabled = true;
            const originalHTML = this.innerHTML;
            this.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Sending...';
            
            try {
                const response = await fetch('/send-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: email })
                });
                
                const data = await response.json();
                
                // Always restore button state
                this.disabled = false;
                this.innerHTML = originalHTML;
                
                if (data.status === 'success') {
                    otpSection.classList.remove('d-none');
                    if (!isVerified) {
                        startOtpTimer();
                    }
                    emailInput.disabled = true;
                    this.disabled = true;
                    
                    alert('Verification code has been sent to your email');
                } else {
                    // More specific error handling
                    const errorMessage = data.message || 'Failed to send verification code';
                    console.error('OTP Send Error:', errorMessage);
                    alert(errorMessage);
                }
            } catch (error) {
                console.error('Network or server error:', error);
                this.disabled = false;
                this.innerHTML = originalHTML;
                
                // More user-friendly error message
                const errorMessage = error.message || 'Network error. Please check your connection.';
                alert(`Failed to send verification code: ${errorMessage}`);
            }
        });
    }

    // Verify OTP
    if (verifyOtpBtn) {
        verifyOtpBtn.addEventListener('click', async function() {
            const otp = otpInput.value;
            if (!otp || otp.length !== 6) {
                alert('Please enter a valid 6-digit verification code');
                return;
            }
            
            const email = document.getElementById('signup-email').value.trim();
            this.disabled = true;
            this.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Verifying...';
            
            try {
                const response = await fetch('/verify-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        email: email,
                        otp: otp
                    })
                });
                
                const data = await response.json();
                
                this.disabled = false;
                this.innerHTML = '<i class="fas fa-check-circle me-2"></i>Verify';
                
                if (response.ok) {
                    isVerified = true;
                    clearInterval(otpTimer);
                    timerDisplay.textContent = 'Email verified!';
                    timerDisplay.className = 'text-success fw-bold';
                    otpInput.classList.add('is-valid');
                    otpInput.classList.remove('is-invalid');
                    verifyOtpBtn.disabled = true;
                    resendOtpBtn.classList.add('d-none');
                    document.getElementById('resend-countdown')?.classList.add('d-none');
                    
                    // Add verified email to hidden input
                    const verifiedEmailInput = document.getElementById('verified_email');
                    if (verifiedEmailInput) {
                        verifiedEmailInput.value = email;
                    }
                    
                    window.formValidator.verifyOTPSuccess();
                    alert('Email verified successfully!');
                } else {
                    otpInput.classList.add('is-invalid');
                    otpInput.classList.remove('is-valid');
                    alert(data.error || 'Invalid verification code');
                }
            } catch (error) {
                console.error('Error verifying code:', error);
                this.disabled = false;
                this.innerHTML = '<i class="fas fa-check-circle me-2"></i>Verify';
                alert('Error verifying code. Please try again.');
            }
        });
    }

    // Timer functions
    function startOtpTimer() {
        if (isVerified) return; // Don't start timer if already verified

        let timeLeft = 180; // 3 minutes
        
        clearInterval(otpTimer);
        otpTimer = setInterval(() => {
            if (isVerified) {
                clearInterval(otpTimer);
                return;
            }

            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            timerDisplay.textContent = `Code expires in: ${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
            
            if (timeLeft <= 0) {
                clearInterval(otpTimer);
                otpSection.classList.add('d-none');
                document.getElementById('signup-email').disabled = false;
                document.getElementById('send-otp-btn').disabled = false;
                window.formValidator.resetOTPVerification();
            }
            timeLeft--;
        }, 1000);

        // Start resend cooldown
        startResendCooldown();
    }

    function startResendCooldown() {
        if (isVerified) return; // Don't start cooldown if already verified

        let cooldown = 30; // 30 seconds cooldown
        const resendBtn = document.getElementById('resend-otp');
        const countdownDisplay = document.getElementById('resend-countdown');
        
        if (!resendBtn || !countdownDisplay) return;
        
        resendBtn.classList.add('d-none');
        countdownDisplay.classList.remove('d-none');
        
        clearInterval(resendTimer);
        resendTimer = setInterval(() => {
            if (isVerified) {
                clearInterval(resendTimer);
                resendBtn.classList.add('d-none');
                countdownDisplay.classList.add('d-none');
                return;
            }

            countdownDisplay.textContent = `Resend in ${cooldown}s`;
            
            if (cooldown <= 0) {
                clearInterval(resendTimer);
                resendBtn.classList.remove('d-none');
                countdownDisplay.classList.add('d-none');
            }
            cooldown--;
        }, 1000);
    }

    // Resend OTP
    if (resendOtpBtn) {
        resendOtpBtn.addEventListener('click', function(e) {
            e.preventDefault();
            if (!isVerified) {
                const sendBtn = document.getElementById('send-otp-btn');
                if (sendBtn) {
                    sendBtn.click();
                }
            }
        });
    }
});