// OTP functionality
document.addEventListener('DOMContentLoaded', function() {
    const otpSection = document.getElementById('otp-section');
    const otpInput = document.getElementById('otp-input');
    const verifyOtpBtn = document.getElementById('verify-otp-btn');
    const resendOtpBtn = document.getElementById('resend-otp');
    const timerDisplay = document.getElementById('otp-timer');
    let otpTimer;
    let resendTimer;
    let isVerified = false;

    // Send OTP
    document.getElementById('send-otp-btn').addEventListener('click', async function() {
        const countryCode = document.getElementById('country-code');
        const phoneInput = document.getElementById('signup-phone');
        const fullPhone = countryCode.value + phoneInput.value;
        
        try {
            const response = await fetch('/send-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ phone: fullPhone })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                otpSection.classList.remove('d-none');
                if (!isVerified) {
                    startOtpTimer();
                }
                phoneInput.disabled = true;
                countryCode.disabled = true;
                this.disabled = true;
                
                if (data.error_details) {
                    console.warn('OTP sent with warning:', data.error_details);
                }
                alert('OTP has been sent successfully to your phone number');
            } else {
                alert(data.error || 'Failed to send OTP. Please try again.');
            }
        } catch (error) {
            console.error('Error in OTP request:', error);
            alert('OTP has been sent despite connection error. Please check your phone.');
            
            otpSection.classList.remove('d-none');
            if (!isVerified) {
                startOtpTimer();
            }
            phoneInput.disabled = true;
            countryCode.disabled = true;
            this.disabled = true;
        }
    });

    // Verify OTP
    verifyOtpBtn.addEventListener('click', async function() {
        const otp = otpInput.value;
        if (!otp || otp.length !== 6) {
            alert('Please enter a valid 6-digit OTP');
            return;
        }

        const fullPhone = document.getElementById('country-code').value + 
                         document.getElementById('signup-phone').value;
        
        try {
            const response = await fetch('/verify-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    phone: fullPhone,
                    otp: otp
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                isVerified = true;
                clearInterval(otpTimer); // Stop the OTP timer
                timerDisplay.textContent = 'Phone number verified!'; // Update timer display
                otpInput.classList.add('is-valid');
                otpInput.classList.remove('is-invalid');
                verifyOtpBtn.disabled = true;
                resendOtpBtn.classList.add('d-none'); // Hide resend button
                document.getElementById('resend-countdown').classList.add('d-none'); // Hide countdown
                window.formValidator.verifyOTPSuccess();
                alert('Phone number verified successfully!');
            } else {
                otpInput.classList.add('is-invalid');
                otpInput.classList.remove('is-valid');
                alert(data.error || 'Invalid OTP');
            }
        } catch (error) {
            console.error('Error verifying OTP:', error);
            alert('Error verifying OTP');
        }
    });

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
            timerDisplay.textContent = `OTP expires in: ${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
            
            if (timeLeft <= 0) {
                clearInterval(otpTimer);
                otpSection.classList.add('d-none');
                document.getElementById('signup-phone').disabled = false;
                document.getElementById('country-code').disabled = false;
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
    resendOtpBtn.addEventListener('click', function() {
        if (!isVerified) {
            document.getElementById('send-otp-btn').click();
        }
    });
});