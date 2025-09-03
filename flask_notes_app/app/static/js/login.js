// @ts-nocheck
document.addEventListener('DOMContentLoaded', function() {
    const countdownElement = document.getElementById('countdown');
    const loginBtn = document.getElementById('login-btn');
    const lockoutMessage = document.querySelector('.lockout-message');

    if (!countdownElement) return; // brak blokady

    const endTime = countdownElement.dataset.lock * 1000;

    function updateCountdown() {
        const now = new Date().getTime();
        const timeLeft = Math.max(0, Math.ceil((endTime - now) / 1000));
        countdownElement.textContent = timeLeft;

        if (timeLeft <= 0) {
            // Enable login button
            loginBtn.disabled = false;
            loginBtn.style.backgroundColor = '#4CAF50';
            loginBtn.style.cursor = 'pointer';
            
            // Hide the entire lockout message
            if (lockoutMessage) {
                lockoutMessage.style.display = 'none';
            }
            
            // Show success message
            const successDiv = document.createElement('div');
            successDiv.className = 'flash-message';
            successDiv.style.backgroundColor = '#d4edda';
            successDiv.style.color = '#155724';
            successDiv.style.border = '1px solid #c3e6cb';
            successDiv.style.padding = '10px';
            successDiv.style.margin = '10px 0';
            successDiv.style.borderRadius = '4px';
            successDiv.style.textAlign = 'center';
            successDiv.textContent = 'Account unlocked! You can now try logging in again.';
            
            // Insert success message before the form
            const form = document.querySelector('form');
            form.parentNode.insertBefore(successDiv, form);
            
            // Auto-hide success message after 3 seconds
            setTimeout(() => {
                if (successDiv && successDiv.parentNode) {
                    successDiv.parentNode.removeChild(successDiv);
                }
            }, 3000);
            
            clearInterval(interval);
        }
    }

    updateCountdown();
    const interval = setInterval(updateCountdown, 1000);

    // Prevent form submission while locked
    document.querySelector('form').addEventListener('submit', function(e) {
        if (parseInt(countdownElement.textContent) > 0) {
            e.preventDefault();
        }
    });
});