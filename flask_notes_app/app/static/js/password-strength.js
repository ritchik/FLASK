document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    const confirmInput = document.getElementById('confirm_password');
    const strengthValue = document.getElementById('strength-value');
    const strengthText = document.getElementById('strength-text');
    const lengthReq = document.getElementById('length');
    const uppercaseReq = document.getElementById('uppercase');
    const lowercaseReq = document.getElementById('lowercase');
    const numberReq = document.getElementById('number');
    const specialReq = document.getElementById('special');
    const passwordMatch = document.getElementById('password-match');
    
    function checkPasswordStrength(password) {
        let strength = 0;
        let checks = {
            length: password.length >= 12,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password)
        };
        
         
        lengthReq.className = checks.length ? 'requirement-met' : 'requirement-unmet';
        uppercaseReq.className = checks.uppercase ? 'requirement-met' : 'requirement-unmet';
        lowercaseReq.className = checks.lowercase ? 'requirement-met' : 'requirement-unmet';
        numberReq.className = checks.number ? 'requirement-met' : 'requirement-unmet';
        specialReq.className = checks.special ? 'requirement-met' : 'requirement-unmet';
        
         
        strength += checks.length ? 20 : 0;
        strength += checks.uppercase ? 20 : 0;
        strength += checks.lowercase ? 20 : 0;
        strength += checks.number ? 20 : 0;
        strength += checks.special ? 20 : 0;
        
         
        strengthValue.style.width = strength + '%';
        
        if (strength === 0) {
            strengthValue.style.backgroundColor = '#ddd';
            strengthText.textContent = 'Kontrola siły hasła: Nie wprowadzono';
        } else if (strength < 40) {
            strengthValue.style.backgroundColor = '#dc3545'; // Red
            strengthText.textContent = 'Kontrola siły hasła: Słabe';
        } else if (strength < 80) {
            strengthValue.style.backgroundColor = '#ffc107'; // Yellow
            strengthText.textContent = 'Kontrola siły hasła: Średnie';
        } else {
            strengthValue.style.backgroundColor = '#28a745'; // Green
            strengthText.textContent = 'Kontrola siły hasła: Silne';
        }
        
        return strength;
    }
    
    function checkPasswordMatch() {
        if (confirmInput.value === '') {
            passwordMatch.textContent = '';
            return;
        }
        
        if (passwordInput.value === confirmInput.value) {
            passwordMatch.textContent = 'Hasła się zgadzają ✓';
            passwordMatch.style.color = '#28a745';
        } else {
            passwordMatch.textContent = 'Hasła nie są identyczne ✗';
            passwordMatch.style.color = '#dc3545';
        }
    }
    
    passwordInput.addEventListener('input', function() {
        checkPasswordStrength(this.value);
    });
    
    confirmInput.addEventListener('input', checkPasswordMatch);
    passwordInput.addEventListener('input', checkPasswordMatch);
});