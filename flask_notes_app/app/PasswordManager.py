import re
import time
import secrets
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from zxcvbn import zxcvbn  # Biblioteka do oceny siły hasła
import time
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.DEBUG)

class PasswordManager:
    @staticmethod
    def validate_password_strength(password, username=None, email=None):
        """
        Ocenia siłę hasła z uwzględnieniem dodatkowych parametrów
        
        Args:
            password (str): Hasło do weryfikacji
            username (str, optional): Nazwa użytkownika
            email (str, optional): Email użytkownika
        
        Returns:
            dict: Szczegółowa analiza siły hasła
        """
        strength_result = zxcvbn(password, user_inputs=[username, email])
        
        # Własne kryteria bezpieczeństwa
        additional_checks = {
            'min_length': len(password) >= 12,
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_digit': bool(re.search(r'\d', password)),
            'has_special_char': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        
        # Łączna ocena
        strength_result['additional_checks'] = additional_checks
        strength_result['is_strong'] = (
            strength_result['score'] >= 3 and 
            all(additional_checks.values())
        )
        
        return strength_result

    @staticmethod
    def generate_salt(length=16):
        """Generuje bezpieczną sól kryptograficzną"""
        return secrets.token_hex(length)

    @staticmethod
    def hash_password(password, salt=None):
        """
        Hashuje hasło z dodatkową solą i wielokrotnym hashowaniem
        
        Args:
            password (str): Hasło do zahashowania
            salt (str, optional): Dodatkowa sól. Jeśli None, wygeneruje nową
        
        Returns:
            str: Zahashowane hasło z solą
        """
        if salt is None:
            salt = PasswordManager.generate_salt()
        
        # Wielokrotne hashowanie
        iterations = 100000  # PBKDF2 standard
        hash_result = generate_password_hash(
            f"{salt}{password}", 
            method='pbkdf2:sha256', 
            salt_length=16
        )
        
        return f"{salt}${hash_result}"

    @staticmethod
    def verify_password(stored_password, provided_password):
        """
        Weryfikuje hasło przeciwko zahashowanemu hasłu
        
        Args:
            stored_password (str): Przechowywane zahashowane hasło
            provided_password (str): Podane hasło do weryfikacji
        
        Returns:
            bool: Wynik weryfikacji hasła
        """
        try:
            salt, hash_part = stored_password.split('$', 1)
            return check_password_hash(hash_part, f"{salt}{provided_password}")
        except Exception:
            return False

class LoginAttemptTracker:
    @staticmethod
    def is_login_allowed(username):
        """
        Sprawdza, czy użytkownik może spróbować się zalogować.
        """
        if 'redis' not in current_app.extensions:
            raise RuntimeError("Redis extension not initialized")

        attempts_key = f"login_attempts:{username}"
        last_attempt_key = f"last_attempt_time:{username}"

        attempts = int(current_app.extensions['redis'].get(attempts_key) or 0)
        last_attempt_time = current_app.extensions['redis'].get(last_attempt_key)


        logging.debug(f"Attempts: {attempts}, Last attempt: {last_attempt_time}")

        # Sprawdzamy, czy osiągnięto 5 nieudanych prób
        if attempts >= 5 and last_attempt_time:
            last_attempt_time = datetime.strptime(last_attempt_time.decode('utf-8'), '%Y-%m-%d %H:%M:%S')
            logging.debug(f"Last attempt time: {last_attempt_time}")
           # Jeśli od ostatniej próby minęło mniej niż 3 minuty, blokujemy logowanie
            if datetime.now() - last_attempt_time < timedelta(minutes=3):
                # Zablokowane na 3 minuty
                return False

        # Jeśli nie ma blokady, możemy spróbować logować się
        if attempts >= 5:
            # Zablokowanie po 5 nieudanych próbach
            return False

        # Jeśli nie przekroczono limitu prób, dodajemy opóźnienie
        if attempts > 0:
            time.sleep(attempts * 0.5)  # Rosnące opóźnienie między próbami

        return True

    @staticmethod
    def record_failed_attempt(username):
        """
        Rejestruje nieudaną próbę logowania w Redis.
        """
        if 'redis' not in current_app.extensions:
            raise RuntimeError("Redis extension not initialized")

        attempts_key = f"login_attempts:{username}"
        last_attempt_key = f"last_attempt_time:{username}"

        attempts = int(current_app.extensions['redis'].get(attempts_key) or 0)

        # Zwiększamy liczbę prób o 1
        current_app.extensions['redis'].set(attempts_key, attempts + 1)

        # Rejestracja czasu ostatniej próby logowania
        current_app.extensions['redis'].set(last_attempt_key, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    @staticmethod
    def reset_login_attempts(username):
        """
        Resetuje licznik nieudanych prób logowania.
        """
        attempts_key = f"login_attempts:{username}"
        last_attempt_key = f"last_attempt_time:{username}"
        current_app.extensions['redis'].delete(attempts_key)
        current_app.extensions['redis'].delete(last_attempt_key)