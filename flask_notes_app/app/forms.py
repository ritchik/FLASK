from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import re
import secrets
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from zxcvbn import zxcvbn


class PasswordManager:
     
    
    @staticmethod
    def validate_password_strength(password, username=None, email=None):
        """Validate password strength with detailed feedback"""
        if not password:
            return {
                'score': 0,
                'is_strong': False,
                'additional_checks': {
                    'min_length': False,
                    'has_uppercase': False,
                    'has_lowercase': False,
                    'has_digit': False,
                    'has_special_char': False
                }
            }
        
         
        user_inputs = [inp for inp in [username, email] if inp]
        strength_result = zxcvbn(password, user_inputs=user_inputs)
        
         
        additional_checks = {
            'min_length': len(password) >= 12,
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_digit': bool(re.search(r'\d', password)),
            'has_special_char': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        
        strength_result['additional_checks'] = additional_checks
        strength_result['is_strong'] = (
            strength_result['score'] >= 3 and 
            all(additional_checks.values())
        )
        
        return strength_result
    
    @staticmethod
    def hash_password(password, salt=None):
        """Hash password with additional salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        hash_result = generate_password_hash(
            f"{salt}{password}", 
            method='pbkdf2:sha256', 
            salt_length=16
        )
        
        return f"{salt}${hash_result}"
    
    @staticmethod
    def verify_password(stored_password, provided_password):
        """Verify password against stored hash"""
        try:
            salt, hash_part = stored_password.split('$', 1)
            return check_password_hash(hash_part, f"{salt}{provided_password}")
        except Exception:
            return False


class BasePasswordForm(FlaskForm):
    """Base class for forms with password validation"""
    
    def validate_password_strength(self, password_field, username=None, email=None):
        """Common password validation logic"""
        strength_result = PasswordManager.validate_password_strength(
            password_field.data, username, email
        )
        
        if not strength_result['is_strong']:
            reasons = []
            checks = strength_result['additional_checks']
            
            if not checks['min_length']:
                reasons.append("at least 12 characters")
            if not checks['has_uppercase']:
                reasons.append("one uppercase letter")
            if not checks['has_lowercase']:
                reasons.append("one lowercase letter")
            if not checks['has_digit']:
                reasons.append("one digit")
            if not checks['has_special_char']:
                reasons.append("one special character")
            
            raise ValidationError(f"Password must contain: {', '.join(reasons)}")


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RegistrationForm(BasePasswordForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=3, max=20, message="Username must be between 3-20 characters")
    ])
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Invalid email format")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Password confirmation is required"),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

    def validate_username(self, field):
        """Validate username format and uniqueness"""
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', field.data):
            raise ValidationError("Username can only contain letters, numbers, and underscores")
        
        from app.models import User
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Username already exists")

    def validate_email(self, field):
        """Check if email already exists"""
        from app.models import User
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Email already registered")

    def validate_password(self, field):
        """Validate password strength"""
        self.validate_password_strength(
            field, 
            self.username.data if self.username.data else None,
            self.email.data if self.email.data else None
        )


class PasswordResetRequestForm(FlaskForm):
    """Form for requesting password reset (formerly ForgotPasswordForm)"""
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"), 
        Email(message="Please enter a valid email address")
    ])
    submit = SubmitField('Send Reset Link')


class PasswordResetForm(BasePasswordForm):
    """Form for actually resetting the password (with token)"""
    password = PasswordField('New Password', validators=[
        DataRequired(message="Password is required")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Password confirmation is required"),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Reset Password')

    def validate_password(self, field):
        """Validate new password strength"""
        self.validate_password_strength(field)


class ChangePasswordForm(BasePasswordForm):
    """Form for changing password when logged in"""
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message="Current password is required")
    ])
    new_password = PasswordField('New Password', validators=[
        DataRequired(message="New password is required")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message="Password confirmation is required"),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')

    def validate_current_password(self, field):
        """Verify current password"""
        from flask_login import current_user
        if not PasswordManager.verify_password(current_user.password_hash, field.data):
            raise ValidationError("Current password is incorrect")

    def validate_new_password(self, field):
        """Validate new password strength"""
        from flask_login import current_user
        self.validate_password_strength(
            field, 
            current_user.username if hasattr(current_user, 'username') else None,
            current_user.email if hasattr(current_user, 'email') else None
        )


class Verify2FAForm(FlaskForm):
    otp = StringField('OTP Code', validators=[
        DataRequired(message="OTP code is required"),
        Length(min=6, max=6, message="OTP code must be exactly 6 digits")
    ])
    submit = SubmitField('Verify')

    def validate_otp(self, field):
        """Validate OTP format"""
        if not field.data.isdigit():
            raise ValidationError("OTP code must contain only digits")


 
 
 