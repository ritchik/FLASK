from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from app.PasswordManager import PasswordManager

# Assuming you're using Flask-WTF for forms
class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(message="Password is required"),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Password confirmation is required")
    ])
    submit = SubmitField('Reset Password')

    def validate_password(self, field):
        # Use PasswordManager to validate password strength
        strength_result = PasswordManager.validate_password_strength(field.data)
        
        if not strength_result['is_strong']:
            # Get specific reasons for password weakness
            reasons = []
            checks = strength_result['additional_checks']
            if not checks['min_length']:
                reasons.append("Password must be at least 12 characters long")
            if not checks['has_uppercase']:
                reasons.append("Password must contain at least one uppercase letter")
            if not checks['has_lowercase']:
                reasons.append("Password must contain at least one lowercase letter")
            if not checks['has_digit']:
                reasons.append("Password must contain at least one digit")
            if not checks['has_special_char']:
                reasons.append("Password must contain at least one special character")
            
            raise ValidationError("Password does not meet security requirements: " + ", ".join(reasons))