# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField,BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length 
 

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), 
                                              EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Reset Password')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')   

class Verify2FAForm(FlaskForm):
    otp = StringField('OTP Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')     


class AddNoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])  # Changed from content_md to content
    password = PasswordField('Encryption Password (optional)')
    is_public = BooleanField('Make this note public')
    submit = SubmitField('Add Note')