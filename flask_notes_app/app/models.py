from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import datetime
import markdown
import bleach
from sqlalchemy.event import listens_for
from app import db 
from cryptography.fernet import Fernet
import base64
import hashlib
from werkzeug.security import check_password_hash, generate_password_hash
 
 

 
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)  # Store the TOTP secret
    is_2fa_verified = db.Column(db.Boolean, default=False)  # Track whether 2FA is verified
    notes = db.relationship('Note', backref='author', lazy=True)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content_md = db.Column(db.Text, nullable=False)  # Markdown
    content_html = db.Column(db.Text, nullable=True)  # Wygenerowany HTML
    encrypted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    signature = db.Column(db.String(512), nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)  # Store hashed password for encrypted notes
    is_public = db.Column(db.Boolean, default=False)

    def render_markdown(self):
        """Konwertuje Markdown na bezpieczny HTML"""
        allowed_tags = ['p', 'strong', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'a', 'img', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre']
        allowed_attrs = {'a': ['href', 'title'], 'img': ['src', 'alt']}
        
        html_content = markdown.markdown(self.content_md, extensions=['extra'])
        safe_html = bleach.clean(html_content, tags=allowed_tags, attributes=allowed_attrs)

        self.content_html = safe_html
    
    def encrypt_content(self, password):
        """Encrypt the content using the provided password."""
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())  # Key derived from password
        fernet = Fernet(key)
        encrypted_content = fernet.encrypt(self.content_md.encode())
        self.content_md = encrypted_content.decode('utf-8')
        self.encrypted = True
        self.password_hash = generate_password_hash(password)  # Store the hashed password for later verification

    def decrypt_content(self, password):
        """Decrypt the content if the password is correct."""
        if not self.encrypted:
            return self.content_md  # Return unencrypted content if not encrypted
        
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())  # Key derived from password
        fernet = Fernet(key)
        
        try:
            decrypted_content = fernet.decrypt(self.content_md.encode()).decode('utf-8')
            return decrypted_content
        except Exception as e:
            return None  # Return None if decryption fails (incorrect password)
        
    def is_accessible_by(self, user):
        """Sprawdza, czy użytkownik ma dostęp do tej notatki"""
        if self.is_public or self.user_id == user.id:
            return True
        return SharedNote.query.filter_by(note_id=self.id, user_id=user.id).first() is not None



class SharedNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Jeśli `NULL`, to publiczna
    shared_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    note = db.relationship("Note", backref="shared_notes")
    user = db.relationship("User", backref="shared_notes")

class Signature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    signature = db.Column(db.String(512), nullable=False)
    signed_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
