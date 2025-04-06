from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone
import markdown
import bleach
from sqlalchemy.event import listens_for
from app import db 
from cryptography.fernet import Fernet
import base64
import hashlib
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
 
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)  # Store the TOTP secret
    is_2fa_verified = db.Column(db.Boolean, default=False)  # Track whether 2FA is verified
    notes = db.relationship('Note', backref='author', lazy=True)
   
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)

    def generate_keys(self):
        """Generuje parę kluczy RSA i zapisuje je w bazie"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.private_key = private_pem
        self.public_key = public_pem
      
        

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content_md = db.Column(db.Text, nullable=False)  # Markdown
    content_html = db.Column(db.Text, nullable=True)  # Wygenerowany HTML
    encrypted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
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

    def sign_note(self, user):
        """Podpisuje notatkę za pomocą klucza prywatnego użytkownika"""
        if not user.private_key:
         raise ValueError("Brak klucza prywatnego dla użytkownika")

        private_key = load_pem_private_key(user.private_key.encode(), password=None)
        signature = private_key.sign(
            self.content_md.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        self.signature = base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, user):
        """Weryfikuje podpis notatki za pomocą klucza publicznego użytkownika"""
        if not user.public_key or not self.signature:
          return False  # <-- правильный отступ
    
        public_key = load_pem_public_key(user.public_key.encode())  # <-- теперь внутри функции
        try:
            public_key.verify(
                base64.b64decode(self.signature),
                self.content_md.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True  # <-- отступ исправлен
        except Exception:
           return False  # <-- отступ исправлен

       

class SharedNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Jeśli `NULL`, to publiczna
    shared_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    note = db.relationship("Note", backref="shared_notes")
    user = db.relationship("User", backref="shared_notes")

class Signature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    signature = db.Column(db.String(512), nullable=False)
    signed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.Text)
    login_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    location = db.Column(db.String(100))     
