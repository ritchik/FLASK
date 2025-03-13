import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'super_secret_key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:abc123@db:5432/flask_notes')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
