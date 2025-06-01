from flask import Flask, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail 
from flask_wtf.csrf import CSRFProtect
import redis
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import secrets

# Declare extensions
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

def create_app():
    app = Flask(__name__)

    # App configuration
    app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY', 'super_secret_key'),
        SQLALCHEMY_DATABASE_URI=os.getenv(
            'DATABASE_URL',
            'postgresql://postgres:abc123@db:5432/flask_notes?client_encoding=utf8'
        ),
        REDIS_URL=os.getenv('REDIS_URL', 'redis://redis:6379/0'),
        PREFERRED_URL_SCHEME='https',
        PROPAGATE_EXCEPTIONS=True,
        DEBUG=os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
        # Mail settings
        MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
        MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
        MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True').lower() == 'true',
        MAIL_USERNAME=os.getenv('MAIL_USERNAME', 'your_email@gmail.com'),
        MAIL_PASSWORD=os.getenv('MAIL_PASSWORD', 'your_app_specific_password'),
        MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', 'your_email@gmail.com')
    )

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    # Login manager setup
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page.'

    # Redis
    redis_instance = redis.StrictRedis.from_url(app.config['REDIS_URL'])
    app.extensions['redis'] = redis_instance

    # Rate limiting
    limiter.storage_backend = redis_instance
    limiter.init_app(app)
    limiter.default_limits = ["200 per day", "50 per hour"]

    # Security headers (Talisman)
    Talisman(
        app,
        content_security_policy={
            'default-src': "'self'",
            'script-src': ["'self'", "'unsafe-inline'", "https://trusted.cdn.com"],
            'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            'img-src': ["'self'", "https:","data:"],
            'font-src': ["'self'", "https://fonts.gstatic.com"],
        },
        content_security_policy_nonce_in=['script-src'],
        force_https=True,
        strict_transport_security=True,
        session_cookie_secure=True
    )

    # User loader
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))
    

    @app.before_request
    def set_csp_nonce():
    # Generate a random nonce for CSP
       g.csp_nonce = secrets.token_hex(16)
    
    # Add CSP nonce to templates
    @app.context_processor
    def inject_csp_nonce():
        return dict(csp_nonce=lambda: g.csp_nonce)

    # Blueprint registration
    from app.routes import main
    app.register_blueprint(main)

    return app