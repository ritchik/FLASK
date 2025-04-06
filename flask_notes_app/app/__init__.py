from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail 
from flask_wtf.csrf import CSRFProtect
import redis
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# Declare SQLAlchemy and LoginManager instances
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
csrf = CSRFProtect()

# Initialize limiter without storage first
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://") 

def create_app():
    app = Flask(__name__)

    # Configuration for the app
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super_secret_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL',
        'postgresql://postgres:abc123@db:5432/flask_notes?client_encoding=utf8'
    )
    app.config['REDIS_URL'] = os.getenv('REDIS_URL', 'redis://redis:6379/0')
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

    # Email configuration
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'your_email@gmail.com')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'your_app_specific_password')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'your_email@gmail.com')

    # Initialize extensions with the app
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app) 
    csrf.init_app(app)

    # Set up login manager
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page'

    # Initialize Redis
    redis_instance = redis.StrictRedis.from_url(app.config['REDIS_URL'])
    app.extensions['redis'] = redis_instance

    # Configure limiter
    limiter.storage_backend = redis_instance
    limiter.init_app(app)
    limiter.default_limits = ["200 per day", "50 per hour"]

    # CSP Configuration
    csp = {
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", "https://trusted.cdn.com"],
        'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        'img-src': ["'self'", "data:"],
        'font-src': ["'self'", "https://fonts.gstatic.com"],
    }

    # Initialize Talisman in production only
    
    Talisman(
            app,
            content_security_policy=csp,
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

    # Register blueprint
    from app.routes import main
    app.register_blueprint(main)
    
    # Remove Server header
    @app.after_request
    def remove_server_header(response):
      response.headers.pop('Server', None)
      response.headers['Server'] = ''  # Try setting empty string
      return response
    
    return app  # Correctly indented inside create_app()