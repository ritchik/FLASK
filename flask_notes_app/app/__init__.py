from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import redis
import os

# Declare SQLAlchemy and LoginManager instances
db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # Configuration for the app postgresql://postgres:abc123@db:5432/flask_notes
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super_secret_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL',
        'postgresql://postgres:abc123@db:5432/flask_notes?client_encoding=utf8'
    )
    app.config['REDIS_URL'] = os.getenv('REDIS_URL', 'redis://redis:6379/0')
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

    # Initialize db and login_manager with the app
    db.init_app(app)
    login_manager.init_app(app)

    # Set up login manager configuration
    login_manager.login_view = 'main.login'  # Specify the login route
    login_manager.login_message = 'Please log in to access this page'

    # Initialize Redis client and store it in app's extensions
    redis_instance = redis.StrictRedis.from_url(app.config['REDIS_URL'])
    app.extensions['redis'] = redis_instance  # Store the Redis client in app's extensions

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User  # Import here to avoid circular imports
        return User.query.get(int(user_id))

    # Register the blueprint
    from app.routes import main
    app.register_blueprint(main)

    # Create tables
    with app.app_context():
        db.create_all()

    return app