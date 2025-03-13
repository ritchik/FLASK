import os
import time
from sqlalchemy.exc import OperationalError
from app import create_app, db

def wait_for_db(app, max_retries=10):
    retry_count = 0
    while retry_count < max_retries:
        try:
            with app.app_context():
                db.create_all()
            return True
        except OperationalError:
            retry_count += 1
            print(f"Database not ready, retrying... ({retry_count}/{max_retries})")
            time.sleep(5)
    return False

# Create the app object for Gunicorn
app = create_app()

# Wait for database and create tables
if not wait_for_db(app):
    raise RuntimeError("Could not connect to database")

# Add this for running directly
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)