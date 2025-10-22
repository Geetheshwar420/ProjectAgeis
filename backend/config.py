import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_super_secret_key'
    # SQLite database path - default to a local file in the backend directory
    SQLITE_DATABASE_PATH = os.environ.get('SQLITE_DATABASE_PATH') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'messaging_app.db'
    )
 
