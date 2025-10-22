from flask import Flask, g
import logging
from config import Config
from db_init import init_database
from db_adapter import DatabaseAdapter

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Register database teardown callback to close connections properly
    init_app(app)
    
    # Skip database initialization during app startup to avoid eventlet conflicts
    # Use init_db_standalone.py to initialize tables separately
    print("✅ App created successfully (run init_db_standalone.py to initialize database)")
    
    return app

def get_db():
    """
    Get database connection (works with both SQLite and PostgreSQL/CockroachDB).
    Uses Flask's g object to store connection per request.
    Connection is automatically closed at the end of the request.
    """
    if 'db' not in g:
        try:
            g.db = DatabaseAdapter()
            g.db.connect()
            logging.info(f'{g.db.db_type.upper()} connection successful')
        except Exception as e:
            logging.error(f'Database connection failed: {e}')
            raise RuntimeError(f'Failed to connect to database: {e}')
    
    return g.db

def close_db(e=None):
    """Close the database connection at the end of the request.
    
    The close operation is wrapped in error handling so teardown continues
    even if the underlying driver raises during close().
    """
    db = g.pop('db', None)
    if db is not None:
        try:
            # Only attempt to close if the object exposes a close method
            if hasattr(db, 'close') and callable(getattr(db, 'close')):
                db.close()
        except Exception as err:
            # Use Flask's logger if available, otherwise fallback to module logger
            try:
                from flask import current_app
                logger = getattr(current_app, 'logger', logging.getLogger(__name__))
            except Exception:
                logger = logging.getLogger(__name__)
            logger.warning(f"Database close() raised during teardown: {err}", exc_info=True)

def init_app(app):
    """Register database functions with the Flask app."""
    app.teardown_appcontext(close_db)
