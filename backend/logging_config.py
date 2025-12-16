"""
Production logging configuration for Quantum Secure Messaging App
Restricts logging to non-sensitive information only
"""
import os
import logging
import sys

# Disable all debug and info logging in production
LOG_LEVEL = logging.WARNING if os.getenv('FLASK_ENV') == 'production' else logging.INFO

# Configure root logger
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

# Suppress verbose loggers
logging.getLogger('flask').setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('socketio').setLevel(logging.WARNING)
logging.getLogger('engineio').setLevel(logging.WARNING)
logging.getLogger('psycopg2').setLevel(logging.WARNING)

# Disable SQLAlchemy logging
logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

# Custom application logger
app_logger = logging.getLogger('messaging_app')
app_logger.setLevel(LOG_LEVEL)

def get_logger(name):
    """Get a configured logger for a module"""
    logger = logging.getLogger(f'messaging_app.{name}')
    logger.setLevel(LOG_LEVEL)
    return logger

# Security: Never log sensitive data patterns
SENSITIVE_PATTERNS = [
    'password',
    'token',
    'secret',
    'key',
    'auth',
    'session',
    'username',
    'email',
    'credit',
    'ssn',
    'api_key'
]

def sanitize_for_logging(data):
    """Remove sensitive information from log data"""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if any(pattern in key.lower() for pattern in SENSITIVE_PATTERNS):
                sanitized[key] = '***REDACTED***'
            else:
                sanitized[key] = value
        return sanitized
    return data
