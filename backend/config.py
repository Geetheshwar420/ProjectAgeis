import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key')
    PORT = int(os.getenv('PORT', 5000))
    DEBUG = os.getenv('FLASK_ENV') == 'development'

    # Firebase Configuration
    FIREBASE_PROJECT_ID = os.getenv('FIREBASE_PROJECT_ID', 'project-ageis')
    FIREBASE_STORAGE_BUCKET = os.getenv('FIREBASE_STORAGE_BUCKET', 'project-ageis.firebasestorage.app')
    FIREBASE_CREDENTIALS_PATH = os.getenv(
        'FIREBASE_CREDENTIALS_PATH',
        'project-ageis-firebase-adminsdk-fbsvc-c98c18ce2c.json'
    )

    # Session Config
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    CORS_HEADERS = 'Content-Type'
