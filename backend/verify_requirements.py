# Requirements Verification Script
# This script verifies that all pinned dependencies are compatible

import sys
import os
import subprocess

def check_imports():
    """Test that all critical packages can be imported."""
    print("=" * 70)
    print("VERIFYING PACKAGE IMPORTS")
    print("=" * 70)
    
    packages = [
        ("Flask", "flask"),
        ("Flask-Cors", "flask_cors"),
        ("Flask-SocketIO", "flask_socketio"),
        ("cryptography", "cryptography"),
        ("bcrypt", "bcrypt"),
        ("eventlet", "eventlet"),
        ("python-dotenv", "dotenv"),
        ("Werkzeug", "werkzeug"),
        ("itsdangerous", "itsdangerous"),
        ("email-validator", "email_validator"),
        ("passlib", "passlib"),
        ("psycopg2-binary", "psycopg2"),
        ("SQLAlchemy", "sqlalchemy")
    ]
    
    failed = []
    
    for package_name, import_name in packages:
        try:
            __import__(import_name)
            print(f"✅ {package_name}: OK")
        except ImportError as e:
            print(f"❌ {package_name}: FAILED - {e}")
            failed.append(package_name)
    
    print("\n" + "=" * 70)
    
    if failed:
        print(f"❌ FAILED: {len(failed)} package(s) could not be imported:")
        for pkg in failed:
            print(f"   - {pkg}")
        return False
    else:
        print("✅ SUCCESS: All packages imported successfully")
        return True

def check_versions():
    """Display installed versions for verification."""
    print("\n" + "=" * 70)
    print("INSTALLED VERSIONS")
    print("=" * 70)
    
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=columns"],
        capture_output=True,
        text=True
    )
    
    packages = [
        "Flask", "Flask-Cors", "Flask-SocketIO", "cryptography", "bcrypt",
        "eventlet", "python-dotenv", "Werkzeug", "itsdangerous",
        "email-validator", "passlib", "psycopg2-binary", "SQLAlchemy"
    ]
    
    for line in result.stdout.split('\n'):
        for pkg in packages:
            if line.startswith(pkg):
                print(line)
                break
    
    print("=" * 70)

def check_compatibility():
    """Test basic compatibility between Flask and Flask-SocketIO."""
    print("\n" + "=" * 70)
    print("CHECKING FLASK + SOCKETIO COMPATIBILITY")
    print("=" * 70)
    
    try:
        from flask import Flask
        from flask_socketio import SocketIO
        from flask_cors import CORS
        
        app = Flask(__name__)
        CORS(app)
        # Avoid wildcard CORS in production; prefer explicit allowlist. For local/verification, we default to localhost.
        origins_env = os.getenv('SOCKETIO_ALLOWED_ORIGINS') or os.getenv('VERIFY_ALLOWED_ORIGINS')
        if origins_env:
            allowed_origins = [o.strip() for o in origins_env.split(',') if o.strip()]
        else:
            allowed_origins = [
                # Common local dev origins (http)
                'http://localhost:3000', 'http://127.0.0.1:3000', 'http://[::1]:3000',
                'http://localhost:5000', 'http://127.0.0.1:5000', 'http://[::1]:5000',
                # Optionally include https localhost
                'https://localhost:3000', 'https://127.0.0.1:3000', 'https://[::1]:3000'
            ]
        socketio = SocketIO(app, cors_allowed_origins=allowed_origins)
        
        print("✅ Flask + Flask-SocketIO + Flask-Cors: Compatible (CORS restricted)")
        return True
    except Exception as e:
        print(f"❌ Flask + Flask-SocketIO + Flask-Cors: INCOMPATIBLE")
        print(f"   Error: {e}")
        return False

def check_crypto():
    """Test cryptography libraries."""
    print("\n" + "=" * 70)
    print("CHECKING CRYPTOGRAPHY LIBRARIES")
    print("=" * 70)
    
    try:
        import bcrypt
        import cryptography
        from passlib.hash import bcrypt as passlib_bcrypt
        
        # Test bcrypt
        password = b"test_password"
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        assert bcrypt.checkpw(password, hashed)
        print("✅ bcrypt: Working")
        
        # Test passlib
        hash_test = passlib_bcrypt.hash("test")
        assert passlib_bcrypt.verify("test", hash_test)
        print("✅ passlib: Working")
        
        # Test cryptography
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(b"test")
        assert f.decrypt(token) == b"test"
        print("✅ cryptography: Working")
        
        return True
    except Exception as e:
        print(f"❌ Cryptography test failed: {e}")
        return False

def check_database():
    """Test database drivers."""
    print("\n" + "=" * 70)
    print("CHECKING DATABASE DRIVERS")
    print("=" * 70)
    
    try:
        import psycopg2
        import sqlalchemy
        from sqlalchemy import create_engine
        
        print(f"✅ psycopg2: Version {psycopg2.__version__}")
        print(f"✅ SQLAlchemy: Version {sqlalchemy.__version__}")
        
        # Test SQLite engine creation (doesn't require actual DB)
        engine = create_engine('sqlite:///:memory:', echo=False)
        with engine.connect() as conn:
            result = conn.execute(sqlalchemy.text("SELECT 1"))
            assert result.scalar() == 1
        print("✅ SQLAlchemy engine: Working")
        
        return True
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def main():
    print("\n" + "=" * 70)
    print("REQUIREMENTS.TXT VERIFICATION")
    print("=" * 70)
    print("This script verifies that all pinned dependencies are compatible")
    print("and working correctly.")
    print("=" * 70 + "\n")
    
    results = {
        "imports": check_imports(),
        "versions": check_versions() or True,  # Display only, always pass
        "compatibility": check_compatibility(),
        "crypto": check_crypto(),
        "database": check_database()
    }
    
    print("\n" + "=" * 70)
    print("FINAL RESULT")
    print("=" * 70)
    
    all_passed = all([
        results["imports"],
        results["compatibility"],
        results["crypto"],
        results["database"]
    ])
    
    if all_passed:
        print("✅ ALL TESTS PASSED")
        print("The pinned versions in requirements.txt are compatible and working.")
        return 0
    else:
        print("❌ SOME TESTS FAILED")
        print("Please review the errors above and adjust requirements.txt")
        return 1

if __name__ == "__main__":
    sys.exit(main())
