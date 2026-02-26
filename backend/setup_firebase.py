#!/usr/bin/env python3
"""
Firebase Setup Verification Script
Run this to verify Firebase is properly configured.
"""

import os
import sys
from pathlib import Path

def check_firebase_credentials():
    """Check if Firebase credentials file exists"""
    creds_path = Path('firebase-credentials.json')
    if creds_path.exists():
        print("✓ firebase-credentials.json found")
        return True
    else:
        print("✗ firebase-credentials.json NOT found")
        print("  Download from: Firebase Console → Project Settings → Service Accounts → Generate New Private Key")
        print("  Save as: backend/firebase-credentials.json")
        return False

def check_env_variables():
    """Check if .env file has required Firebase variables"""
    from dotenv import load_dotenv
    load_dotenv()
    
    required = {
        'FIREBASE_PROJECT_ID': 'Firebase project ID',
        'FIREBASE_STORAGE_BUCKET': 'Firebase storage bucket (projectid.appspot.com)',
    }
    
    all_present = True
    print("\nEnvironment Variables:")
    for var, desc in required.items():
        value = os.getenv(var)
        if value:
            print(f"✓ {var}={value}")
        else:
            print(f"✗ {var} NOT SET - {desc}")
            all_present = False
    
    return all_present

def check_dependencies():
    """Check if Firebase Admin SDK is installed"""
    try:
        import firebase_admin
        print(f"\n✓ firebase-admin installed (version: {firebase_admin.__version__})")
        return True
    except ImportError:
        print("\n✗ firebase-admin NOT installed")
        print("  Install with: pip install firebase-admin>=6.2.0")
        return False

def test_firebase_connection():
    """Test connection to Firebase"""
    try:
        from firebase_db import initialize_firebase, get_db_client
        print("\nTesting Firebase Connection...")
        
        client = initialize_firebase()
        print("✓ Firebase initialized successfully")
        
        # Test Firestore
        client.collection('test').limit(1).stream()
        print("✓ Firestore connection successful")
        
        # Test Storage
        from firebase_admin import storage
        bucket = storage.bucket()
        print(f"✓ Firebase Storage connected (bucket: {bucket.name})")
        
        return True
    except FileNotFoundError as e:
        print(f"✗ Firebase initialization failed: {e}")
        print("  Make sure firebase-credentials.json is in the backend folder")
        return False
    except Exception as e:
        print(f"✗ Firebase connection failed: {e}")
        print(f"  Error: {str(e)}")
        return False

def main():
    """Run all checks"""
    print("=" * 60)
    print("Firebase Setup Verification")
    print("=" * 60)
    
    checks = [
        ("Firebase Credentials", check_firebase_credentials),
        ("Environment Variables", check_env_variables),
        ("Dependencies", check_dependencies),
    ]
    
    results = []
    for name, check_func in checks:
        print(f"\nChecking {name}...")
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"✗ Error checking {name}: {e}")
            results.append((name, False))
    
    # Test Firebase connection
    print("\n" + "=" * 60)
    connection_ok = test_firebase_connection()
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    for name, result in results:
        status = "✓" if result else "✗"
        print(f"{status} {name}")
    
    connection_status = "✓" if connection_ok else "✗"
    print(f"{connection_status} Firebase Connection")
    
    if all(r for _, r in results) and connection_ok:
        print("\n" + "=" * 60)
        print("✓ ALL CHECKS PASSED - Firebase is configured correctly!")
        print("=" * 60)
        return 0
    else:
        print("\n" + "=" * 60)
        print("✗ Some checks failed - see above for details")
        print("=" * 60)
        return 1

if __name__ == '__main__':
    sys.exit(main())
