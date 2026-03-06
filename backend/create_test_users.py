import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from firebase_db import initialize_firebase, create_user

def main():
    load_dotenv()
    
    # Initialize firebase
    try:
        initialize_firebase()
    except Exception as e:
        print(f"Firebase initialization failed: {e}")
        return

    users_to_create = [
        {"username": "alice", "password": "python"},
        {"username": "bob", "password": "python"}
    ]
    
    for user_info in users_to_create:
        pwd_hash = generate_password_hash(user_info["password"])
        created = create_user(user_info["username"], pwd_hash, password=user_info["password"])
        if created:
            print(f"Created user: {user_info['username']} / {user_info['password']}")
        else:
            print(f"User {user_info['username']} already exists or failed to create.")

if __name__ == "__main__":
    main()
