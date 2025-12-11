import json
import time
from app import app


def expect(status, code, label):
    ok = status == code
    print(f"{label}: {'PASS' if ok else f'FAIL ({status} != {code})'}")
    return ok


def main():
    ok = True
    with app.test_client() as client:
        # Health check
        r = client.get('/healthz')
        ok &= expect(r.status_code, 200, 'healthz')
        try:
            print('healthz body:', r.get_json())
        except Exception:
            print('healthz raw:', r.data)

        # Unique user
        ts = int(time.time())
        username = f"smoke_{ts}"
        email = f"{username}@example.com"
        password = "Passw0rd!"

        # Register
        r = client.post('/register', json={
            'username': username,
            'email': email,
            'password': password,
        })
        ok &= expect(r.status_code, 201, 'register')
        try:
            print('register body:', r.get_json())
        except Exception:
            print('register raw:', r.data)

        # Login (session-based, no token in response)
        r = client.post('/login', json={'username': username, 'password': password})
        ok &= expect(r.status_code, 200, 'login')
        data = r.get_json(silent=True) or {}
        
        # For session-based auth, check that user info is returned
        if 'user' in data:
            print('login session created, user:', data['user'])
        else:
            print('login user data missing')
            ok = False

        # Test authenticated endpoint (session should be active)
        r = client.get('/me')
        ok &= expect(r.status_code, 200, '/me endpoint')
        me_data = r.get_json(silent=True) or {}
        if me_data.get('username') == username:
            print(f'/me returned correct user: {username}')
        else:
            print(f'/me failed: expected {username}, got {me_data.get("username")}')
            ok = False

        print('\nOverall:', 'PASS' if ok else 'FAIL')
        return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
