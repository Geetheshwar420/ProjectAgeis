from datetime import datetime, timedelta

class CryptoSession:
    def __init__(self, session_id, user_a, user_b, status):
        self.session_id = session_id
        self.user_a = user_a
        self.user_b = user_b
        self.status = status
        self.created_at = datetime.now()
        self.expires_at = self.created_at + timedelta(minutes=30)
        self.bb84_key = None
        self.kyber_shared_secret = None
        self.session_key = None
