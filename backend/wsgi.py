"""
Gunicorn entry point with early monkey-patching for gevent compatibility.

This file MUST be the Gunicorn entry point (wsgi:app) so that monkey.patch_all()
runs BEFORE any library (urllib3, ssl, firebase) is imported. This prevents the
'Monkey-patching ssl after ssl has already been imported' warning and the
deadlocks that follow.
"""

import os
import time

def log_ts(msg):
    # Print with timestamp for Render logs (Gunicorn will capture this stdout)
    print(f"[{time.strftime('%H:%M:%S')}] [BOOT] {msg}", flush=True)

# Force Firestore HTTP transport before anything touches gRPC/ssl
os.environ["GOOGLE_CLOUD_FIRESTORE_FORCE_HTTP"] = "true"
os.environ["SOCKETIO_ASYNC_MODE"] = "gevent"

log_ts("Applying gevent monkey patches...")
from gevent import monkey  # noqa: E402
monkey.patch_all()
log_ts("Gevent monkey patching completed.")

log_ts("Importing flask app and socketio...")
from app import app, socketio  # noqa: E402, F401
log_ts("App import complete. Ready for Gunicorn workers.")
