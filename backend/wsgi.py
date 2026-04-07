"""
Gunicorn entry point with early monkey-patching for gevent compatibility.

This file MUST be the Gunicorn entry point (wsgi:app) so that monkey.patch_all()
runs BEFORE any library (urllib3, ssl, firebase) is imported. This prevents the
'Monkey-patching ssl after ssl has already been imported' warning and the
deadlocks that follow.
"""

import os

# Force Firestore HTTP transport before anything touches gRPC/ssl
os.environ["GOOGLE_CLOUD_FIRESTORE_FORCE_HTTP"] = "true"
os.environ["SOCKETIO_ASYNC_MODE"] = "gevent"

from gevent import monkey  # noqa: E402
monkey.patch_all()

from app import app, socketio  # noqa: E402, F401
