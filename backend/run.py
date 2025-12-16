import os
import eventlet
eventlet.monkey_patch()

from app import app, socketio

if __name__ == '__main__':
    try:
        # Determine debug mode from environment; force off in production
        env = (os.getenv('FLASK_ENV') or os.getenv('ENV') or '').lower()
        app_debug_env = os.getenv('APP_DEBUG', 'false').lower() in ('1', 'true', 'yes', 'on')
        debug = app_debug_env and env not in ('prod', 'production')
        
        # Note: Debug should remain OFF in production for security.
        # Disable reloader to avoid watchdog child process interfering with binding
        # Use allow_unsafe_werkzeug=True only for development
        socketio.run(
            app,
            host='0.0.0.0',
            port=5000,
            debug=debug,
            use_reloader=False,
            allow_unsafe_werkzeug=True if debug else False,
        )
    except ConnectionResetError:
        pass  # Client disconnection is expected
    except Exception:
        pass  # Silently fail to avoid exposing error details
