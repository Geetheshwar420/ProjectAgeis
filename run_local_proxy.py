import subprocess
import time
import sys
import os

# Try to handle pyngrok import gracefully
try:
    from pyngrok import ngrok
except ImportError:
    print("\n[!] Error: 'pyngrok' library not found.")
    print("[!] Please run: pip install pyngrok")
    print("[!] You may also need to install the ngrok CLI from https://ngrok.com/download")
    sys.exit(1)

def start_services():
    """Starts the Flask backend and an ngrok tunnel on port 5000."""
    print("\n" + "="*50)
    print("🚀 PROJECT AGEIS: LOCAL CLOUD BRIDGE")
    print("="*50)
    
    # Ensure we are in the right directory to find backend/app.py
    root_dir = os.getcwd()
    backend_path = os.path.join(root_dir, 'backend')
    
    if not os.path.exists(os.path.join(backend_path, 'app.py')):
        print(f"❌ Error: Could not find backend/app.py in {root_dir}")
        return

    # 1. Start the Flask Backend
    print(f"📦 Starting Backend Server...")
    # We use -u to ensure unbuffered output for real-time logging
    backend_proc = subprocess.Popen(
        [sys.executable, "-u", "app.py"],
        cwd=backend_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    # 2. Wait a moment for server to bind
    time.sleep(2)

    # 3. Start Ngrok Tunnel
    print("🌐 Initiating ngrok tunnel on port 5000...")
    try:
        
        # Connect with the specific domain provided
        tunnel = ngrok.connect(5000)
        public_url = tunnel.public_url
        
        print("\n" + "*"*50)
        print(f"✨ SUCCESS! LOCAL BACKEND IS NOW PUBLIC")
        print(f"🔗 Public URL: {public_url}")
        print("*"*50)
        print("\n👉 ACTION REQUIRED: Update your Vercel Environment Variables")
        print(f"   Set VITE_API_URL to: {public_url}")
        print("\n" + "="*50)
    except Exception as e:
        print(f"\n❌ FAILED TO START NGROK: {e}")
        print("💡 Hint: Make sure ngrok is installed and you've added your auth token.")
        backend_proc.terminate()
        return

    # 4. Stream logs
    print("📜 Backend logs (Ctrl+C to stop):")
    try:
        for line in iter(backend_proc.stdout.readline, ""):
            if line:
                print(f"  [SERVER] {line.strip()}")
    except KeyboardInterrupt:
        print("\n\n🛑 Received stop signal. Cleaning up...")
    finally:
        print("🧹 Closing tunnel...")
        ngrok.disconnect(public_url)
        print("🧹 Killing backend process...")
        backend_proc.terminate()
        print("✅ Finished.")

if __name__ == "__main__":
    start_services()
