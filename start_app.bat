@echo off
echo ===================================================
echo Starting Authentication Messaging App locally...
echo ===================================================

echo Starting Backend Server (Flask)...
start "Backend Server" cmd /k "cd backend && python app.py"

echo Starting Frontend Server (Vite)...
start "Frontend Server" cmd /k "cd frontend && npm run dev"

echo Both servers are starting up in new windows.
echo You can close this window now.
