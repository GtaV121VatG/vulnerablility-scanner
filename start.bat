@echo off

REM Make sure we start in the folder where the bat file is
cd /d %~dp0

echo Starting backend...
start "" cmd /k "cd backend && python -m pip install -r requirements.txt && python app.py"

echo Waiting for backend to start...
timeout /t 8 /nobreak

echo Starting frontend...
start "" cmd /k "cd frontend && npm install && npm start"

echo App is starting. Keep both windows open.
pause
