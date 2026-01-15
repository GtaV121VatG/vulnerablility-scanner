@echo off

echo Starting backend...
start cmd /k "cd backend && pip install -r requirements.txt && python app.py"

echo Waiting for backend to start...
timeout /t 5 /nobreak

echo Starting frontend...
start cmd /k "cd frontend && npm install && npm start"

echo App is starting. Keep both windows open.
pause
