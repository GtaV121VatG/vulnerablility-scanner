@echo off

echo Starting backend...
start cmd /k "cd backend && pip install -r requirements.txt && python app.py"

echo Starting frontend...
start cmd /k "cd frontend && npm install && npm start"

echo App is starting. Do not close the terminal windows.
pause
