@echo off

REM Start backend
cd /d %~dp0\backend
python -m pip install -r requirements.txt
start cmd /k "python app.py"

REM Wait a few seconds for backend to start
timeout /t 5 /nobreak

REM Start frontend
cd /d %~dp0\frontend
npm install
start cmd /k "npm start"

pause
