@echo off
REM Go to the backend folder
cd /d %~dp0\backend

REM Install required Python packages
python -m pip install -r requirements.txt

REM Start the backend server
python app.py

pause
