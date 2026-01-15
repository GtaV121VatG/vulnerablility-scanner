GtaV121VatG's Web Vulnerability Scanner:


I built this project as a simple web vulnerability scanner to explore how websites can be tested for common security issues. It has two parts: a backend that handles all the scanning logic, and a frontend that gives users a simple web interface to interact with the scanner.

Technical Details

For the backend, I used Python with Flask to run a local server. It handles all the requests to the target website and analyzes responses to detect potential security issues.

The frontend is built with JavaScript/Node.js. It provides a web page where users can enter a URL and view scan results. The frontend communicates with the backend using HTTP requests.

To make it easier to run, I created a start.bat file that opens both the backend and frontend in separate terminals automatically, so you don’t have to start them manually.

Project Structure
backend/     (Python backend files)
frontend/    (Frontend files (JavaScript/Node.js))
start.bat    (Script to start both backend and frontend)

Requirements

Windows computer

Python 3.x installed

Node.js and npm installed

How to Run
Step 1: Download

Go to the GitHub repository

Click the green Code button → Download ZIP

Extract the ZIP file

Step 2: Launch

Open the extracted folder

Double-click start.bat

Two command windows will open:

One runs the backend server

One runs the frontend and opens the website in your browser

Make sure to keep both windows open while using the app.

Using the Scanner

I designed the frontend so it’s simple to use. Just enter a website URL in the input box and click the scan button. The backend processes the request and sends the results back to the frontend, which displays them in a readable format.

This project is meant for learning and demonstration only. Do not scan websites without permission.

Notes

This project does not run directly on GitHub

Only works locally on Windows

Python and Node.js must be installed

License

MIT License – see LICENSE.txt for details
