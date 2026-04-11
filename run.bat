@echo off
title QuizMaster Pro
color 0A
echo.
echo  ==========================================
echo    QuizMaster Pro — Starting Server...
echo  ==========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  ERROR: Python not found!
    echo  Please install Python from https://python.org
    echo  Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

REM Install dependencies
echo  Installing dependencies...
pip install flask flask-limiter flask-talisman bleach --quiet

echo.
echo  ==========================================
echo    Server starting at http://127.0.0.1:5000
echo    Interview Prep: http://127.0.0.1:5000/interview
echo    Press Ctrl+C to stop
echo  ==========================================
echo.

REM Start the server
python app.py

pause
