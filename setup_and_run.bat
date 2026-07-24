@echo off
echo ============================================================
echo  AI Phishing Shield — Setup Script
echo ============================================================
echo.

REM Step 1: Install Python backend dependencies
echo [1/3] Installing FastAPI backend dependencies...
pip install fastapi uvicorn[standard] pydantic joblib pandas pillow
echo.

REM Step 2: Generate Chrome Extension icons
echo [2/3] Generating extension icons...
python create_icons.py
echo.

REM Step 3: Done
echo [3/3] Setup complete!
echo.
echo ============================================================
echo  HOW TO RUN:
echo ============================================================
echo.
echo  [BACKEND] Start the FastAPI server:
echo    python backend\main.py
echo.
echo  [EXTENSION] Load into Chrome:
echo    1. Open Chrome and go to: chrome://extensions/
echo    2. Enable "Developer mode" (top-right toggle)
echo    3. Click "Load unpacked"
echo    4. Select the folder:
echo       %~dp0chrome_extension
echo.
echo  Then browse any website — the shield will analyze it!
echo ============================================================
pause
