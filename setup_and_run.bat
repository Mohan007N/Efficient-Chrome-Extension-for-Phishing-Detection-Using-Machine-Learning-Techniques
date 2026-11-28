@echo off
echo ============================================================
echo  WebShield AI v3.0 — Setup Script
echo ============================================================
echo.

REM Step 1: Install Python backend & ML dependencies
echo [1/3] Installing requirements from requirements.txt...
pip install -r requirements.txt
echo.

REM Step 2: Generate Chrome Extension icons if helper exists
if exist create_icons.py (
  echo [2/3] Generating extension icons...
  python create_icons.py
  echo.
)

REM Step 3: Done
echo [3/3] Setup complete!
echo.
echo ============================================================
echo  HOW TO RUN (v3.0):
echo ============================================================
echo.
echo  [API BACKEND] Start the FastAPI server:
echo    uvicorn backend.main:app --host 0.0.0.0 --port 8000
echo.
echo  [RETRAIN] Build v3.0 datasets ^& train/calibrate models:
echo    python src\build_datasets.py ^&^& python run_train.py
echo.
echo  [EXTENSION] Load into Chrome:
echo    1. Open Chrome and go to: chrome://extensions/
echo    2. Enable "Developer mode" (top-right toggle)
echo    3. Click "Load unpacked" and select:
echo       %~dp0chrome_extension
echo ============================================================
pause
