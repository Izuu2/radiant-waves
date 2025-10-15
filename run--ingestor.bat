@echo off
title Radiant Ingestor
cd /d C:\radiant\ingestor || (echo [ERROR] cd failed & pause & exit /b 1)

:: Create venv on first run
if not exist .venv (
  echo [INFO] Creating virtual environment...
  python -m venv .venv || (echo [ERROR] venv creation failed & pause & exit /b 1)
  call .venv\Scripts\activate
  echo [INFO] Upgrading pip and installing requirements...
  python -m pip install --upgrade pip
  pip install -r requirements.txt || (echo [ERROR] requirements install failed & pause & exit /b 1)
) else (
  call .venv\Scripts\activate
)

:: GCP auth
set "GOOGLE_APPLICATION_CREDENTIALS=%APPDATA%\gcloud\application_default_credentials.json"
set "GOOGLE_CLOUD_PROJECT=radiant-waves"

echo [INFO] Starting ingestion run...
python -X dev -u main.py
echo [INFO] Exit code: %ERRORLEVEL%
pause
