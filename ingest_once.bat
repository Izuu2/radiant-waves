@echo off
cd /d C:\radiant\ingestor
call .venv\Scripts\activate
set "GOOGLE_APPLICATION_CREDENTIALS=%C:\Users\Izuu.ekeh\AppData\Roaming%\gcloud\application_default_credentials.json"
set "GOOGLE_CLOUD_PROJECT=radiant-waves"
python -X dev -u main.py
