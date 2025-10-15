@echo off
cd /d C:\radiant\ingestor
call .\.venv\Scripts\activate
set FLASK_APP=api.py
flask run -h 0.0.0.0 -p 8080
