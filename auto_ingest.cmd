@echo off
cd /d C:\radiant\ingestor
C:\radiant\ingestor\.venv\Scripts\python.exe -X dev -u main.py 1>> ingest.log 2>&1
echo [%Mon 10/13/2025% %16:00:40.97%] DONE >> ingest.log && dir cache_articles.json >> ingest.log
