@echo off
setlocal
cd /d "%~dp0.."
set PYTHONIOENCODING=utf-8
python app.py --host 127.0.0.1 --port 8787
