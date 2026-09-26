@echo off
cd /d "%~dp0"
echo Starting local server at http://localhost:8000 ...
start "" http://localhost:8000
python -m http.server 8000
if errorlevel 1 (
    echo.
    echo "python" not found on PATH -- trying the py launcher instead...
    py -m http.server 8000
)
pause
