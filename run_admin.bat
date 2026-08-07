@echo off
cd /d "%~dp0"
netvis.exe > output.log 2>&1
echo Exit code: %errorlevel% >> output.log
