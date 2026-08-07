@echo off
cd /d "%~dp0"
echo Building... > build.log
go build -o netvis.exe . >> build.log 2>&1
if errorlevel 1 (
    echo BUILD FAILED, see build.log >> build.log
    exit /b 1
)
echo Build OK >> build.log
netvis.exe > output.log 2>&1
echo Exit code: %errorlevel% >> output.log
