@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
  set VSPATH=%%i
)

if not defined VSPATH (
  echo Could not find a Visual Studio installation with the C++ build tools.
  exit /b 1
)

set "VSPATH=%VSPATH%"
cmd /c compile.bat > build.log 2>&1

if errorlevel 1 (
  echo BUILD FAILED - see tools\netvistest\build.log
  exit /b 1
)

echo Build OK - tools\netvistest\netvistest.exe
echo.
echo   netvistest              interactive menu
echo   netvistest demo         idle -^> saturated -^> blocked, with a table
echo   netvistest dns          probe the ad/tracker blocklist
echo.
