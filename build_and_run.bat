@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM Self-elevate. Two reasons this whole script needs Administrator:
REM   1. netvis.exe is very likely already running (it can live in the tray
REM      via "run in background"), and a running exe is file-locked - the
REM      linker can't overwrite netvis.exe while it's in use, so the build
REM      silently produces no new exe. We must kill it first, and it runs
REM      elevated, so killing it needs elevation too.
REM   2. netvis itself needs Administrator for WinDivert.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
  exit /b
)

REM Close any running instance so the linker can replace netvis.exe and so
REM the single-instance check doesn't just re-focus the old copy.
taskkill /IM netvis.exe /F /T >nul 2>&1
REM Give Windows a moment to release the file lock on the exe.
timeout /t 1 /nobreak >nul

REM Delete the old exe up front, so if the link fails the "does netvis.exe
REM exist?" check below actually catches it instead of a stale build
REM silently launching.
del /f /q netvis.exe >nul 2>&1

echo Locating Visual Studio... > build.log

for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
  set VSPATH=%%i
)

if not defined VSPATH (
  echo Could not find a Visual Studio installation with the C++ build tools. >> build.log
  echo Open the Visual Studio Installer and add the "Desktop development with C++" workload, then try again. >> build.log
  echo.
  echo Build failed - see build.log
  pause
  exit /b 1
)

echo Found VS at: %VSPATH% >> build.log
echo Building netvis.exe... >> build.log

REM Run vcvarsall.bat + cl.exe in a fresh cmd.exe via "cmd /c" - some
REM vcvarsall.bat versions do a bare `exit` (not `exit /b`) internally,
REM which would otherwise kill this whole script before cl.exe ever runs.
set "VSPATH=%VSPATH%"
cmd /c compile.bat >> build.log 2>&1

if not exist netvis.exe (
  echo BUILD FAILED - see build.log >> build.log
  echo.
  echo Build failed - see build.log
  pause
  exit /b 1
)

echo Build OK >> build.log

REM Already elevated, so launch directly - no second UAC prompt.
start "" /D "%~dp0" "%~dp0netvis.exe"
