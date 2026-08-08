@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo Locating Visual Studio... > build.log

for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
  set VSPATH=%%i
)

if not defined VSPATH (
  echo Could not find a Visual Studio installation with the C++ build tools. >> build.log
  echo Open the Visual Studio Installer and add the "Desktop development with C++" workload, then try again. >> build.log
  exit /b 1
)

echo Found VS at: %VSPATH% >> build.log
echo Building netvis.exe... >> build.log

REM Run vcvarsall.bat + cl.exe in a fresh cmd.exe via "cmd /c" - some
REM vcvarsall.bat versions do a bare `exit` (not `exit /b`) internally,
REM which would otherwise kill this whole script before cl.exe ever runs.
set "VSPATH=%VSPATH%"
cmd /c compile.bat >> build.log 2>&1

if errorlevel 1 (
  echo BUILD FAILED - see build.log >> build.log
  exit /b 1
)

echo Build OK >> build.log

REM netvis.exe needs Administrator privileges for WinDivert (WinDivertOpen
REM fails otherwise, silently disabling both the bandwidth monitor AND the
REM ad blocker - no crash, no obvious error, it just does nothing). Launch
REM elevated via PowerShell so a plain double-click of this .bat still
REM gets a real, working instance.
powershell -NoProfile -Command "Start-Process -FilePath '%~dp0netvis.exe' -WorkingDirectory '%~dp0' -Verb RunAs"
