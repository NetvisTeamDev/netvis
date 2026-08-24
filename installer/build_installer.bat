@echo off
REM Builds netvis-setup.exe from the current netvis.exe.
REM
REM Needs Inno Setup 6: https://jrsoftware.org/isdl.php
REM
REM Code signing is handled by sign.bat and is optional. Without a certificate
REM configured you still get a working installer - just one that shows the
REM "unknown publisher" warning. To sign, first (once per 2-hour session):
REM
REM   1. Open SimplySign Desktop and log in.
REM   2. set NETVIS_SIGN_SHA1=<thumbprint of the Certum certificate>
REM
REM See sign.bat for the details. Everything below signs automatically when
REM that variable is set, and quietly skips signing when it isn't.

setlocal

set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist %ISCC% (
  echo Inno Setup not found at %ISCC%
  echo Install it from https://jrsoftware.org/isdl.php
  exit /b 1
)

if not exist "%~dp0..\netvis.exe" (
  echo netvis.exe not found - run build_and_run.bat first.
  exit /b 1
)

REM Single source of truth for the version: read it from src\version.h and hand
REM it to Inno Setup, so the installer's version always equals the exe's. If
REM they disagree, a freshly installed build reports an old version and the
REM updater re-downloads the same file forever.
set "APPVER="
for /f "tokens=3" %%v in ('findstr /c:"define NETVIS_VERSION" "%~dp0..\src\version.h"') do set "APPVER=%%v"
set APPVER=%APPVER:"=%
set "VERDEF="
if defined APPVER set "VERDEF=/DAppVersion=%APPVER%"
if defined APPVER (echo Building installer for version %APPVER%) else (echo WARNING: could not read version from src\version.h - using the .iss fallback)

REM Sign the application BEFORE packaging it, so the file INSIDE the installer
REM is signed too. Signing only the installer leaves the exe on disk unsigned,
REM and that on-disk exe is the one antivirus inspects after installation.
call "%~dp0sign.bat" "%~dp0..\netvis.exe"
if errorlevel 1 exit /b 1

%ISCC% %VERDEF% "%~dp0netvis.iss"
if errorlevel 1 exit /b 1

REM Then sign the installer itself, so SmartScreen sees a signed setup.exe
REM at download time.
call "%~dp0sign.bat" "%~dp0output\netvis-setup.exe"
if errorlevel 1 exit /b 1

echo.
echo Built: %~dp0output\netvis-setup.exe
if not defined NETVIS_SIGN_SHA1 echo (unsigned - Windows will warn users about an unknown publisher)
