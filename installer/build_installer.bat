@echo off
REM Builds netvis-setup.exe from the current netvis.exe.
REM
REM Needs Inno Setup 6: https://jrsoftware.org/isdl.php
REM
REM Signing is optional here and controlled by two environment variables.
REM Without them you still get a working installer - just one that shows
REM the "unknown publisher" warning:
REM
REM   set NETVIS_SIGN_SHA1=<thumbprint of your code signing certificate>
REM   set NETVIS_TIMESTAMP=http://timestamp.sectigo.com

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

REM Sign the application BEFORE packaging it, so the file inside the
REM installer is signed too. Signing only the installer leaves the exe on
REM disk unsigned, and that's the one antivirus software inspects later.
if defined NETVIS_SIGN_SHA1 (
  echo Signing netvis.exe...
  signtool sign /sha1 %NETVIS_SIGN_SHA1% /fd SHA256 /tr %NETVIS_TIMESTAMP% /td SHA256 "%~dp0..\netvis.exe"
  if errorlevel 1 exit /b 1
)

%ISCC% "%~dp0netvis.iss"
if errorlevel 1 exit /b 1

if defined NETVIS_SIGN_SHA1 (
  echo Signing the installer...
  signtool sign /sha1 %NETVIS_SIGN_SHA1% /fd SHA256 /tr %NETVIS_TIMESTAMP% /td SHA256 "%~dp0output\netvis-setup.exe"
  if errorlevel 1 exit /b 1
)

echo.
echo Built: %~dp0output\netvis-setup.exe
if not defined NETVIS_SIGN_SHA1 echo (unsigned - Windows will warn users about an unknown publisher)
