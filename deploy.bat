@echo off
REM ==========================================================================
REM  deploy.bat - one click to ship a new netvis release.
REM
REM  What it does, in order:
REM    1. builds netvis.exe (release, optimised)
REM    2. builds the installer (installer\output\netvis-setup.exe)
REM    3. signs the auto-update manifest with your update key
REM    4. uploads the update files + the website download to the server
REM
REM  FIRST RUN ONLY: if there's no update key yet, it generates one, prints the
REM  public half, and stops so you can paste it into src\license.cpp and
REM  rebuild. Keys are generated ONCE - never per release - because the client
REM  is built with the matching public key and would reject a manifest signed
REM  by a different one.
REM
REM  Needs on this machine: Visual Studio C++ build tools, Inno Setup 6, Go,
REM  and OpenSSH (scp/ssh - built into Windows 10/11).
REM ==========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM ---- config you can change ------------------------------------------------
set "REMOTE_DIR=/opt/netvis"
set "SERVICE_USER=netvis"
set "SERVERFILE=deploy_server.txt"
REM --------------------------------------------------------------------------

echo(
echo ===== netvis deploy =====
echo(

REM ---- 0. preflight: tools -------------------------------------------------
where go >nul 2>&1 || (echo [X] Go not found on PATH. Install from https://go.dev/dl/ & goto :fail)
where scp >nul 2>&1 || (echo [X] scp not found. Enable "OpenSSH Client" in Windows Optional Features. & goto :fail)
if not exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
  echo [X] Inno Setup 6 not found. Install from https://jrsoftware.org/isdl.php
  goto :fail
)

REM ---- 1. server address ---------------------------------------------------
if exist "%SERVERFILE%" (
  set /p SERVER=<"%SERVERFILE%"
) else (
  echo First time: where does netvis.cc run?
  set /p SERVER="  Server SSH login (e.g. ubuntu@203.0.113.5): "
  >"%SERVERFILE%" echo !SERVER!
)
echo Server: !SERVER!    ^(edit %SERVERFILE% to change^)
echo(

REM ---- 1b. passwordless SSH: type your password at most ONCE, ever ---------
REM Windows' OpenSSH can't share one login across the several scp/ssh calls a
REM deploy makes, so without a key you'd retype your password 4 times. Instead
REM we set up an SSH key: generate one if missing, and install it on the server
REM the first time (that's the single password prompt). Every deploy after this
REM - and the rest of THIS one - authenticates with the key, no password.
set "SSHKEY=%USERPROFILE%\.ssh\id_ed25519"
if not exist "%USERPROFILE%\.ssh" mkdir "%USERPROFILE%\.ssh" >nul 2>&1
if not exist "%SSHKEY%" (
  echo No SSH key yet - generating one ^(one-time^)...
  ssh-keygen -t ed25519 -N "" -f "%SSHKEY%" >nul
)
REM Does the key already get us in without a password? (quick, no prompt)
ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new !SERVER! "exit" >nul 2>&1
if errorlevel 1 (
  echo(
  echo Installing your SSH key on the server. Enter your password ONE last time:
  type "%SSHKEY%.pub" | ssh -o StrictHostKeyChecking=accept-new !SERVER! "umask 077; mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys"
  REM Verify it now works passwordlessly; if not, we carry on and the later
  REM steps will just prompt as before rather than failing outright.
  ssh -o BatchMode=yes -o ConnectTimeout=8 !SERVER! "exit" >nul 2>&1 && (echo Key installed - no more password prompts.) || (echo Could not confirm key auth; you may still be prompted below.)
  echo(
)

REM ---- 2. build the licensing tool (used to sign updates) ------------------
pushd licensing
go build -o licensing.exe . || (popd & echo [X] building licensing.exe failed & goto :fail)
popd

REM ---- 3. FIRST RUN: generate the update key, then stop --------------------
if not exist "licensing\update_private_key.txt" (
  echo(
  echo No update key yet - generating one ^(this happens only once^).
  pushd licensing
  for /f "tokens=2 delims==" %%K in ('licensing.exe genupdatekeys -write ^| findstr /b UPDATE_PUBLIC_KEY=') do set "PUBKEY=%%K"
  popd
  echo(
  echo ============================ ONE-TIME SETUP ============================
  echo  A private key was saved to  licensing\update_private_key.txt
  echo  ^(keep it secret - it is gitignored, never upload it^).
  echo(
  echo  Now paste this PUBLIC key into src\license.cpp as kUpdatePublicKey:
  echo(
  echo     !PUBKEY!
  echo(
  echo  Then run deploy.bat again. Until the client is rebuilt with this key,
  echo  auto-update will reject everything.
  echo =======================================================================
  goto :end
)

REM ---- 4. version ----------------------------------------------------------
set "VER="
for /f "tokens=3" %%v in ('findstr /c:"define NETVIS_VERSION" src\version.h') do set "VER=%%v"
set VER=%VER:"=%
if "%VER%"=="" (echo [X] couldn't read version from src\version.h & goto :fail)

echo About to build and ship version %VER%.
echo If that's not the new version, bump it in BOTH src\version.h and
echo installer\netvis.iss first, then re-run.
set /p GO="Continue? (Y/N): "
if /i not "%GO%"=="Y" goto :end

REM ---- 5. build netvis.exe (release, optimised) ----------------------------
echo(
echo [1/4] building netvis.exe ...
set "NETVIS_FAST="
taskkill /IM netvis.exe /F /T >nul 2>&1
del /f /q netvis.exe >nul 2>&1
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (echo [X] Visual Studio C++ build tools not found & goto :fail)
cmd /c compile.bat >build.log 2>&1
if not exist netvis.exe (echo [X] build failed - see build.log & goto :fail)

REM ---- 6. build the installer ----------------------------------------------
echo [2/4] building the installer ...
call installer\build_installer.bat >>build.log 2>&1
if not exist "installer\output\netvis-setup.exe" (echo [X] installer build failed - see build.log & goto :fail)

REM ---- 7. sign the update manifest -----------------------------------------
echo [3/4] signing the update manifest ...
pushd licensing
licensing.exe signupdate -version %VER% -file "..\installer\output\netvis-setup.exe" -key @update_private_key.txt
if errorlevel 1 (popd & echo [X] signing failed & goto :fail)
popd
if not exist "licensing\updates\windows\update.json" (echo [X] manifest not produced & goto :fail)

REM ---- 8. upload -----------------------------------------------------------
echo [4/4] uploading to !SERVER! ...
REM -O forces the classic SCP protocol. Modern scp defaults to SFTP, which
REM some servers don't expose - the symptom is "scp: Connection closed".
scp -O -q "licensing\updates\windows\update.json" "licensing\updates\windows\update.json.sig" "licensing\updates\windows\netvis-windows-%VER%.exe" !SERVER!:/tmp/ || (echo [X] scp of update files failed & goto :sshhelp)
ssh -t !SERVER! "sudo mkdir -p %REMOTE_DIR%/updates/windows && sudo mv /tmp/update.json /tmp/update.json.sig /tmp/netvis-windows-%VER%.exe %REMOTE_DIR%/updates/windows/ && sudo chown -R %SERVICE_USER%:%SERVICE_USER% %REMOTE_DIR%/updates" || (echo [X] moving update files on server failed & goto :fail)

scp -O -q "installer\output\netvis-setup.exe" !SERVER!:/tmp/netvis-setup.exe || (echo [X] scp of installer failed & goto :fail)
ssh -t !SERVER! "sudo mkdir -p %REMOTE_DIR%/downloads && sudo mv /tmp/netvis-setup.exe %REMOTE_DIR%/downloads/netvis-setup.exe && sudo chown %SERVICE_USER%:%SERVICE_USER% %REMOTE_DIR%/downloads/netvis-setup.exe" || (echo [X] publishing the download failed & goto :fail)

REM ---- 9. verify -----------------------------------------------------------
echo(
echo Verifying...
curl -s https://netvis.cc/updates/windows/update.json
echo(
echo(
echo ===== DONE - version %VER% is live. =====
echo Clients pick it up within ~10s of launch, or via Settings ^> Check for updates.
goto :end

:sshhelp
echo(
echo Upload failed before anything shipped. Check SSH access:
echo(
echo   1. Can you connect at all?  Run this by hand:
echo         ssh !SERVER!
echo      - if it asks to confirm the host key, type "yes" once so it's saved.
echo      - if it says "Permission denied", your login/key is the problem, not scp.
echo   2. If ssh works but scp doesn't, it's usually the SFTP-vs-SCP protocol.
echo      This script already passes -O to force the classic protocol.
echo   3. A password prompt every time? Set up a key once so uploads are silent:
echo         ssh-keygen -t ed25519
echo         type %USERPROFILE%\.ssh\id_ed25519.pub ^| ssh !SERVER! "cat ^>^> ~/.ssh/authorized_keys"
echo(

:fail
echo(
echo Deploy FAILED. Nothing may have shipped - check the message above / build.log.
pause
exit /b 1

:end
echo(
pause
