@echo off
REM ==========================================================================
REM sign.bat <file>   - code-sign one file with SignTool.
REM
REM Built for the Certum Individual Cloud code signing certificate:
REM   - the private key lives in Certum's cloud, reached through SimplySign
REM     Desktop, which presents the certificate to Windows as a virtual smart
REM     card. So SignTool signs by the certificate's SHA-1 thumbprint exactly
REM     as it would for any cert in the Personal store - no .pfx file exists,
REM     and none can be exported.
REM   - the timestamp server is Certum's RFC3161 endpoint.
REM
REM Before signing, once per work session:
REM   1. Open SimplySign Desktop and log in (needs the SimplySign phone app
REM      for the one-time code). The session lasts two hours.
REM   2. Set the thumbprint of your certificate, e.g. in this shell:
REM        set NETVIS_SIGN_SHA1=A1B2C3...    (Certificate -> Details -> Thumbprint,
REM                                           spaces removed)
REM   You can find the thumbprint with:  certutil -user -store My
REM
REM Deliberately a NO-OP that returns success when NETVIS_SIGN_SHA1 is not
REM set, so the build keeps working in the days before the certificate is
REM issued, and on any machine that isn't the signing one.
REM ==========================================================================
REM Delayed expansion is required below: the SDK lives under
REM "Program Files (x86)", whose literal parentheses would otherwise close the
REM for/if blocks early when the path is expanded at parse time. Referencing
REM it as !var! defers expansion to run time, where the parentheses are inert.
setlocal enabledelayedexpansion

if "%~1"=="" (
  echo sign.bat: no file given
  exit /b 2
)

if not defined NETVIS_SIGN_SHA1 (
  echo   [sign] NETVIS_SIGN_SHA1 not set - skipping "%~nx1" ^(will be unsigned^)
  exit /b 0
)

REM Certum's timestamp server unless the caller overrode it.
if not defined NETVIS_TIMESTAMP set "NETVIS_TIMESTAMP=http://time.certum.pl"

REM Locate signtool.exe. It ships in the Windows SDK, under a versioned
REM folder; take the newest. dir /o:-n sorts the version folders descending,
REM so the first hit is the latest installed SDK. The SDK bin path is stored
REM in WK and only ever referenced as !WK! (see the delayed-expansion note).
set "WK=%ProgramFiles(x86)%\Windows Kits\10\bin"
set "SIGNTOOL="
for /f "delims=" %%D in ('dir /b /a:d /o:-n "!WK!" 2^>nul') do (
  if not defined SIGNTOOL if exist "!WK!\%%D\x64\signtool.exe" (
    set "SIGNTOOL=!WK!\%%D\x64\signtool.exe"
  )
)
if not defined SIGNTOOL if exist "!WK!\x64\signtool.exe" set "SIGNTOOL=!WK!\x64\signtool.exe"
if not defined SIGNTOOL (
  echo   [sign] ERROR: signtool.exe not found. Install the Windows 10/11 SDK
  echo          ^(the "Windows SDK Signing Tools" component is enough^).
  exit /b 1
)

echo   [sign] signing "%~nx1"
REM /fd + /td SHA256 : hash the file and the timestamp with SHA-256, which is
REM                    what current signing policy requires.
REM /tr             : RFC3161 timestamp, so the signature stays valid after the
REM                    certificate itself expires.
REM If SignTool can't find the cloud key by thumbprint alone on your machine,
REM Certum's documented fallback is to name their CSP and key container:
REM   ... /csp "Certum SimplySign CSP" /kc "<container name from SimplySign>"
REM but with an active SimplySign Desktop session the /sha1 form below normally
REM just works, because the certificate is present in the Personal store.
"%SIGNTOOL%" sign /sha1 %NETVIS_SIGN_SHA1% /fd SHA256 /tr %NETVIS_TIMESTAMP% /td SHA256 "%~1"
if errorlevel 1 (
  echo   [sign] ERROR: signing failed. Is SimplySign Desktop open and logged in,
  echo          and is NETVIS_SIGN_SHA1 the right thumbprint?
  exit /b 1
)

REM Prove it: /pa uses the Authenticode policy an end user's machine applies.
"%SIGNTOOL%" verify /pa /v "%~1" >nul
if errorlevel 1 (
  echo   [sign] ERROR: the file signed but did not verify.
  exit /b 1
)
echo   [sign] OK - "%~nx1" is signed and verified
exit /b 0
