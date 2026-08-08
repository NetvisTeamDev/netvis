@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM ============================================================
REM test_netvis.bat - build + smoke-test netvis and its tools.
REM
REM What this actually covers:
REM   - required runtime files are present (WinDivert, blocklist,
REM     the system fonts the UI loads)
REM   - blocklist.txt isn't empty/truncated
REM   - netvis.exe (and tools\trafficgen\trafficgen.exe) build with
REM     no compiler errors
REM   - a real elevated run of netvis.exe: does WinDivert actually
REM     open, does the monitor start capturing, does the blocker
REM     load its lists, are there any "failed" lines in netvis.log
REM   - trafficgen.exe launches and stays running
REM
REM What it can't do from a .bat file: click buttons, verify the
REM ad-blocker score on a real site, confirm Block actually cuts a
REM process's internet, etc. That needs a human - see the checklist
REM printed at the end.
REM ============================================================

set PASS=0
set FAIL=0
set WARN=0

REM WinDivert (and so most of what's tested here) requires Administrator -
REM re-launch elevated so this is actually testing the real code path
REM instead of immediately hitting "run as Administrator" everywhere.
net session >nul 2>&1
if errorlevel 1 (
    echo Not elevated - relaunching as Administrator...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b
)

echo ============================================
echo  netvis test suite
echo ============================================
echo.

echo --- required files ---
call :check_file "WinDivert.dll present" "WinDivert.dll"
call :check_file "WinDivert64.sys present" "WinDivert64.sys"
call :check_file "blocklist.txt present" "blocklist.txt"
call :check_file "Segoe UI (segoeui.ttf) present" "C:\Windows\Fonts\segoeui.ttf"
call :check_file "Segoe UI Bold (segoeuib.ttf) present" "C:\Windows\Fonts\segoeuib.ttf"

echo.
echo --- blocklist sanity ---
if exist blocklist.txt (
    for /f %%A in ('find /c /v "" ^< blocklist.txt') do set BLCOUNT=%%A
    if !BLCOUNT! GTR 1000 (
        call :pass "blocklist.txt has !BLCOUNT! lines"
    ) else (
        call :fail "blocklist.txt only has !BLCOUNT! lines - expected 1000+"
    )
) else (
    call :fail "blocklist.txt missing, skipped line-count check"
)

echo.
echo --- build: netvis.exe ---
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSPATH=%%i
if not defined VSPATH (
    call :fail "Visual Studio C++ toolchain not found (vswhere returned nothing)"
) else (
    del /f /q build.log >nul 2>&1
    set "VSPATH=%VSPATH%"
    cmd /c compile.bat >> build.log 2>&1
    findstr /I /C:"error" build.log >nul
    if errorlevel 1 (
        if exist netvis.exe (
            call :pass "netvis.exe built with no compiler errors"
        ) else (
            call :fail "build.log has no 'error' but netvis.exe wasn't produced - check build.log"
        )
    ) else (
        call :fail "build.log contains errors - see build.log"
    )
)

echo.
echo --- build: tools\trafficgen\trafficgen.exe ---
if exist tools\trafficgen\compile.bat (
    pushd tools\trafficgen
    del /f /q build.log >nul 2>&1
    set "VSPATH=%VSPATH%"
    cmd /c compile.bat >> build.log 2>&1
    findstr /I /C:"error" build.log >nul
    if errorlevel 1 (
        if exist trafficgen.exe (
            call :pass "trafficgen.exe built with no compiler errors"
        ) else (
            call :fail "tools\trafficgen\build.log has no 'error' but trafficgen.exe wasn't produced"
        )
    ) else (
        call :fail "tools\trafficgen\build.log contains errors - see tools\trafficgen\build.log"
    )
    popd
) else (
    call :warn "tools\trafficgen\compile.bat not found, skipped"
)

echo.
echo --- runtime smoke test: netvis.exe ---
if exist netvis.exe (
    taskkill /IM netvis.exe /F >nul 2>&1
    del /f /q netvis.log >nul 2>&1
    start "" netvis.exe
    timeout /t 5 /nobreak >nul
    taskkill /IM netvis.exe /F >nul 2>&1
    timeout /t 1 /nobreak >nul

    if exist netvis.log (
        findstr /C:"netvis starting" netvis.log >nul
        if errorlevel 1 (call :fail "netvis.log: no startup line found") else (call :pass "netvis.log: startup logged")

        findstr /C:"monitor: capture started" netvis.log >nul
        if errorlevel 1 (call :fail "monitor: capture did not start - check Administrator elevation") else (call :pass "monitor: WinDivert capture opened")

        findstr /C:"blocker: started" netvis.log >nul
        if errorlevel 1 (call :fail "blocker: did not start") else (call :pass "blocker: started and loaded its lists")

        findstr /C:"WinDivertOpen" netvis.log ^| findstr /C:"failed" >nul
        if errorlevel 1 (call :pass "no WinDivertOpen failures logged") else (call :fail "WinDivertOpen failure logged - see netvis.log")
    ) else (
        call :fail "netvis.log was not created - netvis.exe may have failed to launch"
    )
) else (
    call :fail "netvis.exe not found, skipped runtime smoke test"
)

echo.
echo --- runtime smoke test: trafficgen.exe ---
if exist tools\trafficgen\trafficgen.exe (
    taskkill /IM trafficgen.exe /F >nul 2>&1
    start "" tools\trafficgen\trafficgen.exe
    timeout /t 2 /nobreak >nul
    tasklist /FI "IMAGENAME eq trafficgen.exe" ^| findstr /I "trafficgen.exe" >nul
    if errorlevel 1 (
        call :fail "trafficgen.exe exited immediately - should stay running and burst every 5s"
    ) else (
        call :pass "trafficgen.exe launched and is still running"
    )
    taskkill /IM trafficgen.exe /F >nul 2>&1
) else (
    call :warn "tools\trafficgen\trafficgen.exe not built, skipped"
)

echo.
echo ============================================
echo  Results: !PASS! passed, !FAIL! failed, !WARN! warned
echo ============================================
if !FAIL! GTR 0 (
    echo.
    echo Some checks failed - see above, plus build.log / netvis.log for detail.
)

echo.
echo ============================================
echo  Manual checklist (needs a human, not covered above)
echo ============================================
echo   [ ] Block a process -^> button flips to Unblock, its traffic stops
echo   [ ] Unblock -^> button flips back, traffic resumes
echo   [ ] Right-click a row -^> Open file location works
echo   [ ] Right-click a row -^> View connections shows real IP:port rows
echo   [ ] Right-click a row -^> Limit traffic actually caps its speed
echo   [ ] Click each table header -^> sort order changes correctly
echo   [ ] Toggle "Ad blocker enabled" -^> blocking actually stops/resumes
echo   [ ] Toggle "Auto-block high-traffic processes" -^> trafficgen.exe
echo       gets auto-blocked on its next burst
echo   [ ] Text in the table / connections view can be selected + copied
echo   [ ] Ad blocker score on your usual test site matches expectations
echo.

if !FAIL! GTR 0 exit /b 1
exit /b 0

:pass
set /a PASS+=1
echo [PASS] %~1
goto :eof

:fail
set /a FAIL+=1
echo [FAIL] %~1
goto :eof

:warn
set /a WARN+=1
echo [WARN] %~1
goto :eof

:check_file
if exist %2 (
    call :pass %1
) else (
    call :fail "%~1 - missing: %~2"
)
goto :eof
