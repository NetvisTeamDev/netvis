@echo off
REM Runs inside its own cmd.exe (invoked via "cmd /c" from build_and_run.bat)
REM so that if vcvarsall.bat's internals do a bare `exit` instead of
REM `exit /b`, it only kills this nested process instead of aborting the
REM whole build script before cl.exe ever runs.
setlocal enabledelayedexpansion
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64

if not exist obj mkdir obj

REM Remove the object of a since-deleted source, so it can't linger and be
REM linked by mistake.
del /f /q obj\tlsinspect.obj >nul 2>&1

REM --- optimisation level -------------------------------------------------
REM Release builds optimise (/O2). For fast iteration set NETVIS_FAST=1 before
REM building: /Od skips optimisation, so the compiler does far less work per
REM file - the exe runs a bit slower but builds noticeably faster. A normal
REM build (no NETVIS_FAST) stays on /O2, which is what release ships.
set "OPT=/O2"
set "MODE=release"
if /I "%NETVIS_FAST%"=="1" (
  set "OPT=/Od"
  set "MODE=fast"
  echo FAST dev build: /Od, no optimisation.
)

REM If the mode changed since last time, wipe ALL cached objects - including
REM ImGui's - and rebuild from scratch at the new level. Without this a
REM release /O2 build would silently reuse /Od objects left by a previous fast
REM build (or vice versa), shipping unoptimised code.
set "MARK=obj\buildmode.txt"
set "LASTMODE="
if exist "%MARK%" set /p LASTMODE=<"%MARK%"
if not "%LASTMODE%"=="%MODE%" (
  echo Build mode is now "%MODE%" ^(was "%LASTMODE%"^) - clean rebuild.
  del /f /q obj\*.obj >nul 2>&1
)
> "%MARK%" echo %MODE%

REM Shared compile flags. /MP builds the translation units in parallel across
REM all CPU cores - the single biggest build-time win here.
set CFLAGS=/nologo /c /MP /EHsc /std:c++17 %OPT% /DUNICODE /D_UNICODE /DNOMINMAX /DIMGUI_DISABLE_OBSOLETE_FUNCTIONS /I external\imgui /I external\imgui\backends /I src

REM --- Dear ImGui + backends: compiled ONCE and cached in obj\. -----------
REM imgui.cpp alone is ~18k lines; recompiling it every build was most of the
REM wait. These never change, so only build them if the objects are missing.
REM (Delete the obj\ folder to force a full clean rebuild, e.g. after changing
REM compiler flags or updating ImGui.)
if not exist obj\imgui.obj (
  echo Compiling Dear ImGui ^(first build only, this is the slow one^)...
  cl.exe %CFLAGS% /Fo:obj\ ^
    external\imgui\imgui.cpp external\imgui\imgui_draw.cpp external\imgui\imgui_tables.cpp external\imgui\imgui_widgets.cpp ^
    external\imgui\backends\imgui_impl_win32.cpp external\imgui\backends\imgui_impl_dx11.cpp
  if errorlevel 1 exit /b 1
)

REM --- netvis's own sources: incremental. --------------------------------
REM Only recompile a .cpp when its .obj is missing or out of date. "Out of
REM date" also counts any header in src\ being newer than the .obj - a blunt
REM but safe rule: touch a header and everything that could depend on it
REM rebuilds, so a changed struct can never leave a stale object behind. Edit
REM just one .cpp and only that one compiles.
REM
REM One PowerShell call computes the whole list (correct timestamp handling,
REM which pure batch does badly). It prints the sources that need building,
REM relative to here.
set "TOBUILD="
for /f "usebackq delims=" %%F in (`powershell -NoProfile -Command "$h=(Get-ChildItem src\*.h -EA SilentlyContinue|Measure-Object LastWriteTime -Maximum).Maximum; Get-ChildItem src\*.cpp|Where-Object{$o='obj\'+$_.BaseName+'.obj'; (-not(Test-Path $o))-or($_.LastWriteTime -gt (Get-Item $o).LastWriteTime)-or($h -and $h -gt (Get-Item $o).LastWriteTime)}|ForEach-Object{'src\'+$_.Name}"`) do (
  set "TOBUILD=!TOBUILD! %%F"
)

if not defined TOBUILD (
  echo No source changes - reusing cached objects.
) else (
  echo Compiling:!TOBUILD!
  cl.exe %CFLAGS% /Fo:obj\ !TOBUILD!
  if errorlevel 1 exit /b 1
)

REM Icon resource (embeds netvis.ico into the exe). Rebuilt only if missing or
REM the .rc/.ico changed.
if not exist obj\netvis.res (
  rc.exe /nologo /fo obj\netvis.res netvis.rc
) else (
  for /f "usebackq delims=" %%R in (`powershell -NoProfile -Command "if((Get-Item netvis.rc).LastWriteTime -gt (Get-Item obj\netvis.res).LastWriteTime -or (Test-Path netvis.ico) -and (Get-Item netvis.ico).LastWriteTime -gt (Get-Item obj\netvis.res).LastWriteTime){'stale'}"`) do (
    rc.exe /nologo /fo obj\netvis.res netvis.rc
  )
)

REM --- Link everything. Fast, since there's no whole-program optimization.
REM /MANIFEST:NO - the manifest comes from netvis.rc. Without this the linker
REM generates its own as well and the two collide.
link.exe /nologo /MANIFEST:NO /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup /OUT:netvis.exe ^
  obj\main.obj obj\monitor.obj obj\netmap.obj obj\procname.obj obj\windivert_shim.obj ^
  obj\blocker.obj obj\pidblock.obj obj\winicon.obj obj\icon_cache.obj obj\log.obj obj\connlist.obj obj\hostcache.obj ^
  obj\alerts.obj obj\settings.obj obj\blocklist_store.obj obj\startup.obj obj\license.obj obj\conn_kill.obj obj\ipban.obj obj\updater.obj ^
  obj\imgui.obj obj\imgui_draw.obj obj\imgui_tables.obj obj\imgui_widgets.obj ^
  obj\imgui_impl_win32.obj obj\imgui_impl_dx11.obj ^
  obj\netvis.res ^
  user32.lib gdi32.lib d3d11.lib dxgi.lib d3dcompiler.lib dwmapi.lib iphlpapi.lib psapi.lib shell32.lib ws2_32.lib comdlg32.lib ole32.lib oleaut32.lib taskschd.lib winhttp.lib advapi32.lib crypt32.lib bcrypt.lib
