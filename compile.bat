@echo off
REM Runs inside its own cmd.exe (invoked via "cmd /c" from build_and_run.bat)
REM so that if vcvarsall.bat's internals do a bare `exit` instead of
REM `exit /b`, it only kills this nested process instead of aborting the
REM whole build script before cl.exe ever runs.
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64

if not exist obj mkdir obj

REM Remove the object of a since-deleted source, so it can't linger and be
REM linked by mistake.
del /f /q obj\tlsinspect.obj >nul 2>&1

REM Shared compile flags. /MP builds the translation units in parallel
REM across all CPU cores - the single biggest build-time win here.
set CFLAGS=/nologo /c /MP /EHsc /std:c++17 /O2 /DUNICODE /D_UNICODE /DNOMINMAX /DIMGUI_DISABLE_OBSOLETE_FUNCTIONS /I external\imgui /I external\imgui\backends /I src

REM --- Dear ImGui + backends: compiled ONCE and cached in obj\. -----------
REM imgui.cpp alone is ~18k lines; recompiling it every build was most of
REM the wait. These never change, so only build them if the objects are
REM missing. (Delete the obj\ folder to force a full clean rebuild, e.g.
REM after changing compiler flags or updating ImGui.)
if not exist obj\imgui.obj (
  echo Compiling Dear ImGui ^(first build only, this is the slow one^)...
  cl.exe %CFLAGS% /Fo:obj\ ^
    external\imgui\imgui.cpp external\imgui\imgui_draw.cpp external\imgui\imgui_tables.cpp external\imgui\imgui_widgets.cpp ^
    external\imgui\backends\imgui_impl_win32.cpp external\imgui\backends\imgui_impl_dx11.cpp
  if errorlevel 1 exit /b 1
)

REM --- netvis's own sources: recompiled every build, in parallel. --------
cl.exe %CFLAGS% /Fo:obj\ ^
  src\main.cpp src\monitor.cpp src\netmap.cpp src\procname.cpp src\windivert_shim.cpp ^
  src\blocker.cpp src\pidblock.cpp src\winicon.cpp src\icon_cache.cpp src\log.cpp src\connlist.cpp src\hostcache.cpp ^
  src\alerts.cpp src\settings.cpp src\blocklist_store.cpp src\startup.cpp src\license.cpp
if errorlevel 1 exit /b 1

REM Icon resource (embeds netvis.ico into the exe).
rc.exe /nologo /fo obj\netvis.res netvis.rc

REM --- Link everything. Fast, since there's no whole-program optimization.
link.exe /nologo /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup /OUT:netvis.exe ^
  obj\main.obj obj\monitor.obj obj\netmap.obj obj\procname.obj obj\windivert_shim.obj ^
  obj\blocker.obj obj\pidblock.obj obj\winicon.obj obj\icon_cache.obj obj\log.obj obj\connlist.obj obj\hostcache.obj ^
  obj\alerts.obj obj\settings.obj obj\blocklist_store.obj obj\startup.obj obj\license.obj ^
  obj\imgui.obj obj\imgui_draw.obj obj\imgui_tables.obj obj\imgui_widgets.obj ^
  obj\imgui_impl_win32.obj obj\imgui_impl_dx11.obj ^
  obj\netvis.res ^
  user32.lib gdi32.lib d3d11.lib dxgi.lib d3dcompiler.lib dwmapi.lib iphlpapi.lib psapi.lib shell32.lib ws2_32.lib comdlg32.lib ole32.lib oleaut32.lib taskschd.lib winhttp.lib advapi32.lib crypt32.lib
