@echo off
REM Runs inside its own cmd.exe (invoked via "cmd /c" from build_and_run.bat)
REM so that if vcvarsall.bat's internals do a bare `exit` instead of
REM `exit /b`, it only kills this nested process instead of aborting the
REM whole build script before cl.exe ever runs.
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64

if not exist obj mkdir obj

REM Compile the icon resource (embeds netvis.ico into the exe). rc.exe
REM comes from the Windows SDK, which vcvarsall.bat above puts on PATH.
rc.exe /nologo /fo obj\netvis.res netvis.rc

cl.exe /nologo /EHsc /std:c++17 /O2 /DUNICODE /D_UNICODE /DNOMINMAX /DIMGUI_DISABLE_OBSOLETE_FUNCTIONS ^
  /I external\imgui /I external\imgui\backends /I src ^
  src\main.cpp src\monitor.cpp src\netmap.cpp src\procname.cpp src\windivert_shim.cpp ^
  src\blocker.cpp src\pidblock.cpp src\winicon.cpp src\icon_cache.cpp src\log.cpp src\connlist.cpp src\hostcache.cpp ^
  src\alerts.cpp src\settings.cpp ^
  external\imgui\imgui.cpp external\imgui\imgui_draw.cpp external\imgui\imgui_tables.cpp external\imgui\imgui_widgets.cpp ^
  external\imgui\backends\imgui_impl_win32.cpp external\imgui\backends\imgui_impl_dx11.cpp ^
  obj\netvis.res ^
  /Fe:netvis.exe /Fo:obj\ ^
  /link /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
  user32.lib gdi32.lib d3d11.lib dxgi.lib d3dcompiler.lib dwmapi.lib iphlpapi.lib psapi.lib shell32.lib ws2_32.lib
