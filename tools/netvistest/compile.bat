@echo off
REM Runs inside its own cmd.exe (invoked via "cmd /c" from build.bat) - see
REM the comment in the main project's compile.bat for why.
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64

cl.exe /nologo /EHsc /std:c++17 /O2 /MT ^
  netvistest.cpp ^
  /Fe:netvistest.exe ^
  /link wininet.lib iphlpapi.lib ws2_32.lib
