@echo off
REM Runs inside its own cmd.exe (invoked via "cmd /c" from build.bat) - see
REM the comment in the main project's compile.bat for why.
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64

cl.exe /nologo /EHsc /std:c++17 /O2 ^
  trafficgen.cpp ^
  /Fe:trafficgen.exe ^
  /link wininet.lib
