@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /O2 /EHsc main.cpp /Fe:bypass.exe /link /SUBSYSTEM:CONSOLE user32.lib
if errorlevel 1 (
  echo [ERROR] bypass.exe build failed
  exit /b 1
)
rem #pragma code_seg forces RX on code sections, so set .pay RWX post-link:
editbin /SECTION:.pay,WE bypass.exe >nul 2>&1
echo [OK] built bypass.exe (integrated single-file, .pay=RXW via editbin)
