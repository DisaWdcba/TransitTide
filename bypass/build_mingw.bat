@echo off
set PATH=D:\mingw64\bin;%PATH%
cd /d "%~dp0"
g++ -O2 -m64 -municode -static -o bypass_mingw.exe main.cpp -luser32
if errorlevel 1 (
  echo [ERROR] mingw build failed
  exit /b 1
)
echo [OK] built bypass_mingw.exe
D:\mingw64\bin\objdump.exe -h bypass_mingw.exe | findstr /i "pay stb pdata text"
