@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /O2 /EHsc /std:c++latest /I sleep_duck_eye\sleep_duck /I sleep_duck_eye\sleep_duck\include sleep_duck_eye\sleep_duck\sleep_duck.cpp sleep_duck_eye\sleep_duck\stack_tracker.cpp sleep_duck_eye\sleep_duck\tools.cpp /link /LIBPATH:sleep_duck_eye\sleep_duck\libs advapi32.lib /out:sleep_duck.exe
