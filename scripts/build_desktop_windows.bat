@echo off
setlocal

rem Resolve repo root (absolute)
for %%I in ("%~dp0..") do set "ROOT=%%~fI"

rem Find MSYS2
set "MSYS2=%MSYS2_DIR%"
if not defined MSYS2 set "MSYS2=C:\msys64"

set "BASH=%MSYS2%\usr\bin\bash.exe"
if not exist "%BASH%" (
  echo Error: MSYS2 bash not found at "%BASH%".
  echo Install MSYS2 (mingw64) or set MSYS2_DIR.
  exit /b 1
)

rem Ensure mingw64 toolchain is on PATH
set "PATH=%MSYS2%\mingw64\bin;%MSYS2%\usr\bin;%PATH%"

rem Forward PQRYPT_CLEAN if provided
set "CLEAN=%PQRYPT_CLEAN%"
if not defined CLEAN set "CLEAN=0"

rem Convert script path to forward slashes for bash
set "SH=%ROOT%\scripts\build_desktop.sh"
set "SH=%SH:\=/%"

"%BASH%" -lc "PQRYPT_CLEAN=%CLEAN% bash '%SH%'"
if errorlevel 1 exit /b %errorlevel%

endlocal
