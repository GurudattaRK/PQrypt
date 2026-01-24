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

rem Ensure ANDROID_NDK_HOME is set (required on Windows)
if "%ANDROID_NDK_HOME%"=="" (
  echo Error: ANDROID_NDK_HOME is not set.
  echo Set ANDROID_NDK_HOME to your Android NDK path and retry.
  exit /b 1
)

rem Help adb discovery if ANDROID_SDK_ROOT/ANDROID_HOME is set
if not "%ANDROID_SDK_ROOT%"=="" (
  if exist "%ANDROID_SDK_ROOT%\platform-tools\adb.exe" set "PATH=%ANDROID_SDK_ROOT%\platform-tools;%PATH%"
)
if not "%ANDROID_HOME%"=="" (
  if exist "%ANDROID_HOME%\platform-tools\adb.exe" set "PATH=%ANDROID_HOME%\platform-tools;%PATH%"
)

rem Forward PQRYPT_CLEAN if provided
set "CLEAN=%PQRYPT_CLEAN%"
if not defined CLEAN set "CLEAN=0"

rem Convert script path to forward slashes for bash
set "SH=%ROOT%\scripts\build_android.sh"
set "SH=%SH:\=/%"

rem Convert ANDROID_NDK_HOME to forward slashes for bash path checks
set "NDK=%ANDROID_NDK_HOME%"
set "NDK=%NDK:\=/%"

"%BASH%" -lc "export ANDROID_NDK_HOME='%NDK%' && PQRYPT_CLEAN=%CLEAN% bash '%SH%'"
if errorlevel 1 exit /b %errorlevel%

endlocal
