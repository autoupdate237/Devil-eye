@echo off
REM ============================================================
REM  Devil's Eye - one-click Windows EXE build
REM  Output: dist\DevilsEye.exe   (single-file executable)
REM ============================================================
setlocal

REM Force UTF-8 stdio — PyInstaller's Unicode output crashes on cp1252
REM consoles when redirected, and this keeps the build deterministic.
set PYTHONUTF8=1

where py >nul 2>nul
if %ERRORLEVEL%==0 (set "PY=py -3") else (set "PY=python")

echo [1/3] Ensuring PyInstaller is available...
%PY% -m pip install --quiet --upgrade pip pyinstaller
if errorlevel 1 goto :fail

echo [2/3] Building DevilsEye.exe ...
%PY% "%~dp0build_exe.py" --onefile
if errorlevel 1 goto :fail

echo [3/3] Done.
echo.
echo   Output: %~dp0..\dist\DevilsEye.exe
echo.
pause
exit /b 0

:fail
echo.
echo BUILD FAILED - see messages above.
pause
exit /b 1
