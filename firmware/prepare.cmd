@echo off
setlocal
cd /d "%~dp0"
where git >nul 2>nul
if errorlevel 1 (
  echo Git was not found. Install Git for Windows and reopen this window.
  pause
  exit /b 1
)
where py >nul 2>nul
if not errorlevel 1 (
  py -3 prepare_arduino.py
) else (
  python prepare_arduino.py
)
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo Preparation failed. Read the error above; no board was flashed.
) else (
  echo Open EvilKeyV1\EvilKeyV1.ino in Arduino IDE.
)
pause
exit /b %RC%
