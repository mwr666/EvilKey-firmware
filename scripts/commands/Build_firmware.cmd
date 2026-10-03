@echo off
setlocal
cd /d "%~dp0\..\.."
where py >nul 2>nul
if not errorlevel 1 (
  py -3 firmware\build_arduino.py
) else (
  python firmware\build_arduino.py
)
set "CODE=%ERRORLEVEL%"
if not "%CODE%"=="0" echo Firmware build failed. Read the message above.
pause
exit /b %CODE%
