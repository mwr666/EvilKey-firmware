@echo off
setlocal
cd /d "%~dp0\..\.."
where py >nul 2>nul
if not errorlevel 1 (
  py -3 firmware\flash_arduino.py
) else (
  python firmware\flash_arduino.py
)
set "CODE=%ERRORLEVEL%"
if not "%CODE%"=="0" echo Firmware upload failed or was interrupted.
pause
exit /b %CODE%
