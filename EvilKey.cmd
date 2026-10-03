@echo off
setlocal
cd /d "%~dp0"
:menu
echo EVILKEY firmware - see RELEASE_CURRENT.json
echo 6. Firmware software checks
echo 7. Build firmware BIN
echo 8. Package public source and accepted BIN
echo 11. Build and flash - choose COM port
echo Q. Exit
set "CHOICE="
set /p "CHOICE=Choice: " || exit /b 0
if /I "%CHOICE%"=="Q" exit /b 0
if "%CHOICE%"=="7" call scripts\commands\Build_firmware.cmd
if "%CHOICE%"=="11" call scripts\commands\Flash_firmware.cmd
if "%CHOICE%"=="6" py -3 scripts\firmware_checks.py
if "%CHOICE%"=="8" py -3 scripts\package_public_release.py
if not defined CHOICE exit /b 0
goto menu
