@echo off
setlocal
title UrielScan - First-Time Installer

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "EXIT_CODE=%errorlevel%"

echo.
pause
exit /b %EXIT_CODE%
