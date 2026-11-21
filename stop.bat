@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title UrielScan Stop

set "STOPPED=0"

if exist "data\urielscan.pid" (
    set /p PID=<"data\urielscan.pid"
    if defined PID (
        echo [*] Arresto processo UrielScan (PID !PID!)...
        taskkill /PID !PID! /T /F >nul 2>&1
        if !errorlevel! equ 0 set "STOPPED=1"
    )
    del /f /q "data\urielscan.pid" >nul 2>&1
)

if "!STOPPED!"=="0" (
    for /f "tokens=5" %%a in ('netstat -ano -p tcp 2^>nul ^| findstr /r /c:":8000 .*LISTENING"') do (
        echo [*] Arresto processo in ascolto sulla porta 8000 (PID %%a)...
        taskkill /PID %%a /T /F >nul 2>&1
        if !errorlevel! equ 0 set "STOPPED=1"
    )
)

if "!STOPPED!"=="1" (
    echo [+] UrielScan arrestato correttamente.
) else (
    echo [i] Nessun processo UrielScan attivo trovato.
)

timeout /t 2 >nul
exit /b 0
