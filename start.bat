@echo off
setlocal
cd /d "%~dp0"
title UrielScan Launcher

if /i "%~1"=="--console" goto :console_mode

set "PY_BIN="
set "PYW_BIN="

if exist ".venv\Scripts\python.exe" (
    set "PY_BIN=.venv\Scripts\python.exe"
    if exist ".venv\Scripts\pythonw.exe" set "PYW_BIN=.venv\Scripts\pythonw.exe"
) else (
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [!] Errore: Python non e installato o non si trova nel PATH.
        echo [i] Esegui install.bat per completare la prima installazione.
        pause
        exit /b 1
    )
    set "PY_BIN=python"
    python -c "import fastapi, uvicorn, socksio" >nul 2>&1
    if %errorlevel% neq 0 (
        echo [*] Dipendenze mancanti: installazione da requirements.txt...
        python -m pip install -r requirements.txt --quiet
        if %errorlevel% neq 0 (
            echo [!] Installazione dipendenze fallita.
            pause
            exit /b 1
        )
    )
    for /f "delims=" %%p in ('where pythonw 2^>nul') do (
        if not defined PYW_BIN set "PYW_BIN=%%p"
    )
)

:: Controllo frontend build (eseguito a schermo solo se mancante)
if exist "frontend\package.json" (
    if not exist "frontend\dist\index.html" (
        echo [*] Compilazione frontend in corso...
        pushd frontend
        call npm install && call npm run build
        popd
    )
)

if defined PYW_BIN (
    start "" "%PYW_BIN%" run.py %*
    exit /b 0
)

:: Fallback se pythonw.exe non fosse disponibile sul sistema
"%PY_BIN%" run.py %*
pause
exit /b %errorlevel%

:console_mode
shift
if exist ".venv\Scripts\python.exe" (
    set "PY_BIN=.venv\Scripts\python.exe"
) else (
    set "PY_BIN=python"
)
echo [*] Avvio UrielScan in modalita console...
"%PY_BIN%" run.py %1 %2 %3 %4 %5 %6 %7 %8 %9
pause
