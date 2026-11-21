@echo off
setlocal
cd /d "%~dp0"
title UrielScan Launcher

echo ========================================================================
echo   Avvio di UrielScan (Next-Gen Purple Team Vulnerability Platform)
echo ========================================================================

set "PY_BIN="
if exist ".venv\Scripts\python.exe" (
    set "PY_BIN=.venv\Scripts\python.exe"
    echo [+] Ambiente virtuale .venv attivo.
) else (
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [!] Errore: Python non e installato o non si trova nel PATH.
        echo [i] Esegui install.bat per completare la prima installazione.
        pause
        exit /b 1
    )
    set "PY_BIN=python"
    echo [i] .venv non trovato ^(consigliato: esegui install.bat la prima volta^).
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
)

:: Controllo frontend build
if exist "frontend\package.json" (
    if not exist "frontend\dist\index.html" (
        echo [*] Compilazione frontend in corso...
        pushd frontend
        call npm install && call npm run build
        popd
    )
)

echo [*] Avvio applicazione UrielScan...
"%PY_BIN%" run.py %*

pause
