@echo off
setlocal
title UrielScan Launcher

echo ========================================================================
echo   Avvio di UrielScan (Next-Gen Purple Team Vulnerability Platform)
echo ========================================================================

:: Verifica Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Errore: Python non e installato o non si trova nel PATH.
    pause
    exit /b 1
)

:: Installazione dipendenze se necessario
echo [*] Verifica dipendenze Python...
python -m pip install -r requirements.txt --quiet

:: Controllo frontend build
if exist "frontend\package.json" (
    if not exist "frontend\dist\index.html" (
        echo [*] Compilazione frontend in corso...
        pushd frontend
        call npm install
        call npm run build
        popd
    )
)

echo [*] Avvio applicazione UrielScan...
python run.py %*

pause
