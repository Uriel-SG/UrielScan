#!/usr/bin/env bash
set -e

echo "========================================================================"
echo "   Avvio di UrielScan (Next-Gen Purple Team Vulnerability Platform)"
echo "========================================================================"

# Verifica Python 3
if ! command -v python3 &> /dev/null; then
    echo "[!] Errore: python3 non è installato o non si trova nel PATH."
    exit 1
fi

echo "[*] Verifica dipendenze Python..."
python3 -m pip install -r requirements.txt --quiet

# Controllo frontend build
if [ -f "frontend/package.json" ] && [ ! -f "frontend/dist/index.html" ]; then
    echo "[*] Compilazione frontend in corso..."
    cd frontend
    npm install
    npm run build
    cd ..
fi

echo "[*] Avvio applicazione UrielScan..."
python3 run.py "$@"
