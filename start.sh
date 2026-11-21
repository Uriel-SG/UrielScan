#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "========================================================================"
echo "   Avvio di UrielScan (Next-Gen Purple Team Vulnerability Platform)"
echo "========================================================================"

if [ -x ".venv/bin/python" ]; then
    PY_BIN=".venv/bin/python"
    echo "[+] Ambiente virtuale .venv attivo."
else
    if ! command -v python3 >/dev/null 2>&1; then
        echo "[!] Errore: python3 non e installato o non si trova nel PATH."
        echo "[i] Esegui ./install.sh per completare la prima installazione."
        exit 1
    fi
    PY_BIN="python3"
    echo "[i] .venv non trovato (consigliato: esegui ./install.sh la prima volta)."
    if ! "$PY_BIN" -c "import fastapi, uvicorn, socksio" >/dev/null 2>&1; then
        echo "[*] Dipendenze mancanti: installazione da requirements.txt..."
        "$PY_BIN" -m pip install -r requirements.txt --quiet
    fi
fi

# Controllo frontend build
if [ -f "frontend/package.json" ] && [ ! -f "frontend/dist/index.html" ]; then
    echo "[*] Compilazione frontend in corso..."
    (cd frontend && npm install && npm run build)
fi

echo "[*] Avvio applicazione UrielScan..."
exec "$PY_BIN" run.py "$@"
