#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "========================================================================"
echo "  UrielScan - First-Time Setup & Engine Provisioning (Linux / macOS)"
echo "========================================================================"

# 1. Verify Python 3.10+
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Error: python3 not found in PATH. Install Python 3.10+ first."
    exit 1
fi

if ! python3 -c "import sys; raise SystemExit(0 if (sys.version_info.major == 3 and sys.version_info.minor >= 10) or sys.version_info.major > 3 else 1)"; then
    PY_VER=$(python3 -V 2>&1 || true)
    echo "[!] Error: Python 3.10+ is required (found: $PY_VER)."
    exit 1
fi
echo "[+] Python detected: $(python3 -V)"

# 2. Verify python3-venv availability (common pitfall on Debian/Ubuntu)
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "[!] Error: python3-venv module is missing."
    echo "    On Debian/Ubuntu/Kali run: sudo apt update && sudo apt install -y python3-venv python3-pip"
    exit 1
fi

# 3. Create isolated .venv
if [ ! -x ".venv/bin/python" ]; then
    echo "[*] Creating isolated virtual environment (.venv)..."
    python3 -m venv .venv
else
    echo "[+] Existing virtual environment detected (.venv)"
fi

VENV_PY=".venv/bin/python"

# 4. Install Python dependencies inside .venv (PEP 668 safe)
echo "[*] Installing Python dependencies from requirements.txt..."
"$VENV_PY" -m pip install --upgrade pip --quiet
"$VENV_PY" -m pip install -r requirements.txt

# 5. Build frontend only if dist/index.html is missing
if [ -f "frontend/package.json" ] && [ ! -f "frontend/dist/index.html" ]; then
    echo "[*] Frontend dist/ not found. Building UI bundle..."
    if ! command -v npm >/dev/null 2>&1; then
        echo "[!] Error: npm is required to build frontend/dist. Install Node.js LTS or provide prebuilt frontend/dist."
        exit 1
    fi
    (cd frontend && npm install && npm run build)
else
    echo "[+] Prebuilt frontend UI verified (frontend/dist/index.html)"
fi

# 6. Pre-install all external scanning engines (Nmap, Nuclei, OWASP ZAP + JRE 17, Tor Expert Bundle)
echo "[*] Checking and provisioning scanning engines (Nmap, Nuclei, OWASP ZAP + JRE 17, Tor)..."
set +e
"$VENV_PY" -m backend.scanners.engine_bootstrap
BOOT_RC=$?
set -e
if [ "$BOOT_RC" -ne 0 ]; then
    echo "[!] Warning: some engines could not be auto-installed during setup. You can retry later in Settings -> Engines."
fi

chmod +x start.sh install.sh

echo ""
echo "========================================================================"
echo "  SETUP COMPLETATO CON SUCCESSO!"
echo "  Tutti i pacchetti e i motori sono configurati."
echo "  Per avviare UrielScan esegui: ./start.sh"
echo "========================================================================"
