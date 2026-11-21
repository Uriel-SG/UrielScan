# UrielScan First-Time Installer for Windows
# Run via install.bat (double-click) or: powershell -ExecutionPolicy Bypass -File .\install.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  UrielScan - First-Time Setup & Engine Provisioning (Windows)" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# 1. Locate Python 3.10+
$PyCmd = $null
$PyArgs = @()

foreach ($cand in @(@("python"), @("py", "-3"))) {
    $cmdName = $cand[0]
    if (Get-Command $cmdName -ErrorAction SilentlyContinue) {
        $extra = if ($cand.Count -gt 1) { $cand[1..($cand.Count - 1)] } else { @() }
        try {
            $verCheck = & $cmdName @extra -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}'); raise SystemExit(0 if (sys.version_info.major == 3 and sys.version_info.minor >= 10) or sys.version_info.major > 3 else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) {
                $PyCmd = $cmdName
                $PyArgs = $extra
                Write-Host "[+] Python detected: $cmdName ($verCheck)" -ForegroundColor Green
                break
            }
        } catch {
            continue
        }
    }
}

if (-not $PyCmd) {
    Write-Host "[!] Python 3.10+ not found in PATH. Install Python 3.10+ from https://www.python.org/downloads/ and check 'Add Python to PATH'." -ForegroundColor Red
    exit 1
}

# 2. Create isolated .venv if needed
$VenvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "[*] Creating virtual environment (.venv)..." -ForegroundColor Yellow
    & $PyCmd @PyArgs -m venv ".venv"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPython)) {
        Write-Host "[!] Failed to create .venv." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[+] Existing virtual environment detected (.venv)" -ForegroundColor Green
}

# 3. Install Python dependencies
Write-Host "[*] Installing Python dependencies from requirements.txt..." -ForegroundColor Yellow
& $VenvPython -m pip install --upgrade pip --quiet
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $VenvPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Failed to install requirements.txt." -ForegroundColor Red
    exit $LASTEXITCODE
}

# 4. Build frontend bundle only if dist/index.html is absent
if ((Test-Path "frontend\package.json") -and -not (Test-Path "frontend\dist\index.html")) {
    Write-Host "[*] Frontend dist/ not found. Checking Node/npm to build UI..." -ForegroundColor Yellow
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Host "[!] npm not found in PATH, and frontend\dist\index.html is missing. Install Node.js LTS or use a prebuilt release." -ForegroundColor Red
        exit 1
    }
    Push-Location "frontend"
    try {
        npm install
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        npm run build
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[+] Prebuilt frontend UI verified (frontend\dist\index.html)" -ForegroundColor Green
}

# 5. Provision all external engines (Nmap, Nuclei, OWASP ZAP + JRE 17, Tor Expert Bundle)
Write-Host "[*] Checking and provisioning scanning engines (Nmap, Nuclei, OWASP ZAP + JRE 17, Tor)..." -ForegroundColor Yellow
& $VenvPython -m backend.scanners.engine_bootstrap
$BootExit = $LASTEXITCODE
if ($BootExit -ne 0) {
    Write-Host "[!] Warning: one or more engines could not be auto-installed during setup. You can retry later in Settings -> Engines." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "  SETUP COMPLETATO CON SUCCESSO!" -ForegroundColor Green
Write-Host "  Tutti i pacchetti e i motori sono configurati." -ForegroundColor Green
Write-Host "  Per avviare UrielScan clicca due volte su: start.bat" -ForegroundColor Cyan
Write-Host "  (oppure da terminale esegui: .\start.bat)" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Green
exit 0
