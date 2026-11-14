# UrielScan - Next-Gen Open Source Purple Team Vulnerability Scanner

<img width="376" height="256" alt="urielscan-logo" src="https://github.com/user-attachments/assets/415d8f3d-b0e9-4a8f-b2a6-83ac81155a37" />

**UrielScan** is an open-source Vulnerability Assessment & Purple Team platform designed to combine **Network Scanning (Nmap + NSE)** and **Web Application Security Testing (Nuclei + OWASP/ZAP-like Native Audit)** in a single modern, multi-theme web interface tailored for **MSP/MSSP** operations (multi-organization management, remote client probes, bilingual `EN / IT` UI, and white-label dual-logo reporting).

## Quick Start (Windows & Linux)

- **Windows**:
  ```powershell
  .\start.bat
  # or directly:
  python run.py
  ```
- **Linux / macOS**:
  ```bash
  chmod +x start.sh && ./start.sh
  # or directly:
  python3 run.py
  ```

Once started, the UrielScan dashboard is available in your browser at **`http://localhost:8000`** (OpenAPI documentation is available at `http://localhost:8000/docs`).

## Remote Probe Agent (MSP Client Networks)

To scan internal client networks without opening inbound firewall ports or encountering RFC1918 subnet conflicts, UrielScan includes a standalone **Outbound Pull Remote Probe** ([`agent/urielscan_probe.py`](agent/urielscan_probe.py)):

1. **Enroll a Probe**: Go to **Settings → Remote Probes**, select the target organization, generate an **Agent Token**, and download `urielscan_probe.py`.
2. **Run on Client Network** (Python 3.10+ stdlib only, optional local `nmap` / `nuclei`):
   ```bash
   python urielscan_probe.py --server https://your-urielscan-domain.com --token <AGENT_TOKEN>
   ```
   - For local/LAN testing, start UrielScan with `python run.py --host 0.0.0.0` and point `--server` to your server LAN IP (e.g., `http://192.168.1.50:8000`).
   - For external client networks, expose UrielScan behind an **HTTPS Reverse Proxy** (Nginx, Caddy, Traefik) or a secure tunnel (Cloudflare Tunnel / WireGuard).
3. **Launch Remote Scans**: In **New Scan Studio**, select the client's registered probe under **Execution Probe** and start the scan as usual.

## Core Architecture
- **Backend & Scanners (`backend/`)**:
  - [`backend/main.py`](backend/main.py): FastAPI server + SPA mount + REST API (including Auth, 2FA TOTP, and Remote Agent endpoints).
  - [`backend/scanners/nmap_engine.py`](backend/scanners/nmap_engine.py): Native Nmap integration + system `.nse` script indexing + ZenMap++ scan profiles.
  - [`backend/scanners/nuclei_engine.py`](backend/scanners/nuclei_engine.py): Nuclei integration with cross-platform auto-downloader from official GitHub Releases.
  - [`backend/scanners/native_engine.py`](backend/scanners/native_engine.py): Asynchronous TCP/Banner scanner, SSL/TLS Inspector, and Web Security Analyzer (Security Headers, CORS, Cookie flags, Sensitive Files, Safe SQLi/XSS Probes).
  - [`backend/ai_engine.py`](backend/ai_engine.py): Multi-provider AI Purple Team Analyst (Google Gemini, OpenAI, Anthropic Claude, Ollama/Local + built-in offline heuristic engine).
  - [`backend/report_engine.py`](backend/report_engine.py), [`backend/export_engine.py`](backend/export_engine.py) & [`backend/scheduler.py`](backend/scheduler.py): White-label HTML, editable DOCX, PDF, CSV, and TXT report/export generators + cross-platform cron/interval scan scheduler.
- **Standalone Remote Agent (`agent/`)**:
  - [`agent/urielscan_probe.py`](agent/urielscan_probe.py): Zero-dependency Python remote probe supporting Native, Nmap, and Nuclei scans over outbound HTTPS polling.
- **Web Frontend (`frontend/`)**:
  - React + TypeScript + TailwindCSS SPA compiled into `frontend/dist`, featuring industrial multi-theme support (`Uriel Ops` default) and bilingual `EN / IT` switching.
