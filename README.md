# UrielScan - Next-Gen Open Source Purple Team Vulnerability Scanner

<img width="376" height="256" alt="urielscan-logo" src="https://github.com/user-attachments/assets/415d8f3d-b0e9-4a8f-b2a6-83ac81155a37" />

**UrielScan** is an open-source Vulnerability Assessment & Purple Team platform designed to combine **Network Scanning (Nmap + NSE)**, **Web Vulnerability Scanning (Nuclei + OWASP ZAP)**, and an **Asynchronous Native Engine** with cross-engine deduplication, **Tor Onion / Custom SOCKS5-HTTP Proxy routing**, **NAT Loopback Guard**, **Self-Contained Remote Probe Installers (`.msi` / `.sh`)**, bilingual `EN / IT` multi-theme UI, and white-label dual-logo reporting for **MSP/MSSP** operations.

## Quick Start (Windows & Linux)

### 1. First-Time Setup (Python `.venv` + All Engines: Nmap, Nuclei, OWASP ZAP + JRE 17, Tor)
- **Windows** (double-click or terminal):
  ```powershell
  .\install.bat
  # or via PowerShell:
  powershell -ExecutionPolicy Bypass -File .\install.ps1
  ```
- **Linux / macOS**:
  ```bash
  chmod +x install.sh && ./install.sh
  ```

### 2. Launch & Stop Application
- **Windows**: Double-click `start.bat` — launches UrielScan silently in the background via `pythonw.exe` (no console window kept open), logs to `data/urielscan.log`, and automatically opens your browser once ready. Run `stop.bat` to stop it (or `start.bat --console` for visible terminal logs).
- **Linux / macOS**: `./start.sh` (or `.venv/bin/python run.py`)

Once started, the UrielScan dashboard is available in your browser at **`http://localhost:8000`** (OpenAPI documentation is available at `http://localhost:8000/docs`).

## Remote Probe Agent (MSP Client Networks)

To scan internal client networks without opening inbound firewall ports or encountering RFC1918 subnet conflicts, UrielScan includes **Outbound Pull Remote Probes**:

1. **Enroll a Probe**: Go to **Settings → Remote Probes**, select the target organization, and create a probe to generate an **Agent Token**.
2. **Deploy on Client Hosts (Zero Manual Python Setup Required)**:
   - **Windows Self-Contained `.msi`**: Downloads an MSI package containing an embedded Python runtime, Windows background service registration, and pre-configured Server URL + Agent Token — ready for GUI install or silent RMM deployment (`msiexec /i ... /qn`).
   - **Linux Self-Contained `.sh`**: Downloads a standalone Bash installer with embedded payload, registers a persistent `systemd` service, and supports one-line remote RMM execution (`curl -fsSL ... | sudo bash`) via time-limited HMAC-signed download links.
   - **Standalone Script (Fallback)**: Alternatively, run [`agent/urielscan_probe.py`](agent/urielscan_probe.py) directly on Python 3.10+ (stdlib only):
     ```bash
     python urielscan_probe.py --server https://your-urielscan-domain.com --token <AGENT_TOKEN>
     ```
3. **Launch Remote Scans**: In **New Scan Studio**, select the client's registered probe under **Execution Probe** and launch the scan as usual. For external networks, expose UrielScan behind an **HTTPS Reverse Proxy** (Nginx, Caddy, Traefik) or follow the step-by-step [Cloudflare Tunnel & Zero Trust Guide](docs/CLOUDFLARE_TUNNEL_GUIDE.md).

## Outbound Network Routing (Tor Onion & Custom Proxy)

In **New Scan Studio → Outbound Network Routing** (local scans), choose between:
- **Direct (Local IP)**: Standard egress and internal LAN/subnet scanning.
- **Onion Routing (Tor)**: Launches the managed Tor Expert Bundle (`socks5h://127.0.0.1:19050` / ControlPort `19051`), supports `.onion` services, verifies Tor Exit IP, supports one-click **New Circuit (`SIGNAL NEWNYM`)**, and enforces fail-closed leak protection (direct Nmap is skipped or wrapped safely with `torsocks` on Unix while Native Net runs TCP/Banner probes over SOCKS5).
- **Custom SOCKS5 / HTTP Proxy**: Route Native TCP/SSL/Web, Nuclei, and OWASP ZAP traffic through an external VPS SSH/SOCKS5 tunnel, WireGuard gateway, or HTTP proxy (`socks5h://`, `socks5://`, `http://`, `https://`) with live Exit IP verification.

## Optional Web Recon Modules (Opt-In: SubRaptor + httpx + Subzy + Feroxbuster)

Disabled by default and selectable per-scan in **New Scan Studio**:
- **Subdomain Discovery & Intelligence**: Combines **SubRaptor**-style passive aggregation (**Subfinder**, **Assetfinder**, **crt.sh** with per-source Found/Unique attribution), optional DNS bruteforce via SecLists (`n0kovo_subdomains.txt`, `subdomains-top1million-110000.txt`, `italian-subdomains.txt`) or custom `.txt` upload, **DNS Zone Audit** (AXFR transfer test, Wildcard check, SPF/DMARC/CAA), live web/tech probing (**ProjectDiscovery `httpx`**), and **Subdomain Takeover** checks (**Subzy** / `can-i-take-over-xyz` 76-signature DB), with optional cascade into Web/Nuclei/ZAP/Feroxbuster.
- **Directory Enumeration (`Feroxbuster`)**: High-speed wildcard-filtered content discovery with SecLists (`DirBuster-2007_directory-list-2.3-medium.txt` / `big.txt`) or custom `.txt` upload, rate/time limits, and proxy/Tor support.

## NAT Loopback Guard & Cross-Engine Deduplication

- **NAT Loopback Guard**: Automatically detects when a public IP/domain target resolves to your local WAN egress IP, queries external WAN exposure via Shodan InternetDB, and suppresses false-positive internal router hairpinning findings.
- **Cross-Engine Deduplication**: Consolidates overlapping findings reported across Nmap, Native Net/SSL/Web, Nuclei, and OWASP ZAP into unified severity-ordered results.

## Reporting, AI Analyst & Archive

- **White-Label Reports & Exports**: Generate **HTML**, **PDF**, **DOCX**, **CSV**, and **TXT** reports with Provider + Client dual branding and persistent Saved Report history.
- **Purple Team AI Analyst**: Supports **Google Gemini**, **OpenAI**, **Anthropic Claude**, **Ollama (Local)**, and a built-in **Offline Heuristic Engine**, with persistent Saved AI Analyses history and executive/single-finding insights.
- **Authentication**: Admin login (`admin:admin` on first boot) with optional **2FA TOTP (RFC 6238)** QR setup and password management.

## Core Architecture
- **Backend & Scanners (`backend/`)**:
  - [`backend/main.py`](backend/main.py): FastAPI server, SPA mount, REST API, Auth/2FA TOTP, Tor/Proxy controls, and Remote Probe endpoints.
  - [`backend/probe_packager.py`](backend/probe_packager.py): Builds self-contained Windows `.msi` and Linux `.sh` remote probe installers and time-limited signed RMM download URLs.
  - [`backend/scanners/orchestrator.py`](backend/scanners/orchestrator.py): Hybrid scan pipeline orchestrator with Tor/Proxy fail-closed routing and NAT Loopback filtering.
  - [`backend/scanners/nmap_engine.py`](backend/scanners/nmap_engine.py): Nmap + `.nse` script indexing, XML parsing, and proxy leak guard.
  - [`backend/scanners/nuclei_engine.py`](backend/scanners/nuclei_engine.py): Nuclei integration with cross-platform auto-installer and `-proxy` routing.
  - [`backend/scanners/zap_engine.py`](backend/scanners/zap_engine.py): OWASP ZAP integration (Daemon API / headless CLI + portable Temurin JRE 17 auto-provisioning) with SOCKS5/HTTP proxy config.
  - [`backend/scanners/tor_engine.py`](backend/scanners/tor_engine.py): Managed Tor Expert Bundle lifecycle, RFC 1928 SOCKS5 / HTTP CONNECT tunneling, Exit IP probe, and circuit rotation.
  - [`backend/scanners/engine_bootstrap.py`](backend/scanners/engine_bootstrap.py): Automatic startup & CLI provisioning for Nmap, Nuclei, OWASP ZAP, and Tor (`bin/`).
  - [`backend/scanners/native_engine.py`](backend/scanners/native_engine.py): Asynchronous TCP/Banner scanner, SSL/TLS Inspector, and OWASP Web Security Analyzer (with SOCKS5h/HTTP proxy support).
  - [`backend/scanners/nat_guard.py`](backend/scanners/nat_guard.py) & [`backend/scanners/deduplicator.py`](backend/scanners/deduplicator.py): WAN hairpin detection and cross-engine finding deduplication.
  - [`backend/ai_engine.py`](backend/ai_engine.py), [`backend/report_engine.py`](backend/report_engine.py), [`backend/export_engine.py`](backend/export_engine.py) & [`backend/scheduler.py`](backend/scheduler.py): Multi-LLM analyst, white-label HTML/DOCX/PDF/CSV/TXT generators, and cron/interval scan scheduler.
- **Standalone Remote Agent (`agent/`)**:
  - [`agent/urielscan_probe.py`](agent/urielscan_probe.py): Zero-dependency Python remote probe supporting Native, Nmap, and Nuclei scans over outbound HTTPS polling.
- **Web Frontend (`frontend/`)**:
  - React + TypeScript + TailwindCSS SPA compiled into `frontend/dist`, featuring industrial multi-theme support (`Uriel Ops` default) and bilingual `EN / IT` switching.
