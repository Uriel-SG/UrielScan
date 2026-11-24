# UrielScan - Next-Gen Open Source Purple Team Vulnerability Scanner

<p align="center">
<img width="376" height="256" alt="urielscan-logo" src="https://github.com/user-attachments/assets/415d8f3d-b0e9-4a8f-b2a6-83ac81155a37" />
</p>

**UrielScan** is an open-source Vulnerability Assessment & Purple Team platform designed to combine **Network Scanning (Nmap + NSE)**, **Web Vulnerability Scanning (Nuclei + OWASP ZAP)**, **Cloud Security Posture Management (Prowler CSPM)**, **Internal Network / Active Directory / Entra ID Security (NetExec, Enum4linux-ng, BloodHound, AzureHound, Responder)**, **Passive External OSINT (Shodan InternetDB, RIPEstat, GreyNoise)**, and an **Asynchronous Native Engine** with cross-engine deduplication, **Tor Onion / Custom SOCKS5-HTTP Proxy routing**, **NAT Loopback Guard**, **Self-Contained Remote Probe Installers (`.msi` / `.sh`)**, bilingual `EN / IT` multi-theme UI, and white-label dual-logo reporting for **MSP/MSSP** operations.

<img width="1917" height="1198" alt="Screenshot 2026-11-22 154719" src="https://github.com/user-attachments/assets/3493d065-cadc-4199-821b-1ae4c5159eac" />

## Quick Start (Windows & Linux)

### 1. First-Time Setup (Python `.venv` + All Engines: Nmap, Nuclei, OWASP ZAP + JRE 17, Tor, Prowler)
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

<img width="1917" height="1198" alt="image" src="https://github.com/user-attachments/assets/7cc8f1b3-6d9a-45fb-b018-e716bce6e913" />

## Outbound Network Routing (Tor Onion & Custom Proxy)

In **New Scan Studio → Outbound Network Routing** (local scans), choose between:
- **Direct (Local IP)**: Standard egress and internal LAN/subnet scanning.
- **Onion Routing (Tor)**: Launches the managed Tor Expert Bundle (`socks5h://127.0.0.1:19050` / ControlPort `19051`), supports `.onion` services, verifies Tor Exit IP, supports one-click **New Circuit (`SIGNAL NEWNYM`)**, and enforces fail-closed leak protection (direct Nmap is skipped or wrapped safely with `torsocks` on Unix while Native Net runs TCP/Banner probes over SOCKS5).
- **Custom SOCKS5 / HTTP Proxy**: Route Native TCP/SSL/Web, Nuclei, and OWASP ZAP traffic through an external VPS SSH/SOCKS5 tunnel, WireGuard gateway, or HTTP proxy (`socks5h://`, `socks5://`, `http://`, `https://`) with live Exit IP verification.

<img width="1917" height="1198" alt="image" src="https://github.com/user-attachments/assets/31bbcb18-2ad3-45d9-b5b5-c4ce2308ed1b" />

## Optional Web Recon Modules (Opt-In: SubRaptor + httpx + Subzy + Feroxbuster)

Disabled by default and selectable per-scan in **New Scan Studio**:
- **Subdomain Discovery & Intelligence**: Combines **SubRaptor**-style passive aggregation (**Subfinder**, **Assetfinder**, **crt.sh** with per-source Found/Unique attribution), optional DNS bruteforce via SecLists (`n0kovo_subdomains.txt`, `subdomains-top1million-110000.txt`, `italian-subdomains.txt`) or custom `.txt` upload, **DNS Zone Audit** (AXFR transfer test, Wildcard check, SPF/DMARC/CAA), live web/tech probing (**ProjectDiscovery `httpx`**), and **Subdomain Takeover** checks (**Subzy** / `can-i-take-over-xyz` 76-signature DB), with optional cascade into Web/Nuclei/ZAP/Feroxbuster.
- **Directory Enumeration (`Feroxbuster`)**: High-speed wildcard-filtered content discovery with SecLists (`DirBuster-2007_directory-list-2.3-medium.txt` / `big.txt`) or custom `.txt` upload, configurable rate/time/max-depth limits, and proxy/Tor support.
- **Standalone Tech Stack Fingerprinting (`Wappalyzer / httpx + HTML/Headers + Nmap CPE`)**: Runs independently of SubRaptor on both external and internal/LAN targets, combining `httpx -tech-detect`, HTTP header/HTML/cookie version extraction, and Nmap `<cpe>` fusion into a unified Technology Stack inventory in UI and HTML/PDF/DOCX reports.
- **CVE, CISA KEV, EPSS & PoC-in-GitHub Intelligence**: Correlates versioned components against **NVD API v2**, **CISA KEV**, **FIRST EPSS**, and **PoC-in-GitHub** with a 24h local SQLite cache (`cve_intel_cache`), attaching public PoC URLs and transparent `VERSION-BASED` labeling (deduplicated below active Nuclei/ZAP findings).
- **External OSINT Intelligence (`Shodan InternetDB + RIPEstat + GreyNoise Community API`)**: Free, zero-API-key passive enrichment for public global IPs (RFC1918/loopback targets are automatically skipped) with 24h local SQLite caching — retrieving ASN/organization/CIDR prefix, passively indexed open ports/CPEs/tags/CVEs, and GreyNoise scanner reputation.

<img width="1916" height="1198" alt="image" src="https://github.com/user-attachments/assets/5646b324-d4e1-40f0-8c83-340d08cc016a" />

## Cloud Security Posture Management (Prowler CSPM)

Accessible directly under **New Scan → Cloud Security**, UrielScan integrates **Prowler CSPM** (auto-bootstrapped in `.venv`/PATH during first-time installation and on startup):
- **Multi-Cloud & Encrypted Credential Profiles**: Store encrypted AWS (`AccessKey` / `RoleARN` / `Profile`), Azure (`Service Principal`), GCP (`Service Account JSON`), Microsoft 365 (`App Registration`), or Kubernetes (`Kubeconfig`) profiles in SQLite (`cloud_profiles`).
- **Compliance & OCSF Ingestion**: Audit against **CIS**, **SOC 2**, **ISO 27001**, **GDPR**, **HIPAA**, **PCI-DSS**, and **NIST** frameworks; ingest Prowler OCSF JSON results into a dedicated per-service pass-rate dashboard and full CSPM report tables.

## Internal Network, Active Directory & Entra ID Security

Accessible under **Cloud Security → Internal & AD**, UrielScan provides a dedicated internal LAN, Active Directory, and Microsoft Entra ID assessment suite:
- **Modular NetExec (`nxc`) Orchestration**: Select target protocol (`SMB`, `LDAP`, `WinRM`, `RDP`, `MSSQL`, `SSH`) and toggleable audit flags (Signing/Null Sessions, Shares, Users/Groups, Password Policy, Kerberoasting/ASREPRoast, ADCS Certificate Templates, SAM/LSA, local admin reuse) with optional domain/local credentials.
- **Enum4linux-ng Enumeration**: Full SMB/RPC/NetBIOS share, user, group, and password policy audit — automatically flagging readable sensitive network shares and anonymous/null-session exposures in findings and reports.
- **BloodHound AD & AzureHound Entra ID**: Run automated collectors (`bloodhound-python` / `BloodHound.py` and `azurehound`) or upload offline `.zip`/`.json` archives for native attack-path analysis (Kerberoastable accounts, ASREPRoastable users, Unconstrained/Constrained Delegation, Dangerous ACLs such as `GenericAll`/`WriteDacl`/`WriteOwner`, Tier-0 Entra ID privileged roles, and risky App/Graph permissions), plus one-click `.zip` export for the BloodHound GUI.
- **Responder LAN Broadcast Audit (Passive Default)**: Safe, non-invasive **Passive UDP Sniffer** by default (listens on UDP `137`, `5353`, `5355` to detect LLMNR/NBNS/mDNS poisoning exposure without injecting packets). Optional **Active Mode** (`-A`/full Responder) requires an explicit authorization checkbox, displays a clear risk warning dialog, and is enforced by backend API & engine validation (`HTTP 400` / `ValueError` without client authorization).

## NAT Loopback Guard & Cross-Engine Deduplication

- **NAT Loopback Guard**: Automatically detects when a public IP/domain target resolves to your local WAN egress IP, queries external WAN exposure via Shodan InternetDB, and suppresses false-positive internal router hairpinning findings.
- **Cross-Engine Deduplication**: Consolidates overlapping findings reported across Nmap, Native Net/SSL/Web, Nuclei, and OWASP ZAP into unified severity-ordered results.

## Reporting, AI Analyst & Archive

- **White-Label Reports & Exports**: Generate **HTML**, **PDF**, **DOCX**, **CSV**, and **TXT** reports with Provider + Client dual branding, persistent Saved Report history, and dedicated tables for **Attack Surface & Tech Stack**, **CVE/KEV/PoC Intel**, **External OSINT**, **Cloud Security Posture (Prowler CSPM)**, and **Internal Network / AD / Entra ID**.
- **Purple Team AI Analyst**: Supports **Google Gemini**, **OpenAI**, **Anthropic Claude**, **Ollama (Local)**, and a built-in **Offline Heuristic Engine**, with persistent Saved AI Analyses history and executive/single-finding insights.
- **Authentication**: Admin login (`admin:admin` on first boot) with optional **2FA TOTP (RFC 6238)** QR setup and password management.

*Example - Report:*

<img width="882" height="1107" alt="image" src="https://github.com/user-attachments/assets/fedf1921-de14-4972-a985-0c2f0aa79751" />

*Example - AI configuration:*

<img width="988" height="752" alt="image" src="https://github.com/user-attachments/assets/0a84a2fd-034b-42ac-9482-a3d0a72a20aa" />

*Example - AI analysis:*

<img width="1585" height="307" alt="image" src="https://github.com/user-attachments/assets/cee4cb46-eda2-4b65-9954-dbcf1bf3988a" />

<img width="1556" height="450" alt="image" src="https://github.com/user-attachments/assets/3b6f5ede-78d6-4030-b49b-22da6871b36c" />

<img width="1556" height="766" alt="image" src="https://github.com/user-attachments/assets/0248b680-9286-4319-8515-5f79e5949e42" />

<img width="1572" height="756" alt="image" src="https://github.com/user-attachments/assets/497edf24-82bc-468f-9b79-e1f4701edc01" />

*Example - AI html Report:*

<img width="867" height="777" alt="image" src="https://github.com/user-attachments/assets/bbcb2293-18bd-4d2e-adc6-54ef8aae59a9" />


## Core Architecture
- **Backend & Scanners (`backend/`)**:
  - [`backend/main.py`](backend/main.py): FastAPI server, SPA mount, REST API, Auth/2FA TOTP, Tor/Proxy controls, and Remote Probe endpoints.
  - [`backend/probe_packager.py`](backend/probe_packager.py): Builds self-contained Windows `.msi` and Linux `.sh` remote probe installers and time-limited signed RMM download URLs.
  - [`backend/scanners/orchestrator.py`](backend/scanners/orchestrator.py): Hybrid scan pipeline orchestrator with Tor/Proxy fail-closed routing and NAT Loopback filtering.
  - [`backend/scanners/nmap_engine.py`](backend/scanners/nmap_engine.py): Nmap + `.nse` script indexing, XML parsing, and proxy leak guard.
  - [`backend/scanners/nuclei_engine.py`](backend/scanners/nuclei_engine.py): Nuclei integration with cross-platform auto-installer and `-proxy` routing.
  - [`backend/scanners/zap_engine.py`](backend/scanners/zap_engine.py): OWASP ZAP integration (Daemon API / headless CLI + portable Temurin JRE 17 auto-provisioning) with SOCKS5/HTTP proxy config.
  - [`backend/scanners/tor_engine.py`](backend/scanners/tor_engine.py): Managed Tor Expert Bundle lifecycle, RFC 1928 SOCKS5 / HTTP CONNECT tunneling, Exit IP probe, and circuit rotation.
  - [`backend/scanners/engine_bootstrap.py`](backend/scanners/engine_bootstrap.py): Automatic startup & CLI provisioning for Nmap, Nuclei, OWASP ZAP, Tor, and **Prowler** (`bin/` / `.venv`).
  - [`backend/scanners/native_engine.py`](backend/scanners/native_engine.py): Asynchronous TCP/Banner scanner, SSL/TLS Inspector, and OWASP Web Security Analyzer (with SOCKS5h/HTTP proxy support).
  - [`backend/scanners/prowler_engine.py`](backend/scanners/prowler_engine.py): Multi-cloud CSPM engine (Prowler OCSF parser + encrypted Cloud Profile management).
  - [`backend/scanners/internal_ad_engine.py`](backend/scanners/internal_ad_engine.py): Internal LAN & AD/Entra ID suite (modular NetExec flags, Enum4linux-ng parser, BloodHound & AzureHound analyzers, passive-default Responder UDP sniffer & active authorization guard).
  - [`backend/scanners/osint_engine.py`](backend/scanners/osint_engine.py): Free passive external OSINT enrichment via Shodan InternetDB, RIPEstat, and GreyNoise Community API (`is_global` IP guard + 24h cache).
  - [`backend/scanners/recon_engine.py`](backend/scanners/recon_engine.py), [`backend/scanners/wordlists.py`](backend/scanners/wordlists.py) & [`backend/scanners/tech_cve_engine.py`](backend/scanners/tech_cve_engine.py): SubRaptor, `httpx`, Subzy, Feroxbuster, standalone Wappalyzer/CPE Tech Fingerprinting, and NVD/CISA KEV/EPSS/PoC-in-GitHub correlation.
  - [`backend/scanners/nat_guard.py`](backend/scanners/nat_guard.py) & [`backend/scanners/deduplicator.py`](backend/scanners/deduplicator.py): WAN hairpin detection and cross-engine finding deduplication.
  - [`backend/ai_engine.py`](backend/ai_engine.py), [`backend/report_engine.py`](backend/report_engine.py), [`backend/export_engine.py`](backend/export_engine.py) & [`backend/scheduler.py`](backend/scheduler.py): Multi-LLM analyst, white-label HTML/DOCX/PDF/CSV/TXT generators, and cron/interval scan scheduler.
- **Standalone Remote Agent (`agent/`)**:
  - [`agent/urielscan_probe.py`](agent/urielscan_probe.py): Zero-dependency Python remote probe supporting Native, Nmap, and Nuclei scans over outbound HTTPS polling.
- **Web Frontend (`frontend/`)**:
  - React + TypeScript + TailwindCSS SPA compiled into `frontend/dist`, featuring industrial multi-theme support (`Uriel Ops` default) and bilingual `EN / IT` switching.

## UrielScan Engines

<img width="1125" height="680" alt="image" src="https://github.com/user-attachments/assets/6ed2641d-dc8a-42ab-9b4a-3201bfe68aff" />

## Different Themes

*Phosphor Ops:*

<img width="1916" height="976" alt="image" src="https://github.com/user-attachments/assets/1f1c7479-6211-4acf-ad15-66f988764205" />

*Carbon Tactical:*

<img width="1916" height="976" alt="image" src="https://github.com/user-attachments/assets/163b3577-6512-4c42-bb2a-a4c53ba1b5b8" />

*Swiss Editorial:*

<img width="1916" height="982" alt="image" src="https://github.com/user-attachments/assets/f343298d-885a-462c-89dc-fcc2c6599fa0" />
