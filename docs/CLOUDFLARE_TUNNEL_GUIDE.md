# UrielScan — Cloudflare Tunnel & Zero Trust Deployment Guide

This guide describes how to expose a self-hosted **UrielScan** instance securely behind **Cloudflare Tunnel (`cloudflared`)** and **Cloudflare Zero Trust Access** (Free tier compatible), without opening any inbound firewall ports on your host or router.

---

## 1. Architecture Overview

- **Local-Only Binding**: UrielScan listens exclusively on `127.0.0.1:8000` inside the host or dedicated VLAN.
- **Outbound-Only Tunnel**: `cloudflared` establishes outbound TLS/QUIC connections (`443/tcp`, `7844/udp|tcp`) to Cloudflare Edge—zero inbound port forwarding is required.
- **Layered Authentication**:
  1. **Cloudflare Zero Trust Access** (Google Workspace / IdP / Email OTP) protects the web UI and management APIs before traffic reaches your host.
  2. **UrielScan Native Auth + 2FA TOTP** protects the application session.
  3. **Remote Probes (`.msi` / `.sh`)** communicate exclusively over `/api/agent/*` using per-agent SHA-256 Bearer tokens (`X-Agent-Token`) and HMAC-signed 24-hour installer tickets.

---

## 2. Prerequisites

1. A domain managed on Cloudflare DNS (e.g., `example.com` -> `scanner.example.com`).
2. A host running UrielScan (installed via `./install.sh` on Linux or `install.bat` on Windows).

---

## 3. Running UrielScan as a Service (Linux `systemd` Example)

Create `/etc/systemd/system/urielscan.service` (adjust user and paths as needed):

```ini
[Unit]
Description=UrielScan Purple Team Platform
After=network.target

[Service]
Type=simple
User=urielscan
WorkingDirectory=/opt/UrielScan
ExecStart=/opt/UrielScan/.venv/bin/python /opt/UrielScan/run.py --no-browser --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now urielscan
sudo systemctl status urielscan
```

---

## 4. Creating & Connecting the Cloudflare Tunnel

1. Sign in to **Cloudflare Zero Trust** (`https://one.dash.cloudflare.com`).
2. Navigate to **Networks → Tunnels → Create a tunnel**.
3. Select **Cloudflared**, name the tunnel (e.g., `urielscan-prod`), and save.
4. Install `cloudflared` on your server and register the tunnel token as shown in the Cloudflare dashboard:
   - **Debian / Ubuntu**:
     ```bash
     curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
     echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
     sudo apt-get update && sudo apt-get install -y cloudflared
     sudo cloudflared service install <YOUR_TUNNEL_TOKEN>
     ```
5. Under the tunnel's **Public Hostname** tab, add:
   - **Subdomain**: `scanner`
   - **Domain**: `example.com` (resulting in `https://scanner.example.com`)
   - **Service Type**: `HTTP`
   - **URL**: `127.0.0.1:8000`

---

## 5. Hardening with Cloudflare Access & Remote Probe Bypass

If you protect `scanner.example.com` with **Cloudflare Zero Trust → Access → Applications** (e.g., Google SSO or Email OTP), browser requests will authenticate against Cloudflare first. However, **Remote Probes** are non-interactive daemons and must be able to reach `/api/agent/*` without hitting a browser login redirect.

### Required Access Application Split

1. **Primary Application (Protected UI & Admin APIs)**:
   - **Domain**: `scanner.example.com` (root path `/`)
   - **Policy Action**: `Allow` (e.g., restricted to specific corporate/admin email addresses via Google/IdP).

2. **Agent API Application (Required for Remote Probes)**:
   - Create a second **Self-hosted** application in **Access → Applications**:
     - **Subdomain**: `scanner`
     - **Domain**: `example.com`
     - **Path**: `api/agent/*` *(include the trailing slash so only agent endpoints match)*
   - Add an Access Policy:
     - **Action**: `Bypass`
     - **Include**: `Everyone` *(for probes on dynamic client IPs)* — **or** `IP Ranges` *(recommended if probes only run from known static egress IPs)*.

### Why `/api/agent/*` Bypass Remains Safe
- All other endpoints (`/api/scans`, `/api/settings`, `/api/organizations`, `/api/reports`, `/api/agents`, `/api/wordlists`) remain gated by **both** Cloudflare Access and UrielScan's JWT + 2FA session middleware.
- `/api/agent/heartbeat`, `/api/agent/jobs/next`, `/api/agent/jobs/{id}/progress`, and `/api/agent/jobs/{id}/results` enforce `X-Agent-Token` (SHA-256 verified against the database) and scope job updates strictly to the owning `agent_id`.
- `/api/agent/installer/{ticket}` requires a high-entropy HMAC-signed ticket with a 24-hour TTL.

### Quick Verification

```bash
# Unauthenticated probe check should bypass Cloudflare login and return UrielScan's native 401 JSON:
curl -i https://scanner.example.com/api/agent/jobs/next
```

---

## 6. Host Firewall & Application Hardening

- **Host Firewall (`ufw`)**:
  - Deny all inbound traffic (allow SSH only from internal management subnets if needed).
  - Allow outbound `443/tcp` (HTTPS), `7844/tcp` & `7844/udp` (`cloudflared` QUIC/HTTP2), `53` (DNS), and `123/udp` (NTP).
- **UrielScan First-Boot Security**:
  - Immediately change the default `admin` password and enable **2FA TOTP** under **Settings → Security**.

---

## 7. Deploying Remote Probes

1. Open `https://scanner.example.com` → **Settings → Remote Probes**.
2. Select the target organization, create a probe, and choose **Download Windows (`.msi`)** or **Download Linux (`.sh`)**.
3. Run the installer on the client host (or copy the silent PowerShell / Bash RMM deployment command). The probe authenticates automatically to `https://scanner.example.com` using its embedded `X-Agent-Token`.
