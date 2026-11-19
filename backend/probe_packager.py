"""Self-contained Windows (.msi) and Linux (.sh) Remote Probe installer packager."""

import base64
import json
import os
import socket
import ssl
import urllib.parse
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
MSI_TEMPLATE_PATH = BASE_DIR / "agent" / "templates" / "urielscan_probe_base.msi"
PROBE_SCRIPT_PATH = BASE_DIR / "agent" / "urielscan_probe.py"

SLOT_SIZE = 32768
CFG_START = b"URIELSCAN_PROBE_CFG_START:"
CFG_END = b":URIELSCAN_PROBE_CFG_END"


def _fetch_server_leaf_cert_pem(server_url: str, timeout: float = 2.0) -> str:
    """Best-effort retrieval of the UrielScan server TLS certificate in PEM format."""
    try:
        parsed = urllib.parse.urlparse(server_url or "")
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return ""
        host = parsed.hostname
        port = parsed.port or 443
        # Skip loopback unit-test URLs when no real TLS listener is up
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return ""
                return ssl.DER_cert_to_PEM_cert(der_cert).strip()
    except Exception:
        return ""


def _read_configured_ca_pem() -> str:
    """Read optional custom server/CA PEM bundle if configured via URIELSCAN_PROBE_CA_FILE."""
    ca_file = os.environ.get("URIELSCAN_PROBE_CA_FILE", "").strip()
    if ca_file and Path(ca_file).is_file():
        return Path(ca_file).read_text(encoding="utf-8", errors="ignore").strip()
    return ""


def _build_slot_bytes(payload: dict) -> bytes:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    pad_len = SLOT_SIZE - len(CFG_START) - len(encoded) - len(CFG_END)
    if pad_len < 0:
        # Retry without bulky CA if unexpected oversized chain
        compact = dict(payload)
        compact["ca_pem"] = ""
        encoded = json.dumps(compact, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        pad_len = SLOT_SIZE - len(CFG_START) - len(encoded) - len(CFG_END)
        if pad_len < 0:
            raise ValueError("Probe configuration exceeds fixed 32KB MSI config slot.")
    return CFG_START + encoded + (b" " * pad_len) + CFG_END


def build_windows_msi(
    agent_name: str,
    token: str,
    server_url: str,
    insecure: bool = False,
    interval: int = 5,
    ca_pem: Optional[str] = None,
) -> bytes:
    """Generate a ready-to-install Windows .msi embedding config, auth key, Python runtime, and TLS cert."""
    if not MSI_TEMPLATE_PATH.is_file():
        raise FileNotFoundError(f"Base Windows MSI template missing: {MSI_TEMPLATE_PATH}")

    template_bytes = MSI_TEMPLATE_PATH.read_bytes()
    start_idx = template_bytes.find(CFG_START)
    if start_idx == -1:
        raise RuntimeError("MSI template does not contain ProbeConfigSlot start marker.")
    end_idx = template_bytes.find(CFG_END, start_idx)
    if end_idx == -1:
        raise RuntimeError("MSI template does not contain ProbeConfigSlot end marker.")

    actual_slot_len = (end_idx + len(CFG_END)) - start_idx
    if actual_slot_len != SLOT_SIZE:
        raise RuntimeError(f"Unexpected MSI config slot length {actual_slot_len} (expected {SLOT_SIZE}).")

    pem_data = (ca_pem or "").strip() or _read_configured_ca_pem() or _fetch_server_leaf_cert_pem(server_url)
    payload = {
        "agent_name": agent_name,
        "server_url": server_url.rstrip("/"),
        "token": token,
        "insecure": bool(insecure),
        "interval": int(interval),
        "ca_pem": pem_data,
    }
    patched_slot = _build_slot_bytes(payload)
    if len(patched_slot) != SLOT_SIZE:
        raise RuntimeError("Patched MSI config slot length mismatch.")

    return template_bytes[:start_idx] + patched_slot + template_bytes[start_idx + SLOT_SIZE :]


def build_linux_sh(
    agent_name: str,
    token: str,
    server_url: str,
    insecure: bool = False,
    interval: int = 5,
    ca_pem: Optional[str] = None,
) -> bytes:
    """Generate a self-contained Linux .sh installer with embedded probe script, config, TLS cert, and portable Python bootstrap."""
    if not PROBE_SCRIPT_PATH.is_file():
        raise FileNotFoundError(f"Probe script missing: {PROBE_SCRIPT_PATH}")

    probe_b64 = base64.b64encode(PROBE_SCRIPT_PATH.read_bytes()).decode("ascii")
    pem_data = (ca_pem or "").strip() or _read_configured_ca_pem() or _fetch_server_leaf_cert_pem(server_url)

    config_obj = {
        "agent_name": agent_name,
        "server_url": server_url.rstrip("/"),
        "token": token,
        "insecure": bool(insecure),
        "interval": int(interval),
    }
    if pem_data:
        config_obj["cacert"] = "/opt/urielscan-probe/cacert.pem"

    config_b64 = base64.b64encode(json.dumps(config_obj, indent=2).encode("utf-8")).decode("ascii")
    pem_b64 = base64.b64encode((pem_data + "\n").encode("utf-8")).decode("ascii") if pem_data else ""

    script = f"""#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/urielscan-probe"
PYTHON_DIR="$INSTALL_DIR/python"
SERVICE_NAME="urielscan-probe"

if [ "${{EUID:-$(id -u)}}" -ne 0 ]; then
  echo "[UrielScan Probe] Run this installer as root (e.g. sudo bash $0)."
  exit 1
fi

echo "[UrielScan Probe] Installing into $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"

base64 -d > "$INSTALL_DIR/urielscan_probe.py" <<'__URIEL_PROBE_PY__'
{probe_b64}
__URIEL_PROBE_PY__
chmod 700 "$INSTALL_DIR/urielscan_probe.py"

base64 -d > "$INSTALL_DIR/probe_config.json" <<'__URIEL_PROBE_CFG__'
{config_b64}
__URIEL_PROBE_CFG__
chmod 600 "$INSTALL_DIR/probe_config.json"
"""

    if pem_b64:
        script += f"""
base64 -d > "$INSTALL_DIR/cacert.pem" <<'__URIEL_PROBE_CA__'
{pem_b64}
__URIEL_PROBE_CA__
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
  cat /etc/ssl/certs/ca-certificates.crt >> "$INSTALL_DIR/cacert.pem"
elif [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
  cat /etc/pki/tls/certs/ca-bundle.crt >> "$INSTALL_DIR/cacert.pem"
fi
chmod 644 "$INSTALL_DIR/cacert.pem"
"""

    script += """
find_python3() {
  for cand in python3 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$cand" >/dev/null 2>&1; then
      if "$cand" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >/dev/null 2>&1; then
        command -v "$cand"
        return 0
      fi
    fi
  done
  return 1
}

PYTHON_BIN=""
if PYTHON_BIN="$(find_python3)"; then
  echo "[UrielScan Probe] Using system Python: $PYTHON_BIN"
else
  echo "[UrielScan Probe] Compatible Python 3.10+ not found; provisioning standalone portable Python runtime..."
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) PY_ARCH="x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) PY_ARCH="aarch64-unknown-linux-gnu" ;;
    *)
      echo "[UrielScan Probe] Unsupported CPU architecture for portable Python: $ARCH"
      exit 1
      ;;
  esac
  PY_URL="https://github.com/astral-sh/python-build-standalone/releases/download/20241016/cpython-3.12.7+20241016-${PY_ARCH}-install_only.tar.gz"
  mkdir -p "$PYTHON_DIR"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$PY_URL" -o /tmp/uriel_py.tar.gz
  elif command -v wget >/dev/null 2>&1; then
    wget -qO /tmp/uriel_py.tar.gz "$PY_URL"
  else
    echo "[UrielScan Probe] Neither curl nor wget available to fetch portable Python runtime."
    exit 1
  fi
  tar -xzf /tmp/uriel_py.tar.gz -C "$PYTHON_DIR" --strip-components=1
  rm -f /tmp/uriel_py.tar.gz
  PYTHON_BIN="$PYTHON_DIR/bin/python3"
  echo "[UrielScan Probe] Portable Python installed at $PYTHON_BIN"
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=UrielScan Remote Probe Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON_BIN $INSTALL_DIR/urielscan_probe.py --config $INSTALL_DIR/probe_config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE_NAME"
  echo "[UrielScan Probe] Service '${SERVICE_NAME}' started via systemd."
else
  nohup "$PYTHON_BIN" "$INSTALL_DIR/urielscan_probe.py" --config "$INSTALL_DIR/probe_config.json" > "$INSTALL_DIR/probe.log" 2>&1 &
  echo $! > "$INSTALL_DIR/probe.pid"
  echo "[UrielScan Probe] Background probe daemon started (PID $(cat "$INSTALL_DIR/probe.pid"))."
fi
"""
    return script.encode("utf-8")
