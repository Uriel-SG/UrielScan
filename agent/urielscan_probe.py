#!/usr/bin/env python3
"""
UrielScan Standalone Remote Probe Agent
======================================
100% Standalone, Zero-Dependency (Python 3.10+ Standard Library Only).
Connects to a UrielScan server via HTTPS/HTTP, reports heartbeat/capabilities,
pulls assigned jobs, executes native TCP/SSL/Web, Nmap and Nuclei scans,
streams progress, and uploads structured Purple Team results.
"""

import argparse
import asyncio
import ipaddress
import itertools
import json
import os
import platform
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import certifi
except ImportError:
    certifi = None  # type: ignore

CFG_MARKER_START = b"URIELSCAN_PROBE_CFG_START:"
CFG_MARKER_END = b":URIELSCAN_PROBE_CFG_END"

_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9.\-:/\[\]]+$")
_ALLOWED_NMAP_FLAGS = {
    "-sV", "-sC", "-sT", "-Pn", "-P0", "-F", "-v", "-n", "--open",
    "--version-light", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5"
}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"Redirect blocked ({code} -> {newurl})", headers, fp)

VERSION = "1.0.0"

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
    1433, 3306, 3389, 5432, 6379, 8080, 8443
]

PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 1433: "ms-sql-s",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt"
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_time_str() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


class ProbeClient:
    def __init__(self, server_url: str, token: str, insecure: bool = False, ca_bundle: Optional[str] = None):
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.insecure = insecure
        if insecure:
            self.ssl_context: Optional[ssl.SSLContext] = ssl._create_unverified_context()
        elif ca_bundle and os.path.exists(ca_bundle):
            self.ssl_context = ssl.create_default_context(cafile=ca_bundle)
        elif certifi is not None:
            self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        else:
            self.ssl_context = None

    def request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None, timeout: float = 15.0) -> Dict[str, Any]:
        url = f"{self.server_url}{path}"
        headers = {
            "User-Agent": f"UrielScan-Probe/{VERSION}",
            "X-Agent-Token": self.token,
            "Accept": "application/json"
        }
        data_bytes = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data_bytes = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
        handlers = [_NoRedirectHandler()]
        if self.ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code} on {path}: {err_body}")
        except Exception as e:
            raise RuntimeError(f"Network error on {path}: {e}")

    def heartbeat(self, engines: Dict[str, Any]) -> Dict[str, Any]:
        hostname = socket.gethostname()
        try:
            ip_addr = socket.gethostbyname(hostname)
        except Exception:
            ip_addr = "127.0.0.1"

        os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        payload = {
            "hostname": hostname,
            "ip_address": ip_addr,
            "os_info": os_info,
            "engines": engines,
            "version": VERSION
        }
        return self.request("POST", "/api/agent/heartbeat", payload=payload)

    def get_next_job(self) -> Optional[Dict[str, Any]]:
        resp = self.request("GET", "/api/agent/jobs/next")
        return resp.get("job")

    def update_progress(self, scan_id: int, progress: int, current_task: str, logs: List[Dict[str, Any]]) -> bool:
        """Returns True if scan should STOP, else False."""
        payload = {
            "progress": progress,
            "current_task": current_task,
            "logs": logs
        }
        resp = self.request("POST", f"/api/agent/jobs/{scan_id}/progress", payload=payload)
        return bool(resp.get("stop", False))

    def upload_results(self, scan_id: int, hosts: List[Dict[str, Any]], logs: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        payload = {
            "hosts": hosts,
            "logs": logs,
            "findings": findings
        }
        return self.request("POST", f"/api/agent/jobs/{scan_id}/results", payload=payload)


def _find_zap_bin() -> Optional[str]:
    for name in ("zap.bat", "zap.sh", "zaproxy", "zap"):
        p = shutil.which(name)
        if p:
            return p
    return None


def detect_local_engines() -> Dict[str, Any]:
    nmap_path = shutil.which("nmap")
    nuclei_path = shutil.which("nuclei")
    zap_path = _find_zap_bin()
    return {
        "native": {"installed": True, "version": VERSION},
        "nmap": {"installed": bool(nmap_path), "path": nmap_path or ""},
        "nuclei": {"installed": bool(nuclei_path), "path": nuclei_path or ""},
        "zap": {"installed": bool(zap_path), "path": zap_path or ""}
    }


# ==========================================
# NATIVE PROBE MODULES
# ==========================================

async def probe_tcp_port(host: str, port: int, timeout: float = 1.2) -> Tuple[bool, str]:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
    except Exception:
        return False, ""

    banner = ""
    try:
        if port in (80, 8080):
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 6379:
            writer.write(b"PING\r\nINFO\r\n")
        elif port in (21, 22, 25, 110, 143):
            pass  # wait for initial server greeting
        else:
            writer.write(b"\r\n")
        await writer.drain()

        read_coro = reader.read(1024)
        data = await asyncio.wait_for(read_coro, timeout=1.0)
        banner = data.decode("utf-8", errors="replace").strip()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return True, banner


def generate_native_port_finding(host: str, port: int, banner: str, service: str) -> Dict[str, Any]:
    b_ev = f"\nPorta {port}/TCP aperta su {host}.\nBanner: {banner}" if banner else f"\nPorta {port}/TCP aperta su {host}."

    if port == 23:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "telnet",
            "title": "Protocollo Telnet Esposto Senza Crittografia (Porta 23)",
            "severity": "high", "cvss": 8.5, "cve_ids": "", "cwe_id": "CWE-319",
            "source_engine": "native_probe",
            "description": "Il servizio Telnet trasmette credenziali amministrative e sessioni in chiaro sulla rete senza crittografia.",
            "evidence": b_ev,
            "remediation": "Disattivare immediatamente Telnet e sostituirlo con SSH v2 cifrato.",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1078 - Valid Accounts"
        }
    elif port == 6379:
        is_unauth = ("PONG" in banner or "redis_version" in banner)
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "redis",
            "title": "Database Redis Esposto Senza Autenticazione" if is_unauth else "Database Redis Esposto (Porta 6379)",
            "severity": "critical" if is_unauth else "high",
            "cvss": 9.8 if is_unauth else 8.0,
            "cve_ids": "CVE-2018-11235", "cwe_id": "CWE-306",
            "source_engine": "native_probe",
            "description": "L'istanza Redis consente accesso non autenticato permettendo la lettura/scrittura dei dati in memoria.",
            "evidence": b_ev,
            "remediation": "Abilitare requirepass nel file redis.conf ed eseguire il bind esclusivamente su localhost.",
            "mitre_tactic": "Credential Access", "mitre_technique": "T1552 - Unsecured Credentials"
        }
    elif port == 21:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "ftp",
            "title": "Servizio FTP Esposto in Chiaro (Porta 21)",
            "severity": "medium", "cvss": 7.0, "cwe_id": "CWE-319",
            "source_engine": "native_probe",
            "description": "Il servizio FTP accetta connessioni sulla porta standard 21. Se privo di TLS, trasferisce credenziali in chiaro.",
            "evidence": b_ev,
            "remediation": "Disabilitare FTP non cifrato e migrare a SFTP o FTPS.",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1078 - Valid Accounts"
        }
    elif port == 445:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "microsoft-ds",
            "title": "Servizio SMB Microsoft-DS (Porta 445) Rilevato",
            "severity": "medium", "cvss": 7.0, "cwe_id": "CWE-200",
            "source_engine": "native_probe",
            "description": "Protocollo SMB attivo su porta 445. Rischio di attacchi NTLM Relay ed exploit remoti se privo di firma obbligatoria.",
            "evidence": b_ev,
            "remediation": "Filtrare la porta 445 a livello perimetrale e abilitare SMB Signing obbligatorio sui server Windows.",
            "mitre_tactic": "Lateral Movement", "mitre_technique": "T1021.002 - SMB/Windows Admin Shares"
        }
    elif port in (3306, 5432, 1433):
        db_map = {3306: "MySQL", 5432: "PostgreSQL", 1433: "Microsoft SQL Server"}
        db_name = db_map.get(port, "Database")
        return {
            "host": host, "port": port, "protocol": "tcp", "service": service,
            "title": f"Database {db_name} Esposto sulla Rete (Porta {port})",
            "severity": "medium", "cvss": 6.5, "cwe_id": "CWE-306",
            "source_engine": "native_probe",
            "description": f"Il server di database {db_name} è direttamente accessibile sulla porta {port}/TCP.",
            "evidence": b_ev,
            "remediation": f"Isolare il database {db_name} e limitare l'accesso ai soli host applicativi autorizzati.",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1190 - Exploit Public-Facing Application"
        }
    elif port == 3389:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "ms-wbt-server",
            "title": "Servizio Desktop Remoto (RDP Porta 3389) Esposto",
            "severity": "low", "cvss": 4.0, "cwe_id": "CWE-200",
            "source_engine": "native_probe",
            "description": "Porta RDP 3389 aperta sul sistema. Esposta a tentativi di brute-force.",
            "evidence": b_ev,
            "remediation": "Isolare RDP dietro un Gateway VPN con MFA e abilitare Network Level Authentication (NLA).",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1078 - Valid Accounts"
        }
    elif port == 22:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "ssh",
            "title": "Servizio SSH Attivo sulla Porta 22",
            "severity": "low", "cvss": 3.7, "cwe_id": "CWE-200",
            "source_engine": "native_probe",
            "description": "Demone SSH raggiungibile su porta 22/TCP.",
            "evidence": b_ev,
            "remediation": "Disabilitare l'autenticazione password per SSH e utilizzare chiavi asimmetriche con fail2ban.",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1078 - Valid Accounts"
        }
    elif port in (80, 443, 8080, 8443):
        return {
            "host": host, "port": port, "protocol": "tcp", "service": service,
            "title": f"Superficie Web Attiva: Porta {port}/TCP ({service})",
            "severity": "info", "cvss": 0.0, "cwe_id": "CWE-200",
            "source_engine": "native_probe",
            "description": f"Servizio web attivo su porta {port}/TCP.",
            "evidence": b_ev,
            "remediation": "Mantenere aggiornato il server web e verificare gli header di protezione OWASP.",
            "mitre_tactic": "Discovery", "mitre_technique": "T1046 - Network Service Discovery"
        }
    else:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": service,
            "title": f"Porta Aperta Rilevata: {port}/TCP ({service})",
            "severity": "info", "cvss": 0.0, "cwe_id": "CWE-200",
            "source_engine": "native_probe",
            "description": f"La porta {port}/TCP ({service}) risulta aperta ed accetta connessioni.",
            "evidence": b_ev,
            "remediation": "Verificare la necessità del servizio e filtrarlo se non essenziale.",
            "mitre_tactic": "Discovery", "mitre_technique": "T1046 - Network Service Discovery"
        }


def inspect_ssl(host: str, port: int = 443, timeout: float = 3.0) -> List[Dict[str, Any]]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append({
                        "host": host,
                        "port": port,
                        "protocol": "tcp",
                        "service": "https",
                        "title": f"Protocollo Crittografico Deprecato Abilitato ({version})",
                        "severity": "medium",
                        "cvss": 5.9,
                        "cwe_id": "CWE-326",
                        "source_engine": "native_probe",
                        "description": f"Il server supporta una versione crittografica deprecata ({version}).",
                        "evidence": f"TLS version: {version}, Cipher: {cipher[0] if cipher else 'N/A'}",
                        "remediation": "Disabilitare versioni SSL/TLS inferiori a TLSv1.2 sul server.",
                        "mitre_tactic": "Initial Access",
                        "mitre_technique": "T1557 - Adversary-in-the-Middle"
                    })
    except Exception:
        pass
    return findings


def inspect_http_headers(host: str, port: int, insecure: bool = False, timeout: float = 3.5) -> List[Dict[str, Any]]:
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    headers = {"User-Agent": f"UrielScan-RemoteProbe/{VERSION}"}
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl._create_unverified_context() if (insecure or scheme == "https") else None

    resp_headers: Dict[str, str] = {}
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as he:
        resp_headers = {k.lower(): v for k, v in he.headers.items()}
    except Exception:
        return findings

    missing = []
    if "content-security-policy" not in resp_headers:
        missing.append("Content-Security-Policy")
    if scheme == "https" and "strict-transport-security" not in resp_headers:
        missing.append("Strict-Transport-Security (HSTS)")
    if "x-frame-options" not in resp_headers and "content-security-policy" not in resp_headers:
        missing.append("X-Frame-Options")
    if "x-content-type-options" not in resp_headers:
        missing.append("X-Content-Type-Options")

    if missing:
        findings.append({
            "host": host,
            "port": port,
            "protocol": "tcp",
            "service": scheme,
            "title": f"Mancanza di Header di Sicurezza HTTP ({len(missing)} assenti)",
            "severity": "medium",
            "cvss": 5.0,
            "cwe_id": "CWE-693",
            "source_engine": "native_probe",
            "description": "L'applicazione web non implementa header protettivi standard raccomandati da OWASP.",
            "evidence": f"URL: {url}\nHeader di sicurezza assenti: {', '.join(missing)}",
            "remediation": "Configurare il web server per includere HSTS, CSP, X-Frame-Options e X-Content-Type-Options.",
            "mitre_tactic": "Impact",
            "mitre_technique": "T1498 - Network Denial of Service"
        })

    server_h = resp_headers.get("server", "")
    powered_h = resp_headers.get("x-powered-by", "")
    disclosed = []
    if server_h and any(c.isdigit() for c in server_h):
        disclosed.append(f"Server: {server_h}")
    if powered_h:
        disclosed.append(f"X-Powered-By: {powered_h}")

    if disclosed:
        findings.append({
            "host": host,
            "port": port,
            "protocol": "tcp",
            "service": scheme,
            "title": "Information Disclosure: Versioni Software Rivelate negli Header",
            "severity": "low",
            "cvss": 3.7,
            "cwe_id": "CWE-200",
            "source_engine": "native_probe",
            "description": "Gli header di risposta rivelano nomi e versioni del software applicativo.",
            "evidence": "\n".join(disclosed),
            "remediation": "Disattivare l'emissione dei dettagli software negli header HTTP di risposta.",
            "mitre_tactic": "Reconnaissance",
            "mitre_technique": "T1592 - Gather Victim Host Information"
        })

    return findings


# ==========================================
# EXTERNAL SCANNERS: NMAP & NUCLEI
# ==========================================

def _sanitize_targets(targets_str: str) -> List[str]:
    clean: List[str] = []
    for entry in [t.strip() for t in targets_str.replace(",", " ").split() if t.strip()]:
        if entry.startswith("-"):
            continue
        cleaned = re.sub(r"^https?://", "", entry, flags=re.IGNORECASE).split("/")[0] if entry.lower().startswith(("http://", "https://")) else entry
        if _SAFE_TARGET_RE.match(cleaned) and not cleaned.startswith("-") and cleaned not in clean:
            clean.append(cleaned)
    return clean


def run_nmap_probe(targets: str, config: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return [], []

    cmd = [nmap_path, "-sV", "-oX", "-"]
    flags = config.get("nmap_flags") or config.get("nmap_args")
    has_pn = False
    if flags:
        raw_flags = shlex.split(flags) if isinstance(flags, str) else [str(x) for x in flags]
        for tok in raw_flags:
            if tok in _ALLOWED_NMAP_FLAGS:
                if tok in ("-Pn", "-P0"):
                    has_pn = True
                if tok not in cmd:
                    cmd.append(tok)
    if not has_pn:
        cmd.append("-Pn")

    target_list = _sanitize_targets(targets)
    if not target_list:
        return [], []
    cmd.append("--")
    cmd.extend(target_list)

    hosts: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        xml_out = proc.stdout
        if xml_out:
            root = ET.fromstring(xml_out)
            for host_el in root.findall("host"):
                addr_el = host_el.find("address")
                ip = addr_el.get("addr") if addr_el is not None else "unknown"
                hostname = ip
                hostnames_el = host_el.find("hostnames")
                if hostnames_el is not None:
                    hn_el = hostnames_el.find("hostname")
                    if hn_el is not None:
                        hostname = hn_el.get("name", ip)

                ports_list = []
                ports_el = host_el.find("ports")
                if ports_el is not None:
                    for port_el in ports_el.findall("port"):
                        port_id = int(port_el.get("portid", 0))
                        proto = port_el.get("protocol", "tcp")
                        state_el = port_el.find("state")
                        state = state_el.get("state", "open") if state_el is not None else "open"
                        if state != "open":
                            continue

                        service_el = port_el.find("service")
                        service_name = service_el.get("name", f"port-{port_id}") if service_el is not None else f"port-{port_id}"
                        product = service_el.get("product", "") if service_el is not None else ""
                        version = service_el.get("version", "") if service_el is not None else ""

                        ports_list.append({
                            "port": port_id,
                            "protocol": proto,
                            "service": service_name,
                            "product": product,
                            "version": version,
                            "state": "open"
                        })

                        for script_el in port_el.findall("script"):
                            s_id = script_el.get("id", "nmap-script")
                            s_output = script_el.get("output", "")
                            findings.append({
                                "host": hostname,
                                "port": port_id,
                                "protocol": proto,
                                "service": service_name,
                                "title": f"Nmap Script: {s_id}",
                                "severity": "medium" if "VULNERABLE" in s_output.upper() else "info",
                                "cvss": 6.0 if "VULNERABLE" in s_output.upper() else 0.0,
                                "source_engine": "nmap",
                                "description": f"Output dello script Nmap {s_id}",
                                "evidence": s_output,
                                "remediation": "Esaminare il servizio identificato e applicare le patch raccomandate."
                            })

                hosts.append({
                    "ip": ip,
                    "hostname": hostname,
                    "os": "Nmap Host Discovery",
                    "ports": ports_list
                })
    except Exception as e:
        print(f"[NMAP ERROR] {e}")

    return hosts, findings


def run_nuclei_probe(targets: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        return []

    target_list = [t.strip() for t in targets.replace(",", " ").split() if t.strip()]
    findings: List[Dict[str, Any]] = []

    for tgt in target_list:
        cmd = [nuclei_path, "-u", tgt, "-jsonl", "-silent"]
        tags = config.get("nuclei_tags")
        if tags and isinstance(tags, list):
            cmd.extend(["-tags", ",".join(tags)])
        severities = config.get("nuclei_severities") or config.get("nuclei_severity")
        if severities and isinstance(severities, list):
            cmd.extend(["-severity", ",".join(severities)])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    info = obj.get("info", {})
                    sev = info.get("severity", "info").lower()
                    findings.append({
                        "host": obj.get("host", tgt),
                        "port": obj.get("port"),
                        "protocol": obj.get("type", "http"),
                        "service": obj.get("type", "http"),
                        "title": info.get("name", obj.get("template-id", "Nuclei Finding")),
                        "severity": sev,
                        "cvss": float(info.get("classification", {}).get("cvss-score", 0.0) or 0.0),
                        "cve_ids": ", ".join(info.get("classification", {}).get("cve-id", [])) if isinstance(info.get("classification", {}).get("cve-id"), list) else str(info.get("classification", {}).get("cve-id", "")),
                        "cwe_id": ", ".join(info.get("classification", {}).get("cwe-id", [])) if isinstance(info.get("classification", {}).get("cwe-id"), list) else str(info.get("classification", {}).get("cwe-id", "")),
                        "source_engine": "nuclei",
                        "description": info.get("description", ""),
                        "evidence": obj.get("matched-at", ""),
                        "remediation": info.get("remediation", ""),
                    })
                except Exception:
                    pass
        except Exception as e:
            print(f"[NUCLEI ERROR] {e}")

    return findings


def run_zap_probe(targets: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    zap_path = _find_zap_bin()
    if not zap_path:
        return []

    findings: List[Dict[str, Any]] = []
    target_list = _sanitize_targets(targets)
    if not target_list:
        return []

    urls: List[str] = []
    for t in target_list:
        if t.lower().startswith(("http://", "https://")):
            urls.append(t)
        else:
            urls.append(f"https://{t}")
            urls.append(f"http://{t}")

    import tempfile, uuid
    for u in list(dict.fromkeys(urls))[:4]:
        out_xml = os.path.join(tempfile.gettempdir(), f"uriel_zap_{os.getpid()}_{uuid.uuid4().hex[:8]}.xml")
        try:
            subprocess.run([zap_path, "-cmd", "-quickurl", u, "-quickout", out_xml, "-quickprogress"], capture_output=True, text=True, timeout=240)
            if os.path.isfile(out_xml):
                root = ET.parse(out_xml).getroot()
                for site in root.findall("site"):
                    s_host = site.get("host") or u.split("://")[-1].split("/")[0].split(":")[0]
                    try:
                        s_port = int(site.get("port") or 80)
                    except Exception:
                        s_port = 80
                    alerts_el = site.find("alerts")
                    if alerts_el is None:
                        continue
                    for alert in alerts_el.findall("alertitem"):
                        title = (alert.findtext("alert") or "OWASP ZAP Finding").strip()
                        rc = int(alert.findtext("riskcode") or 0) if str(alert.findtext("riskcode") or "").isdigit() else 0
                        sev = "high" if rc >= 3 else ("medium" if rc == 2 else ("low" if rc == 1 else "info"))
                        cvss = 7.5 if sev == "high" else (5.3 if sev == "medium" else (3.1 if sev == "low" else 0.0))
                        cwe_raw = (alert.findtext("cweid") or "").strip()
                        desc = re.sub(r"<[^>]+>", " ", alert.findtext("desc") or title).strip()
                        sol = re.sub(r"<[^>]+>", " ", alert.findtext("solution") or "").strip()
                        findings.append({
                            "host": s_host,
                            "port": s_port,
                            "protocol": "tcp",
                            "service": "https" if s_port in (443, 8443) else "http",
                            "title": title,
                            "severity": sev,
                            "cvss": cvss,
                            "cve_ids": "",
                            "cwe_id": f"CWE-{cwe_raw}" if cwe_raw.isdigit() and int(cwe_raw) > 0 else "",
                            "source_engine": "zap",
                            "description": desc,
                            "evidence": u,
                            "remediation": sol,
                            "mitre_tactic": "Discovery",
                            "mitre_technique": "T1190 - Exploit Public-Facing Application",
                        })
        except Exception as e:
            print(f"[ZAP ERROR] {e}")
        finally:
            if os.path.isfile(out_xml):
                try:
                    os.remove(out_xml)
                except Exception:
                    pass
    return findings


# ==========================================
# SCAN EXECUTION CONTROLLER
# ==========================================

async def execute_job(client: ProbeClient, job: Dict[str, Any], insecure: bool = False) -> None:
    scan_id = job["id"]
    targets_str = job.get("targets", "")
    engines = job.get("engines", ["native"])
    config = job.get("config", {})

    logs: List[Dict[str, Any]] = [
        {"time": now_time_str(), "level": "INFO", "msg": f"Job #{scan_id} preso in carico dalla Probe Remota UrielScan v{VERSION}."}
    ]

    stop = client.update_progress(scan_id, 10, "Inizializzazione scansione remota...", logs)
    if stop:
        print(f"[JOB #{scan_id}] Interrotto dal server.")
        return

    hosts: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    try:
        # 1. Native Engine
        if "native" in engines or "native_net" in engines:
            logs.append({"time": now_time_str(), "level": "INFO", "msg": f"[Native Engine] Avvio port scan TCP su target: {targets_str}"})
            client.update_progress(scan_id, 25, "Scansione porte TCP nativa in corso...", logs)

            raw_entries = [t.strip() for t in targets_str.replace(",", " ").split() if t.strip() and not t.strip().startswith("-")]
            expanded_targets: List[str] = []
            for entry in raw_entries:
                is_url = entry.lower().startswith(("http://", "https://"))
                if not is_url and "/" in entry:
                    base_p, slash_p = entry.split("/", 1)
                    if slash_p.isdigit():
                        try:
                            net = ipaddress.ip_network(entry, strict=False)
                            c_ips = [str(ip) for ip in itertools.islice(net.hosts(), 256)]
                            if not c_ips and net.num_addresses == 1:
                                c_ips = [str(net.network_address)]
                            for cip in c_ips:
                                for qp in (80, 443, 445, 22, 8080, 3389):
                                    ok, _ = await probe_tcp_port(cip, qp, timeout=0.25)
                                    if ok:
                                        expanded_targets.append(cip)
                                        break
                            continue
                        except Exception:
                            pass
                expanded_targets.append(entry)

            for target in expanded_targets:
                clean_host = target.replace("http://", "").replace("https://", "").split("/")[0]
                if ":" in clean_host and not clean_host.startswith("["):
                    try:
                        ipaddress.IPv6Address(clean_host)
                    except Exception:
                        clean_host = clean_host.split(":")[0]
                try:
                    ip_addr = socket.gethostbyname(clean_host)
                except Exception:
                    ip_addr = clean_host

                open_ports = []
                for p in COMMON_PORTS:
                    is_open, banner = await probe_tcp_port(ip_addr, p)
                    if is_open:
                        svc = PORT_SERVICE_MAP.get(p, f"port-{p}")
                        open_ports.append({
                            "port": p,
                            "protocol": "tcp",
                            "service": svc,
                            "product": banner[:60] if banner else svc,
                            "version": "",
                            "state": "open",
                            "banner": banner
                        })
                        findings.append(generate_native_port_finding(clean_host, p, banner, svc))

                hosts.append({
                    "ip": ip_addr,
                    "hostname": clean_host,
                    "os": "Remote Probe Native Discovery",
                    "ports": open_ports
                })

                # SSL checks if 443 or 8443 open
                for ssl_p in (443, 8443):
                    if any(p["port"] == ssl_p for p in open_ports):
                        findings.extend(inspect_ssl(clean_host, port=ssl_p))

                # Web header checks
                for p in open_ports:
                    if p["port"] in (80, 443, 8080, 8443):
                        hdr_findings = inspect_http_headers(clean_host, port=p["port"], insecure=insecure)
                        findings.extend(hdr_findings)

            logs.append({"time": now_time_str(), "level": "INFO", "msg": f"[Native Engine] Scansione completata. {len(hosts)} host e {len(findings)} finding rilevati."})

        stop = client.update_progress(scan_id, 65, "Scansione nativa completata, verifica moduli esterni...", logs)
        if stop:
            print(f"[JOB #{scan_id}] Interrotto dal server.")
            return

        # 2. Nmap Engine
        if "nmap" in engines and shutil.which("nmap"):
            logs.append({"time": now_time_str(), "level": "INFO", "msg": "[Nmap Engine] Avvio motore Nmap locale..."})
            client.update_progress(scan_id, 70, "Esecuzione scansione Nmap locale...", logs)
            nmap_hosts, nmap_findings = await asyncio.to_thread(run_nmap_probe, targets_str, config)
            findings.extend(nmap_findings)
            for nh in nmap_hosts:
                matched = False
                for h in hosts:
                    if h["ip"] == nh["ip"]:
                        h["ports"].extend([p for p in nh["ports"] if p["port"] not in [x["port"] for x in h["ports"]]])
                        matched = True
                        break
                if not matched:
                    hosts.append(nh)
            logs.append({"time": now_time_str(), "level": "INFO", "msg": f"[Nmap Engine] Completato. {len(nmap_findings)} finding aggiuntivi."})

        # 3. Nuclei Engine
        if "nuclei" in engines and shutil.which("nuclei"):
            logs.append({"time": now_time_str(), "level": "INFO", "msg": "[Nuclei Engine] Avvio motore Nuclei locale..."})
            client.update_progress(scan_id, 80, "Esecuzione scansione Nuclei locale...", logs)
            nuclei_findings = await asyncio.to_thread(run_nuclei_probe, targets_str, config)
            findings.extend(nuclei_findings)
            logs.append({"time": now_time_str(), "level": "INFO", "msg": f"[Nuclei Engine] Completato. {len(nuclei_findings)} finding identificati."})

        # 4. OWASP ZAP Engine
        if "zap" in engines and _find_zap_bin():
            logs.append({"time": now_time_str(), "level": "INFO", "msg": "[OWASP ZAP Engine] Avvio scansione web ZAP locale..."})
            client.update_progress(scan_id, 90, "Esecuzione OWASP ZAP Web Scan locale...", logs)
            zap_findings = await asyncio.to_thread(run_zap_probe, targets_str, config)
            findings.extend(zap_findings)
            logs.append({"time": now_time_str(), "level": "INFO", "msg": f"[OWASP ZAP Engine] Completato. {len(zap_findings)} alert web rilevati."})

        logs.append({"time": now_time_str(), "level": "INFO", "msg": "Caricamento risultati finali completato."})
        client.upload_results(scan_id, hosts=hosts, logs=logs, findings=findings)
        print(f"[JOB #{scan_id}] Scansione completata con successo ({len(findings)} finding inviati al server).")
    except Exception as exc:
        logs.append({"time": now_time_str(), "level": "ERROR", "msg": f"Errore durante esecuzione job remoto: {exc}"})
        try:
            client.upload_results(scan_id, hosts=hosts, logs=logs, findings=findings)
        except Exception as upload_exc:
            print(f"[JOB #{scan_id}] Errore invio risultati parziali: {upload_exc}")


# ==========================================
# MAIN LOOP
# ==========================================

async def run_probe_loop(
    server: str,
    token: str,
    interval: int = 5,
    insecure: bool = False,
    run_once: bool = False,
    ca_bundle: Optional[str] = None,
) -> None:
    client = ProbeClient(server, token, insecure=insecure, ca_bundle=ca_bundle)
    engines = detect_local_engines()

    print("=" * 60)
    print(f" UrielScan Standalone Remote Probe Agent v{VERSION}")
    print(f" Server:   {server}")
    print(f" Token:    {token[:8]}...")
    print(f" Insecure: {insecure}")
    print(f" Engines:  Native=OK, Nmap={'OK' if engines['nmap']['installed'] else 'NO'}, Nuclei={'OK' if engines['nuclei']['installed'] else 'NO'}")
    print("=" * 60)

    while True:
        try:
            # 1. Heartbeat
            hb = client.heartbeat(engines)
            print(f"[{now_time_str()}] Heartbeat inviato con successo (Agent ID: {hb.get('agent_id')}).")

            # 2. Check for next queued job
            job = client.get_next_job()
            if job:
                print(f"[{now_time_str()}] Job #{job['id']} ('{job.get('name')}') assegnato! Avvio esecuzione...")
                await execute_job(client, job, insecure=insecure)
            else:
                # No job queued
                pass

        except Exception as e:
            print(f"[{now_time_str()}] Errore ciclo probe: {e}")

        if run_once:
            break

        await asyncio.sleep(interval)


def _runtime_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _configure_windowless_streams() -> None:
    """Redirect None stdout/stderr (PyInstaller --noconsole / SYSTEM task) cleanly to probe.log."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    import tempfile
    candidates = [_runtime_base_dir() / "probe.log", Path(tempfile.gettempdir()) / "urielscan_probe.log"]
    log_fh = None
    for cand in candidates:
        try:
            cand.parent.mkdir(parents=True, exist_ok=True)
            log_fh = open(cand, "a", encoding="utf-8", buffering=1)
            break
        except OSError:
            continue
    if log_fh is None:
        log_fh = open(os.devnull, "w", encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = log_fh
    if sys.stderr is None:
        sys.stderr = log_fh


def _extract_msi_config_payload(msi_path: Path) -> Dict[str, Any]:
    raw = msi_path.read_bytes()
    start_idx = raw.find(CFG_MARKER_START)
    if start_idx == -1:
        raise RuntimeError(f"Configuration marker not found inside MSI: {msi_path}")
    payload_start = start_idx + len(CFG_MARKER_START)
    end_idx = raw.find(CFG_MARKER_END, payload_start)
    if end_idx == -1:
        raise RuntimeError(f"Unterminated configuration marker inside MSI: {msi_path}")
    raw_json = raw[payload_start:end_idx].decode("utf-8").strip()
    return json.loads(raw_json)


def _find_msi_with_config(raw_candidates: List[str], log_fn) -> Optional[Tuple[Path, Dict[str, Any]]]:
    for raw in raw_candidates:
        cleaned = (raw or "").strip().strip('"')
        if not cleaned or cleaned.startswith("["):
            continue
        p = Path(cleaned)
        if not p.is_file():
            continue
        try:
            cfg = _extract_msi_config_payload(p)
            if isinstance(cfg, dict) and cfg.get("token"):
                log_fn(f"Loaded config from candidate MSI: {p}")
                return p, cfg
        except Exception as exc:
            log_fn(f"Skipped candidate MSI {p}: {exc}")

    # Fallback: search recent *.msi files in C:\Windows\Installer (last 15 min, newest 8)
    win_inst = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Installer"
    if win_inst.is_dir():
        now = time.time()
        recent: List[Tuple[float, Path]] = []
        try:
            for item in win_inst.iterdir():
                if item.is_file() and item.suffix.lower() == ".msi":
                    try:
                        mt = item.stat().st_mtime
                        if now - mt <= 900.0:
                            recent.append((mt, item))
                    except OSError:
                        pass
        except OSError:
            pass
        recent.sort(key=lambda x: x[0], reverse=True)
        for _, msi_cand in recent[:8]:
            try:
                cfg = _extract_msi_config_payload(msi_cand)
                if isinstance(cfg, dict) and cfg.get("token"):
                    log_fn(f"Loaded config from Windows Installer cache: {msi_cand}")
                    return msi_cand, cfg
            except Exception:
                continue
    return None


def _install_from_msi_data(raw_data: str) -> None:
    parts: Dict[str, str] = {}
    for seg in (raw_data or "").split(";"):
        if "=" in seg:
            k, v = seg.split("=", 1)
            parts[k.strip().lower()] = v.strip()

    base_dir = _runtime_base_dir()
    raw_dir = (parts.get("dir") or "").strip().strip('"')
    if not raw_dir or raw_dir.startswith("["):
        raw_dir = str(base_dir)
    install_dir = Path(raw_dir).resolve()
    install_dir.mkdir(parents=True, exist_ok=True)
    log_path = install_dir / "msi_install.log"

    def _msi_log(msg: str) -> None:
        line = f"[{datetime.now(timezone.utc).isoformat()}] {msg}\n"
        try:
            with open(log_path, "a", encoding="utf-8") as lf:
                lf.write(line)
        except OSError:
            pass

    _msi_log(f"Starting MSI post-install (raw_data={raw_data!r})")
    found = _find_msi_with_config([parts.get("db", ""), parts.get("msi", "")], _msi_log)
    if not found:
        cfg_file = install_dir / "probe_config.json"
        if cfg_file.exists():
            _msi_log("Using pre-existing probe_config.json")
            return
        _msi_log("ERROR: Unable to locate MSI payload configuration.")
        raise RuntimeError("Installer database config payload not found.")

    _, cfg = found

    ca_pem = str(cfg.pop("ca_pem", "") or "").strip()
    ca_path = install_dir / "cacert.pem"
    if ca_pem:
        parts_pem = [ca_pem]
        if certifi is not None:
            try:
                parts_pem.append(Path(certifi.where()).read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass
        ca_path.write_text("\n".join(parts_pem) + "\n", encoding="utf-8")
        cfg["cacert"] = str(ca_path)

    cfg_path = install_dir / "probe_config.json"
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    _msi_log(f"Wrote probe_config.json for server={cfg.get('server_url')}")

    exe_path = Path(sys.executable).resolve() if getattr(sys, "frozen", False) else (install_dir / "urielscan_probe.exe")
    if os.name == "nt" and exe_path.exists() and os.environ.get("URIELSCAN_MSI_SKIP_TASK") != "1":
        task_name = "UrielScanRemoteProbe"
        cmd_tr = f'"{exe_path}" --config "{cfg_path}"'
        r1 = subprocess.run(
            ["schtasks", "/Create", "/F", "/TN", task_name, "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST", "/TR", cmd_tr],
            capture_output=True,
            text=True,
            check=False,
        )
        r2 = subprocess.run(["schtasks", "/Run", "/TN", task_name], capture_output=True, text=True, check=False)
        _msi_log(f"schtasks Create rc={r1.returncode}, Run rc={r2.returncode}")
    else:
        _msi_log("Skipped schtasks registration.")


def _uninstall_probe_service(install_dir_raw: str) -> None:
    if os.name == "nt":
        task_name = "UrielScanRemoteProbe"
        subprocess.run(["schtasks", "/End", "/TN", task_name], capture_output=True, check=False)
        subprocess.run(["schtasks", "/Delete", "/F", "/TN", task_name], capture_output=True, check=False)
    cleaned_dir = install_dir_raw.strip()
    if cleaned_dir.lower().startswith("dir="):
        cleaned_dir = cleaned_dir.split("=", 1)[1].split(";", 1)[0].strip()
    base_dir = Path(cleaned_dir).resolve() if cleaned_dir else _runtime_base_dir()
    for fname in ("probe_config.json", "cacert.pem"):
        fp = base_dir / fname
        if fp.exists():
            try:
                fp.unlink()
            except Exception:
                pass


def main():
    _configure_windowless_streams()

    parser = argparse.ArgumentParser(description="UrielScan Standalone Remote Probe Agent")
    parser.add_argument("--config", default="", help="Percorso probe_config.json (auto-rilevato nella cartella dell'eseguibile se presente)")
    parser.add_argument("--server", default="", help="UrielScan server URL (es. https://uriel.msp.com o http://127.0.0.1:8000)")
    parser.add_argument("--token", default="", help="Agent token (preferisci variabile URIELSCAN_AGENT_TOKEN o --token-file)")
    parser.add_argument("--token-file", default="", help="Percorso file contenente il token dell'agente")
    parser.add_argument("--cacert", default="", help="Percorso bundle CA PEM per verifica TLS del server")
    parser.add_argument("--interval", type=int, default=5, help="Intervallo polling e heartbeat in secondi (default: 5)")
    parser.add_argument("--insecure", action="store_true", help="Disabilita verifica certificato SSL del server (per certificati self-signed)")
    parser.add_argument("--once", action="store_true", help="Esegue un solo ciclo di heartbeat/job ed esce")
    parser.add_argument("--install-from-msi-data", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--uninstall-probe", default=None, help=argparse.SUPPRESS)

    args = parser.parse_args()

    if args.install_from_msi_data is not None:
        _install_from_msi_data(args.install_from_msi_data)
        return

    if args.uninstall_probe is not None:
        _uninstall_probe_service(args.uninstall_probe)
        return

    base_dir = _runtime_base_dir()
    cfg: Dict[str, Any] = {}
    cfg_candidate = Path(args.config) if args.config else (base_dir / "probe_config.json")
    if cfg_candidate.exists():
        try:
            cfg = json.loads(cfg_candidate.read_text(encoding="utf-8"))
        except Exception as exc:
            parser.error(f"Impossibile leggere file di configurazione {cfg_candidate}: {exc}")

    server = (args.server or cfg.get("server_url") or os.environ.get("URIELSCAN_SERVER_URL", "")).strip()
    if not server:
        parser.error("--server richiesto (oppure impostabile via probe_config.json).")

    token = (args.token or os.environ.get("URIELSCAN_AGENT_TOKEN", "") or cfg.get("token", "")).strip()
    if not token and args.token_file:
        with open(args.token_file, "r", encoding="utf-8") as tf:
            token = tf.read().strip()
    if not token:
        parser.error("Token richiesto: passa --token, --token-file, probe_config.json oppure imposta URIELSCAN_AGENT_TOKEN.")

    ca_bundle = (args.cacert or cfg.get("cacert") or "").strip() or None
    if not ca_bundle and (base_dir / "cacert.pem").exists():
        ca_bundle = str(base_dir / "cacert.pem")

    insecure = bool(args.insecure or cfg.get("insecure", False))
    interval = int(args.interval if args.interval != 5 else cfg.get("interval", 5))

    try:
        asyncio.run(run_probe_loop(
            server=server,
            token=token,
            interval=interval,
            insecure=insecure,
            run_once=args.once,
            ca_bundle=ca_bundle,
        ))
    except KeyboardInterrupt:
        print("\nProbe arrestata dall'utente.")


if __name__ == "__main__":
    main()
