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
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

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
    def __init__(self, server_url: str, token: str, insecure: bool = False):
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.insecure = insecure
        self.ssl_context = ssl._create_unverified_context() if insecure else None

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
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ssl_context) as resp:
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


def detect_local_engines() -> Dict[str, Any]:
    nmap_path = shutil.which("nmap")
    nuclei_path = shutil.which("nuclei")
    return {
        "native": {"installed": True, "version": VERSION},
        "nmap": {"installed": bool(nmap_path), "path": nmap_path or ""},
        "nuclei": {"installed": bool(nuclei_path), "path": nuclei_path or ""}
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

def run_nmap_probe(targets: str, config: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return [], []

    cmd = [nmap_path, "-sV", "-oX", "-"]
    flags = config.get("nmap_flags") or config.get("nmap_args")
    if flags:
        cmd.extend(flags.split())
    else:
        cmd.append("-Pn")

    target_list = [t.strip() for t in targets.replace(",", " ").split() if t.strip()]
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

    # 1. Native Engine
    if "native" in engines or "native_net" in engines:
        logs.append({"time": now_time_str(), "level": "INFO", "msg": f"[Native Engine] Avvio port scan TCP su target: {targets_str}"})
        client.update_progress(scan_id, 25, "Scansione porte TCP nativa in corso...", logs)

        raw_targets = [t.strip() for t in targets_str.replace(",", " ").split() if t.strip()]
        for target in raw_targets:
            clean_host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
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

            # SSL checks if 443 open
            if any(p["port"] in (443, 8443) for p in open_ports):
                ssl_findings = inspect_ssl(clean_host, port=443)
                findings.extend(ssl_findings)

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
        nmap_hosts, nmap_findings = run_nmap_probe(targets_str, config)
        findings.extend(nmap_findings)
        # Merge nmap hosts
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
        client.update_progress(scan_id, 85, "Esecuzione scansione Nuclei locale...", logs)
        nuclei_findings = run_nuclei_probe(targets_str, config)
        findings.extend(nuclei_findings)
        logs.append({"time": now_time_str(), "level": "INFO", "msg": f"[Nuclei Engine] Completato. {len(nuclei_findings)} finding identificati."})

    logs.append({"time": now_time_str(), "level": "INFO", "msg": "Caricamento risultati finali completato."})
    client.upload_results(scan_id, hosts=hosts, logs=logs, findings=findings)
    print(f"[JOB #{scan_id}] Scansione completata con successo ({len(findings)} finding inviati al server).")


# ==========================================
# MAIN LOOP
# ==========================================

async def run_probe_loop(server: str, token: str, interval: int = 5, insecure: bool = False, run_once: bool = False) -> None:
    client = ProbeClient(server, token, insecure=insecure)
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


def main():
    parser = argparse.ArgumentParser(description="UrielScan Standalone Remote Probe Agent")
    parser.add_argument("--server", required=True, help="UrielScan server URL (es. https://uriel.msp.com o http://127.0.0.1:8000)")
    parser.add_argument("--token", required=True, help="Agent authentication token generato dalla dashboard MSSP")
    parser.add_argument("--interval", type=int, default=5, help="Intervallo polling e heartbeat in secondi (default: 5)")
    parser.add_argument("--insecure", action="store_true", help="Disabilita verifica certificato SSL del server (per certificati self-signed)")
    parser.add_argument("--once", action="store_true", help="Esegue un solo ciclo di heartbeat/job ed esce")

    args = parser.parse_args()

    try:
        asyncio.run(run_probe_loop(
            server=args.server,
            token=args.token,
            interval=args.interval,
            insecure=args.insecure,
            run_once=args.once
        ))
    except KeyboardInterrupt:
        print("\nProbe arrestata dall'utente.")


if __name__ == "__main__":
    main()
