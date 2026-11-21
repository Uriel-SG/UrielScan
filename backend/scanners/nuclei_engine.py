import os
import sys
import json
import shutil
import platform
import subprocess
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
import httpx

from backend.scanners.archive_utils import safe_extract_zip, stream_download
from backend.scanners.tor_engine import validate_proxy_url

BASE_DIR = Path(__file__).resolve().parent.parent.parent
BIN_DIR = BASE_DIR / "bin"
BIN_DIR.mkdir(parents=True, exist_ok=True)


def get_nuclei_bin_path() -> Optional[str]:
    # Check bin/ in workspace
    local_name = "nuclei.exe" if platform.system() == "Windows" else "nuclei"
    local_path = BIN_DIR / local_name
    if local_path.is_file():
        return str(local_path)

    # Check common Windows paths
    if platform.system() == "Windows":
        known = [r"C:\Nuclei\nuclei.exe", r"C:\Program Files\Nuclei\nuclei.exe"]
        for k in known:
            if os.path.isfile(k):
                return k

    # Check system PATH
    system_path = shutil.which("nuclei")
    if system_path:
        return system_path

    return None


def detect_nuclei() -> Dict[str, Any]:
    npath = get_nuclei_bin_path()
    if not npath:
        return {
            "installed": False,
            "version": "",
            "path": ""
        }

    version = "Available"
    try:
        proc = subprocess.run([npath, "-version"], capture_output=True, text=True, timeout=5)
        out = (proc.stdout or "") + (proc.stderr or "")
        import re
        m = re.search(r"v([0-9\.]+)", out)
        if m:
            version = f"v{m.group(1)}"
        else:
            first_line = out.splitlines()[0] if out.splitlines() else "v3.x"
            version = first_line
    except Exception:
        pass

    return {
        "installed": True,
        "version": version,
        "path": npath
    }


async def install_nuclei() -> Dict[str, Any]:
    os_name = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {
        "windows": "windows",
        "linux": "linux",
        "darwin": "macos"
    }
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64"
    }

    target_os = os_map.get(os_name, "windows")
    target_arch = arch_map.get(machine, "amd64")

    # If already installed, verify
    det = detect_nuclei()
    if det["installed"]:
        return {
            "success": True,
            "version": det["version"],
            "path": det["path"],
            "message": f"Nuclei è già installato nel sistema: {det['path']} ({det['version']})"
        }

    # Fetch release from GitHub API
    api_url = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(api_url, headers={"User-Agent": "UrielScan-Installer"})
            if resp.status_code != 200:
                return {
                    "success": False,
                    "version": "",
                    "path": "",
                    "message": f"Impossibile contattare GitHub API: HTTP {resp.status_code}"
                }

            release_data = resp.json()
            tag = release_data.get("tag_name", "latest")
            assets = release_data.get("assets", [])

            # Find matching zip asset
            asset_download_url = None
            for asset in assets:
                name = asset.get("name", "").lower()
                if target_os in name and target_arch in name and name.endswith(".zip"):
                    asset_download_url = asset.get("browser_download_url")
                    break

            if not asset_download_url:
                return {
                    "success": False,
                    "version": "",
                    "path": "",
                    "message": f"Nessun asset compatibile trovato per {target_os}_{target_arch}."
                }

            # Download & safely extract zip
            zip_temp = BIN_DIR / "nuclei_download.zip"
            await stream_download(asset_download_url, zip_temp, timeout=180.0)
            try:
                safe_extract_zip(zip_temp, BIN_DIR)
            finally:
                if zip_temp.exists():
                    zip_temp.unlink(missing_ok=True)

            binary_name = "nuclei.exe" if platform.system() == "Windows" else "nuclei"
            bin_final = BIN_DIR / binary_name
            if not bin_final.exists():
                return {
                    "success": False,
                    "version": "",
                    "path": "",
                    "message": "Estrazione completata ma il binario nuclei non è stato trovato nella directory bin/."
                }

            if platform.system() != "Windows":
                os.chmod(str(bin_final), 0o755)

            new_det = detect_nuclei()
            return {
                "success": True,
                "version": new_det["version"],
                "path": str(bin_final),
                "message": f"Nuclei {tag} installato con successo in {bin_final}"
            }
    except Exception as e:
        return {
            "success": False,
            "version": "",
            "path": "",
            "message": f"Eccezione durante l'installazione di Nuclei: {str(e)}"
        }


async def run_nuclei_scan(
    targets: str,
    severities: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str, str], Any]] = None,
    proxy_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    det = detect_nuclei()

    def log(level: str, msg: str):
        if log_callback:
            try:
                res = log_callback(level, msg)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception:
                pass

    if not det["installed"]:
        log("WARN", "Nuclei non è installato sul sistema. Le scansioni template nuclei verranno delegate al motore web nativo.")
        return []

    # Build targets list
    raw_targets = [t.strip() for t in targets.replace(",", " ").split() if t.strip()]
    if not raw_targets:
        return []

    # Format targets: prepare URLs
    formatted_targets = []
    for t in raw_targets:
        if t.startswith("http://") or t.startswith("https://"):
            formatted_targets.append(t)
        else:
            # Add both http and https for thoroughness
            formatted_targets.append(f"http://{t}")
            formatted_targets.append(f"https://{t}")

    # Write target list to unique temporary file to avoid parallel scan collisions
    import uuid
    temp_target_file = BIN_DIR / f"targets_{os.getpid()}_{uuid.uuid4().hex[:8]}.txt"
    with open(temp_target_file, "w", encoding="utf-8") as f:
        for u in formatted_targets:
            f.write(f"{u}\n")

    args = [
        det["path"],
        "-list", str(temp_target_file),
        "-jsonl",
        "-silent",
        "-nc",
        "-timeout", "15" if proxy_url else "5",
        "-retries", "2" if proxy_url else "1"
    ]

    if proxy_url:
        validated_proxy = validate_proxy_url(proxy_url)
        if validated_proxy:
            # Go/Nuclei fastdialer expects socks5:// rather than socks5h:// and resolves remotely via proxy
            nuclei_proxy = (
                "socks5://" + validated_proxy[len("socks5h://"):]
                if validated_proxy.lower().startswith("socks5h://")
                else validated_proxy
            )
            args.extend(["-proxy", nuclei_proxy])
            log("INFO", f"[Nuclei] Routing tramite proxy attivo ({nuclei_proxy.split('@')[-1]})")

    if severities and len(severities) > 0:
        args.extend(["-severity", ",".join(severities)])
    else:
        args.extend(["-severity", "critical,high,medium,low"])

    if tags and len(tags) > 0:
        args.extend(["-tags", ",".join(tags)])

    log("INFO", f"Avvio scansione Nuclei su {len(formatted_targets)} URL target...")

    findings = []
    scan_timeout = 480.0 if proxy_url else 300.0
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=scan_timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            log("ERROR", f"Timeout globale Nuclei raggiunto ({int(scan_timeout)}s): processo terminato.")
            return []
    except Exception as e:
        log("ERROR", f"Errore durante l'esecuzione di Nuclei: {str(e)}")
        return []
    finally:
        if temp_target_file.exists():
            try:
                temp_target_file.unlink()
            except Exception:
                pass

    lines = stdout.decode("utf-8", errors="replace").splitlines()
    for line in lines:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
            info = item.get("info", {})
            classification = info.get("classification", {})

            template_id = item.get("template-id", "")
            name = info.get("name", template_id)
            severity = info.get("severity", "info").lower()

            cve_ids = classification.get("cve-id") or []
            if isinstance(cve_ids, list):
                cve_str = ", ".join(cve_ids)
            else:
                cve_str = str(cve_ids)

            cwe_ids = classification.get("cwe-id") or []
            cwe_str = ", ".join(cwe_ids) if isinstance(cwe_ids, list) else str(cwe_ids)

            cvss_score = float(classification.get("cvss-score") or (
                9.5 if severity == "critical" else (7.5 if severity == "high" else (5.0 if severity == "medium" else 2.5))
            ))

            matched_at = item.get("matched-at", "")
            host = item.get("host", "")
            port = int(item.get("port") or (443 if "https://" in matched_at else 80))

            evidence = f"Matched at: {matched_at}\nTemplate: {template_id}"
            if item.get("extracted-results"):
                evidence += f"\nExtracted: {item['extracted-results']}"
            if item.get("curl-command"):
                evidence += f"\nCurl Reproduction:\n{item['curl-command']}"

            finding = {
                "host": host or matched_at,
                "port": port,
                "protocol": "tcp",
                "service": "http/https",
                "title": f"[Nuclei] {name}",
                "severity": severity,
                "cvss": cvss_score,
                "cve_ids": cve_str,
                "cwe_id": cwe_str or "CWE-20",
                "source_engine": "nuclei",
                "description": info.get("description", f"Nuclei template {template_id} triggered positive verification."),
                "evidence": evidence[:2500],
                "remediation": info.get("remediation", "Applicare gli aggiornamenti di sicurezza o disattivare la risorsa vulnerabile esposta."),
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1190 - Exploit Public-Facing Application",
                "ai_insight": f"Identificato tramite il template ufficiale Nuclei ({template_id})."
            }
            findings.append(finding)
        except Exception:
            continue

    log("INFO", f"Scansione Nuclei completata: {len(findings)} vulnerabilità identificate.")
    return findings
