import os
import re
import html
import json
import time
import uuid
import shutil
import asyncio
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent.parent
BIN_DIR = BASE_DIR / "bin"
BIN_DIR.mkdir(parents=True, exist_ok=True)

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_SAFE_URL_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]/_?=&%]+$")

KNOWN_ZAP_PATHS = [
    r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat",
    r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
    r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
    "/usr/share/zaproxy/zap.sh",
    "/usr/bin/zaproxy",
    "/usr/local/bin/zaproxy",
    "/opt/zaproxy/zap.sh",
    "/Applications/ZAP.app/Contents/Java/zap.sh",
]


def _clean_html(raw: Any) -> str:
    txt = _HTML_TAG_RE.sub(" ", str(raw or ""))
    txt = html.unescape(txt)
    return re.sub(r"\s+", " ", txt).strip()


def _zap_api_request(base_url: str, path: str, params: Optional[Dict[str, str]] = None, api_key: str = "", timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    q = dict(params or {})
    if api_key:
        q["apikey"] = api_key
    qs = f"?{urllib.parse.urlencode(q)}" if q else ""
    url = f"{base_url.rstrip('/')}{path}{qs}"
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "UrielScan-ZAP/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return data if isinstance(data, dict) else None
    except Exception:
        return None


def detect_zap() -> Dict[str, Any]:
    """Detects either a running OWASP ZAP daemon API or a local OWASP ZAP CLI installation."""
    zap_url = os.getenv("URIELSCAN_ZAP_URL", "http://127.0.0.1:8080").strip()
    api_key = os.getenv("URIELSCAN_ZAP_API_KEY", "").strip()

    # 1. Fast probe against running ZAP API daemon (0.4s so UI status never stalls)
    if zap_url:
        ver_data = _zap_api_request(zap_url, "/JSON/core/view/version/", api_key=api_key, timeout=0.45)
        if ver_data and "version" in ver_data:
            return {
                "installed": True,
                "mode": "api",
                "version": f"ZAP {ver_data['version']} (API)",
                "path": zap_url,
            }

    # 2. Check local PATH binaries
    for cmd_name in ("zap.bat", "zap.sh", "zaproxy", "zap"):
        found = shutil.which(cmd_name)
        if found:
            return {
                "installed": True,
                "mode": "cli",
                "version": "OWASP ZAP CLI",
                "path": found,
            }

    # 3. Check standard install directories and BIN_DIR
    for p_str in KNOWN_ZAP_PATHS:
        if Path(p_str).is_file():
            return {
                "installed": True,
                "mode": "cli",
                "version": "OWASP ZAP CLI",
                "path": p_str,
            }

    for sub_bin in BIN_DIR.glob("**/zap.*"):
        if sub_bin.name.lower() in ("zap.bat", "zap.sh") and sub_bin.is_file():
            return {
                "installed": True,
                "mode": "cli",
                "version": "OWASP ZAP CLI",
                "path": str(sub_bin),
            }

    return {"installed": False, "mode": "none", "version": "", "path": ""}


def _map_zap_risk(riskcode: Any, confidence: Any, title: str) -> Tuple[str, float]:
    try:
        rc = int(riskcode)
    except Exception:
        t = str(riskcode or "").lower()
        if "high" in t:
            rc = 3
        elif "med" in t:
            rc = 2
        elif "low" in t:
            rc = 1
        else:
            rc = 0

    try:
        conf = int(confidence)
    except Exception:
        conf = 2

    t_low = title.lower()
    if rc == 3 and conf >= 2 and any(
        kw in t_low for kw in ("sql injection", "remote os command", "command injection", "remote code", "path traversal", "xxe")
    ):
        return "critical", 9.3

    if rc >= 3:
        return "high", 7.5
    if rc == 2:
        return "medium", 5.3
    if rc == 1:
        return "low", 3.1
    return "info", 0.0


def _mitre_for_zap_alert(title: str, cwe_id: str) -> Tuple[str, str]:
    t = title.lower()
    if any(k in t for k in ("sql injection", "xss", "cross site scripting", "command", "traversal")):
        return "Initial Access", "T1190 - Exploit Public-Facing Application"
    if any(k in t for k in ("header", "csp", "hsts", "x-frame", "cookie", "cors")):
        return "Defense Evasion", "T1562 - Impair Defenses"
    if any(k in t for k in ("server leaks", "version", "directory", ".git", ".env", "banner")):
        return "Reconnaissance", "T1592 - Gather Victim Host Information"
    return "Discovery", f"T1190 ({cwe_id or 'Web App Vulnerability'})"


def _extract_host_port(url_str: str, fallback_host: str = "") -> Tuple[str, int, str]:
    s = (url_str or "").strip()
    if not s:
        return fallback_host or "localhost", 80, "http"
    parsed = urllib.parse.urlparse(s if "://" in s else f"http://{s}")
    scheme = parsed.scheme.lower() or "http"
    host = (parsed.hostname or fallback_host or "localhost").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    service = "https" if scheme == "https" or port in (443, 8443) else "http"
    return host, port, service


def parse_zap_alerts(alerts: List[Dict[str, Any]], fallback_host: str = "") -> List[Dict[str, Any]]:
    """Converts OWASP ZAP REST API JSON alerts into normalized UrielScan findings."""
    findings: List[Dict[str, Any]] = []
    for a in alerts:
        if not isinstance(a, dict):
            continue
        title = str(a.get("alert") or a.get("name") or "OWASP ZAP Finding").strip()
        sev, cvss = _map_zap_risk(a.get("riskcode", a.get("risk", 0)), a.get("confidence", 2), title)
        url_val = str(a.get("url") or "")
        host, port, service = _extract_host_port(url_val, fallback_host)
        raw_cwe = str(a.get("cweid") or "").strip()
        cwe_id = f"CWE-{raw_cwe}" if raw_cwe.isdigit() and int(raw_cwe) > 0 else ""

        ev_parts = [p for p in [
            f"URL: {url_val}" if url_val else "",
            f"Param: {a.get('param')}" if a.get("param") else "",
            f"Attack: {a.get('attack')}" if a.get("attack") else "",
            f"Evidence: {a.get('evidence')}" if a.get("evidence") else "",
        ] if p]

        tactic, technique = _mitre_for_zap_alert(title, cwe_id)
        findings.append({
            "host": host,
            "port": port,
            "protocol": "tcp",
            "service": service,
            "title": title,
            "severity": sev,
            "cvss": cvss,
            "cve_ids": "",
            "cwe_id": cwe_id,
            "source_engine": "zap",
            "description": _clean_html(a.get("description") or a.get("desc") or title),
            "evidence": " | ".join(ev_parts)[:800],
            "remediation": _clean_html(a.get("solution") or ""),
            "mitre_tactic": tactic,
            "mitre_technique": technique,
        })
    return findings


def parse_zap_xml(xml_content: str, fallback_host: str = "") -> List[Dict[str, Any]]:
    """Parses OWASP ZAP XML quickout report into normalized UrielScan findings."""
    findings: List[Dict[str, Any]] = []
    if not xml_content or not xml_content.strip():
        return findings

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return findings

    for site in root.findall("site"):
        site_name = site.get("name") or ""
        site_host = site.get("host") or fallback_host
        try:
            site_port = int(site.get("port") or 0)
        except Exception:
            site_port = 0

        alerts_el = site.find("alerts")
        if alerts_el is None:
            continue

        for alert in alerts_el.findall("alertitem"):
            title = (alert.findtext("alert") or alert.findtext("name") or "OWASP ZAP Finding").strip()
            riskcode = alert.findtext("riskcode") or alert.findtext("riskdesc") or "0"
            confidence = alert.findtext("confidence") or "2"
            sev, cvss = _map_zap_risk(riskcode, confidence, title)
            raw_cwe = (alert.findtext("cweid") or "").strip()
            cwe_id = f"CWE-{raw_cwe}" if raw_cwe.isdigit() and int(raw_cwe) > 0 else ""

            desc = _clean_html(alert.findtext("desc") or title)
            sol = _clean_html(alert.findtext("solution") or "")

            instance_urls: List[str] = []
            sample_uri = site_name
            sample_ev = ""
            instances = alert.find("instances")
            if instances is not None:
                for inst in instances.findall("instance")[:5]:
                    uri = (inst.findtext("uri") or "").strip()
                    param = (inst.findtext("param") or "").strip()
                    ev = (inst.findtext("evidence") or "").strip()
                    if uri and not sample_uri:
                        sample_uri = uri
                    if ev and not sample_ev:
                        sample_ev = ev
                    if uri:
                        instance_urls.append(f"{uri}{f' (param={param})' if param else ''}")

            host, port, service = _extract_host_port(sample_uri or site_name, site_host)
            if site_port and not port:
                port = site_port

            ev_text = "; ".join(instance_urls[:3])
            if sample_ev:
                ev_text = f"{ev_text} | Match: {sample_ev}" if ev_text else f"Match: {sample_ev}"

            tactic, technique = _mitre_for_zap_alert(title, cwe_id)
            findings.append({
                "host": host,
                "port": port,
                "protocol": "tcp",
                "service": service,
                "title": title,
                "severity": sev,
                "cvss": cvss,
                "cve_ids": "",
                "cwe_id": cwe_id,
                "source_engine": "zap",
                "description": desc,
                "evidence": ev_text[:800],
                "remediation": sol,
                "mitre_tactic": tactic,
                "mitre_technique": technique,
            })
    return findings


def _format_web_urls(targets: str) -> List[str]:
    urls: List[str] = []
    for raw in [t.strip() for t in targets.replace(",", " ").split() if t.strip()]:
        if raw.startswith("-"):
            continue
        if not _SAFE_URL_HOST_RE.match(raw):
            continue
        if raw.lower().startswith(("http://", "https://")):
            urls.append(raw)
        else:
            # Prefer HTTPS and HTTP for plain host/IP targets
            urls.append(f"https://{raw}")
            urls.append(f"http://{raw}")
    return list(dict.fromkeys(urls))


async def _run_zap_api_scan(
    zap_url: str,
    api_key: str,
    urls: List[str],
    zap_mode: str,
    log: Callable[[str, str], None],
) -> List[Dict[str, Any]]:
    all_alerts: List[Dict[str, Any]] = []
    for u in urls:
        log("INFO", f"[OWASP ZAP API] Spider avviato su {u}...")
        sp = await asyncio.to_thread(
            _zap_api_request, zap_url, "/JSON/spider/action/scan/", {"url": u, "maxChildren": "25"}, api_key, 10.0
        )
        if not sp or "scan" not in sp:
            continue
        spider_id = str(sp["scan"])

        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            st = await asyncio.to_thread(
                _zap_api_request, zap_url, "/JSON/spider/view/status/", {"scanId": spider_id}, api_key, 5.0
            )
            if st and int(st.get("status", 0)) >= 100:
                break
            await asyncio.sleep(1.5)

        if zap_mode == "full":
            log("INFO", f"[OWASP ZAP API] Active Scan avviato su {u}...")
            asc = await asyncio.to_thread(
                _zap_api_request, zap_url, "/JSON/ascan/action/scan/", {"url": u, "recurse": "true"}, api_key, 10.0
            )
            if asc and "scan" in asc:
                ascan_id = str(asc["scan"])
                a_deadline = time.monotonic() + 180.0
                while time.monotonic() < a_deadline:
                    ast = await asyncio.to_thread(
                        _zap_api_request, zap_url, "/JSON/ascan/view/status/", {"scanId": ascan_id}, api_key, 5.0
                    )
                    if ast and int(ast.get("status", 0)) >= 100:
                        break
                    await asyncio.sleep(2.0)

        res = await asyncio.to_thread(
            _zap_api_request, zap_url, "/JSON/core/view/alerts/", {"baseurl": u, "start": "0", "count": "250"}, api_key, 10.0
        )
        if res and isinstance(res.get("alerts"), list):
            parsed = parse_zap_alerts(res["alerts"], fallback_host=u)
            all_alerts.extend(parsed)
    return all_alerts


async def _run_zap_cli_scan(
    zap_bin: str,
    urls: List[str],
    log: Callable[[str, str], None],
) -> List[Dict[str, Any]]:
    all_findings: List[Dict[str, Any]] = []
    for u in urls[:4]:
        out_xml = BIN_DIR / f"zap_{os.getpid()}_{uuid.uuid4().hex[:8]}.xml"
        cmd = [zap_bin, "-cmd", "-quickurl", u, "-quickout", str(out_xml), "-quickprogress"]
        log("INFO", f"[OWASP ZAP CLI] Scansione headless su {u}...")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=240.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                log("WARN", f"[OWASP ZAP CLI] Timeout su {u} (240s): processo terminato.")
                continue

            if out_xml.is_file():
                xml_txt = out_xml.read_text(encoding="utf-8", errors="replace")
                all_findings.extend(parse_zap_xml(xml_txt, fallback_host=u))
        except Exception as exc:
            log("ERROR", f"[OWASP ZAP CLI] Errore su {u}: {exc}")
        finally:
            if out_xml.exists():
                try:
                    out_xml.unlink()
                except Exception:
                    pass
    return all_findings


async def run_zap_scan(
    targets: str,
    zap_mode: str = "baseline",
    log_callback: Optional[Callable[[str, str], Any]] = None,
) -> List[Dict[str, Any]]:
    def log(level: str, msg: str):
        if log_callback:
            try:
                res = log_callback(level, msg)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception:
                pass

    det = detect_zap()
    if not det["installed"]:
        log("WARN", "OWASP ZAP non rilevato (né daemon API su porta 8080 né CLI locale): scansione ZAP saltata.")
        return []

    urls = _format_web_urls(targets)
    if not urls:
        return []

    mode = det["mode"]
    if mode == "api":
        api_key = os.getenv("URIELSCAN_ZAP_API_KEY", "").strip()
        return await _run_zap_api_scan(det["path"], api_key, urls, zap_mode, log)
    return await _run_zap_cli_scan(det["path"], urls, log)
