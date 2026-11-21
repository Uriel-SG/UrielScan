import os
import re
import html
import json
import time
import uuid
import shutil
import asyncio
import platform
import subprocess
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import httpx

from backend.scanners.archive_utils import safe_extract_tar, safe_extract_zip, stream_download
from backend.scanners.tor_engine import validate_proxy_url

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


def _check_java_major(java_bin: str) -> int:
    try:
        proc = subprocess.run([java_bin, "-version"], capture_output=True, text=True, timeout=5)
        out = (proc.stderr or "") + "\n" + (proc.stdout or "")
        m = re.search(r'(?:version\s+"|openjdk\s+)(\d+)(?:\.(\d+))?', out, re.IGNORECASE)
        if m:
            maj = int(m.group(1))
            return int(m.group(2) or 0) if maj == 1 else maj
    except Exception:
        pass
    return 0


def _find_java_bin(min_major: int = 17) -> Optional[str]:
    java_exe = "java.exe" if platform.system() == "Windows" else "java"
    candidates: List[str] = []

    for cand in sorted(BIN_DIR.glob(f"jre/**/bin/{java_exe}"), reverse=True):
        if cand.is_file():
            candidates.append(str(cand))

    java_home = os.environ.get("JAVA_HOME", "").strip()
    if java_home:
        jh_bin = Path(java_home) / "bin" / java_exe
        if jh_bin.is_file():
            candidates.append(str(jh_bin))

    sys_java = shutil.which("java")
    if sys_java:
        candidates.append(sys_java)

    if platform.system() == "Windows":
        for p in (
            r"C:\Program Files\ZAP\Zed Attack Proxy\jre\bin\java.exe",
            r"C:\Program Files\OWASP\Zed Attack Proxy\jre\bin\java.exe",
        ):
            if Path(p).is_file():
                candidates.append(p)
        adopt_dir = Path(r"C:\Program Files\Eclipse Adoptium")
        if adopt_dir.is_dir():
            for cand in sorted(adopt_dir.glob("*/bin/java.exe"), reverse=True):
                candidates.append(str(cand))

    seen = set()
    for c in candidates:
        if c in seen or not Path(c).is_file():
            continue
        seen.add(c)
        if _check_java_major(c) >= min_major:
            return c
    return None


def _extract_zap_version_label(zap_bin_path: Path) -> str:
    parent = zap_bin_path.parent
    for jar in sorted(parent.glob("zap-*.jar"), reverse=True):
        m = re.search(r"zap-([0-9]+\.[0-9]+\.[0-9]+)", jar.name)
        if m:
            return f"OWASP ZAP {m.group(1)} (CLI)"
    m = re.search(r"ZAP[_-]([0-9]+\.[0-9]+\.[0-9]+)", parent.name, re.IGNORECASE)
    if m:
        return f"OWASP ZAP {m.group(1)} (CLI)"
    return "OWASP ZAP CLI"


def detect_zap() -> Dict[str, Any]:
    """Detects either a running OWASP ZAP daemon API or a local OWASP ZAP CLI installation."""
    zap_url = os.getenv("URIELSCAN_ZAP_URL", "http://127.0.0.1:8080").strip()
    api_key = os.getenv("URIELSCAN_ZAP_API_KEY", "").strip()

    # 1. Fast probe against running ZAP API daemon (0.45s so UI status never stalls)
    if zap_url:
        ver_data = _zap_api_request(zap_url, "/JSON/core/view/version/", api_key=api_key, timeout=0.45)
        if ver_data and "version" in ver_data:
            return {
                "installed": True,
                "mode": "api",
                "version": f"ZAP {ver_data['version']} (API)",
                "path": zap_url,
            }

    # 2. Check portable ZAP in bin/zap (requires usable Java 17+ or adjacent JRE)
    target_script = "zap.bat" if platform.system() == "Windows" else "zap.sh"
    for sub_bin in sorted(BIN_DIR.glob(f"zap/**/{target_script}"), reverse=True):
        if sub_bin.is_file():
            has_local_jre = (sub_bin.parent / "jre").is_dir()
            if has_local_jre or _find_java_bin(17):
                return {
                    "installed": True,
                    "mode": "cli",
                    "version": _extract_zap_version_label(sub_bin),
                    "path": str(sub_bin),
                }

    # 3. Check local PATH binaries
    for cmd_name in ("zap.bat", "zap.sh", "zaproxy", "zap"):
        found = shutil.which(cmd_name)
        if found:
            return {
                "installed": True,
                "mode": "cli",
                "version": _extract_zap_version_label(Path(found)),
                "path": found,
            }

    # 4. Check standard install directories
    for p_str in KNOWN_ZAP_PATHS:
        p_obj = Path(p_str)
        if p_obj.is_file():
            return {
                "installed": True,
                "mode": "cli",
                "version": _extract_zap_version_label(p_obj),
                "path": p_str,
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
    proxy_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    all_findings: List[Dict[str, Any]] = []
    zap_dir = Path(zap_bin).resolve().parent
    zap_jars = sorted(zap_dir.glob("zap-*.jar"), reverse=True)
    java_bin = _find_java_bin(17)

    env = os.environ.copy()
    if java_bin:
        java_home = str(Path(java_bin).resolve().parent.parent)
        env["JAVA_HOME"] = java_home
        env["PATH"] = str(Path(java_bin).resolve().parent) + os.pathsep + env.get("PATH", "")

    proxy_configs: List[str] = []
    validated_proxy = validate_proxy_url(proxy_url) if proxy_url else None
    if validated_proxy:
        p_parsed = urllib.parse.urlparse(validated_proxy)
        p_scheme = p_parsed.scheme.lower()
        p_host = p_parsed.hostname or ""
        p_port = p_parsed.port or (8080 if p_scheme in ("http", "https") else 1080)
        if p_scheme in ("socks5", "socks5h"):
            proxy_configs.extend([
                "-config", "connection.socksProxy.enabled=true",
                "-config", f"connection.socksProxy.host={p_host}",
                "-config", f"connection.socksProxy.port={p_port}",
                "-config", "connection.socksProxy.version=5",
                "-config", "connection.socksProxy.dns=true",
            ])
        else:
            proxy_configs.extend([
                "-config", "connection.proxyChain.enabled=true",
                "-config", f"connection.proxyChain.hostName={p_host}",
                "-config", f"connection.proxyChain.port={p_port}",
            ])
        log("INFO", f"[OWASP ZAP CLI] Outbound proxy attivo ({p_scheme}://{p_host}:{p_port}).")

    cli_timeout = 360.0 if validated_proxy else 240.0
    for u in urls[:4]:
        out_xml = BIN_DIR / f"zap_{os.getpid()}_{uuid.uuid4().hex[:8]}.xml"
        if zap_jars and java_bin:
            cmd = [java_bin, "-Xmx512m", "-jar", str(zap_jars[0]), "-cmd", *proxy_configs, "-quickurl", u, "-quickout", str(out_xml), "-quickprogress"]
        else:
            cmd = [zap_bin, "-cmd", *proxy_configs, "-quickurl", u, "-quickout", str(out_xml), "-quickprogress"]

        log("INFO", f"[OWASP ZAP CLI] Scansione headless su {u}...")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(zap_dir) if zap_dir.is_dir() else None,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=cli_timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                log("WARN", f"[OWASP ZAP CLI] Timeout su {u} ({int(cli_timeout)}s): processo terminato.")
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


async def _ensure_portable_jre() -> Optional[str]:
    existing = _find_java_bin(17)
    if existing:
        return existing

    os_map = {"windows": "windows", "linux": "linux", "darwin": "mac"}
    arch_map = {"x86_64": "x64", "amd64": "x64", "arm64": "aarch64", "aarch64": "aarch64"}
    target_os = os_map.get(platform.system().lower(), "linux")
    target_arch = arch_map.get(platform.machine().lower(), "x64")

    api_url = (
        f"https://api.adoptium.net/v3/assets/latest/17/hotspot"
        f"?architecture={target_arch}&image_type=jre&os={target_os}&vendor=eclipse"
    )
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        resp = await client.get(api_url, headers={"User-Agent": "UrielScan-Installer/1.0"})
        if resp.status_code != 200:
            return None
        assets = resp.json()
        if not assets or not isinstance(assets, list):
            return None
        pkg = (assets[0].get("binary") or {}).get("package") or {}
        dl_url = pkg.get("link")
        pkg_name = pkg.get("name") or f"temurin17_jre.{'zip' if target_os == 'windows' else 'tar.gz'}"
        if not dl_url:
            return None

    arch_path = BIN_DIR / pkg_name
    jre_dir = BIN_DIR / "jre"
    await stream_download(dl_url, arch_path, timeout=300.0)
    try:
        if pkg_name.lower().endswith(".zip"):
            safe_extract_zip(arch_path, jre_dir)
        else:
            safe_extract_tar(arch_path, jre_dir)
    finally:
        if arch_path.exists():
            arch_path.unlink(missing_ok=True)

    if platform.system() != "Windows":
        for jbin in jre_dir.glob("**/bin/*"):
            if jbin.is_file():
                try:
                    os.chmod(str(jbin), 0o755)
                except Exception:
                    pass

    return _find_java_bin(17)


async def install_zap() -> Dict[str, Any]:
    """Automatically downloads Eclipse Temurin JRE 17 and OWASP ZAP Crossplatform into bin/zap."""
    det = detect_zap()
    if det["installed"]:
        return {
            "success": True,
            "version": det["version"],
            "path": det["path"],
            "message": f"OWASP ZAP already installed: {det['path']} ({det['version']})",
        }

    try:
        java_bin = await _ensure_portable_jre()
        if not java_bin:
            return {
                "success": False,
                "version": "",
                "path": "",
                "message": "Failed to provision Java 17+ JRE required by OWASP ZAP.",
            }

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(
                "https://api.github.com/repos/zaproxy/zaproxy/releases/latest",
                headers={"User-Agent": "UrielScan-Installer/1.0"},
            )
            if resp.status_code != 200:
                return {
                    "success": False,
                    "version": "",
                    "path": "",
                    "message": f"GitHub API error fetching OWASP ZAP release: HTTP {resp.status_code}",
                }
            release = resp.json()
            tag = release.get("tag_name", "latest")
            assets = release.get("assets", []) or []
            dl_url = None
            for asset in assets:
                name = str(asset.get("name", "")).lower()
                if "crossplatform" in name and name.endswith(".zip"):
                    dl_url = asset.get("browser_download_url")
                    break
            if not dl_url:
                return {
                    "success": False,
                    "version": "",
                    "path": "",
                    "message": "OWASP ZAP Crossplatform ZIP asset not found in latest release.",
                }

        zap_zip = BIN_DIR / "zap_download.zip"
        zap_dir = BIN_DIR / "zap"
        await stream_download(dl_url, zap_zip, timeout=360.0)
        try:
            safe_extract_zip(zap_zip, zap_dir)
        finally:
            if zap_zip.exists():
                zap_zip.unlink(missing_ok=True)

        if platform.system() != "Windows":
            for sh_file in zap_dir.glob("**/zap.sh"):
                if sh_file.is_file():
                    os.chmod(str(sh_file), 0o755)

        det = detect_zap()
        if det["installed"]:
            return {
                "success": True,
                "version": det["version"],
                "path": det["path"],
                "message": f"OWASP ZAP {tag} installed in {det['path']} (with JRE 17).",
            }
        return {
            "success": False,
            "version": "",
            "path": "",
            "message": "OWASP ZAP extraction completed but CLI binary was not detected.",
        }
    except Exception as exc:
        return {
            "success": False,
            "version": "",
            "path": "",
            "message": f"OWASP ZAP installation failed: {exc}",
        }


async def run_zap_scan(
    targets: str,
    zap_mode: str = "baseline",
    log_callback: Optional[Callable[[str, str], Any]] = None,
    proxy_url: Optional[str] = None,
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
        if proxy_url:
            log("WARN", "[OWASP ZAP API] Modalità daemon esterno rilevata: preferisco CLI locale o avviso proxy non applicato all'istanza API.")
        api_key = os.getenv("URIELSCAN_ZAP_API_KEY", "").strip()
        return await _run_zap_api_scan(det["path"], api_key, urls, zap_mode, log)
    return await _run_zap_cli_scan(det["path"], urls, log, proxy_url=proxy_url)
