"""Web Recon & Surface Discovery Engines: SubRaptor (Subfinder + crt.sh + DNS), ProjectDiscovery httpx, Subzy/Takeover Audit, DNS Zone AXFR, and Feroxbuster."""

import asyncio
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import dns.asyncresolver
import dns.exception
import dns.query
import dns.rdatatype
import dns.zone
import httpx

from backend.scanners.archive_utils import safe_extract_tar, safe_extract_zip, stream_download
from backend.scanners.tor_engine import to_httpx_proxy_url, validate_proxy_url
from backend.scanners.wordlists import resolve_wordlist_path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
BIN_DIR = BASE_DIR / "bin"
BIN_DIR.mkdir(parents=True, exist_ok=True)

SUBFINDER_DIR = BIN_DIR / "subfinder"
PD_HTTPX_DIR = BIN_DIR / "pd_httpx"
FEROX_DIR = BIN_DIR / "feroxbuster"
SUBZY_DIR = BIN_DIR / "subzy"
SUBZY_FP_PATH = SUBZY_DIR / "fingerprints.json"

FINGERPRINTS_URL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_SAFE_SUB_RE = re.compile(r"^[a-z0-9._-]+$")
_EXT_CLEAN_RE = re.compile(r"^[a-zA-Z0-9,]+$")


def _normalize_go_proxy(proxy_url: Optional[str]) -> Optional[str]:
    if not proxy_url:
        return None
    validated = validate_proxy_url(proxy_url)
    if not validated:
        return None
    if validated.lower().startswith("socks5h://"):
        return "socks5://" + validated[len("socks5h://"):]
    return validated


def _find_bin_in_dir(target_dir: Path, exe_name: str) -> Optional[str]:
    direct = target_dir / exe_name
    if direct.is_file():
        return str(direct)
    if target_dir.is_dir():
        for match in sorted(target_dir.rglob(exe_name)):
            if match.is_file() and match.name == exe_name:
                return str(match)
    return None


def _run_ver_cmd(cmd: List[str], timeout: float = 5.0) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    except Exception:
        return ""


def _pd_asset_match(assets: List[Dict[str, Any]], tool: str) -> Optional[str]:
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    os_tok = "windows" if sys_name == "windows" else ("macos" if sys_name == "darwin" else "linux")
    arch_tok = "arm64" if machine in ("arm64", "aarch64") else "amd64"

    for a in assets or []:
        name = str(a.get("name", ""))
        low = name.lower()
        if not low.endswith(".zip"):
            continue
        if tool in low and os_tok in low and arch_tok in low:
            return a.get("browser_download_url")
    # Fallback to amd64 on Windows/macOS ARM if arm64 build absent
    if arch_tok == "arm64":
        for a in assets or []:
            low = str(a.get("name", "")).lower()
            if low.endswith(".zip") and tool in low and os_tok in low and "amd64" in low:
                return a.get("browser_download_url")
    return None


async def _install_github_zip_tool(
    repo: str,
    tool: str,
    dest_dir: Path,
    detect_fn: Callable[[], Dict[str, Any]],
) -> Dict[str, Any]:
    det = detect_fn()
    if det.get("installed"):
        return {
            "success": True,
            "version": det.get("version", ""),
            "path": det.get("path", ""),
            "message": f"{tool} already installed: {det.get('path')} ({det.get('version')})",
        }
    try:
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
            resp = await client.get(
                f"https://api.github.com/repos/{repo}/releases/latest",
                headers={"User-Agent": "UrielScan-Installer/1.0"},
            )
            if resp.status_code != 200:
                return {"success": False, "version": "", "path": "", "message": f"GitHub API HTTP {resp.status_code} for {repo}"}
            rel = resp.json()
            dl_url = _pd_asset_match(rel.get("assets", []), tool)
            if not dl_url:
                return {"success": False, "version": "", "path": "", "message": f"No matching binary asset found for {tool}"}

        dest_dir.mkdir(parents=True, exist_ok=True)
        zpath = BIN_DIR / f"{tool}_download.zip"
        await stream_download(dl_url, zpath, timeout=240.0)
        try:
            safe_extract_zip(zpath, dest_dir)
        finally:
            zpath.unlink(missing_ok=True)

        if platform.system() != "Windows":
            for p in dest_dir.rglob("*"):
                if p.is_file() and tool in p.name.lower():
                    try:
                        os.chmod(str(p), 0o755)
                    except Exception:
                        pass

        after = detect_fn()
        if after.get("installed"):
            return {
                "success": True,
                "version": after.get("version", ""),
                "path": after.get("path", ""),
                "message": f"{tool} installed successfully ({after.get('version', 'ready')})",
            }
        return {"success": False, "version": "", "path": "", "message": f"{tool} archive extracted but binary not detected."}
    except Exception as exc:
        return {"success": False, "version": "", "path": "", "message": f"Failed installing {tool}: {exc}"}


# ==========================================
# TOOL DETECTION & INSTALLERS
# ==========================================

def get_subfinder_bin_path() -> Optional[str]:
    exe = "subfinder.exe" if platform.system() == "Windows" else "subfinder"
    return _find_bin_in_dir(SUBFINDER_DIR, exe) or shutil.which("subfinder")


def detect_subfinder() -> Dict[str, Any]:
    path = get_subfinder_bin_path()
    if not path:
        return {"installed": False, "version": "", "path": ""}
    out = _run_ver_cmd([path, "-version"])
    m = re.search(r"v([0-9]+\.[0-9]+\.[0-9]+)", out)
    return {"installed": True, "version": f"v{m.group(1)}" if m else "Available", "path": path}


async def install_subfinder() -> Dict[str, Any]:
    return await _install_github_zip_tool("projectdiscovery/subfinder", "subfinder", SUBFINDER_DIR, detect_subfinder)


def get_httpx_bin_path() -> Optional[str]:
    exe = "httpx.exe" if platform.system() == "Windows" else "httpx"
    local = _find_bin_in_dir(PD_HTTPX_DIR, exe)
    if local:
        return local
    # Distinguish ProjectDiscovery httpx from Python pip's httpx CLI
    sys_path = shutil.which("httpx")
    if sys_path:
        out = _run_ver_cmd([sys_path, "-version"]).lower()
        if "projectdiscovery" in out or "current version" in out or "[inf]" in out:
            return sys_path
    return None


def detect_httpx() -> Dict[str, Any]:
    path = get_httpx_bin_path()
    if not path:
        return {"installed": False, "version": "", "path": ""}
    out = _run_ver_cmd([path, "-version"])
    m = re.search(r"v([0-9]+\.[0-9]+\.[0-9]+)", out)
    return {"installed": True, "version": f"v{m.group(1)}" if m else "Available", "path": path}


async def install_httpx() -> Dict[str, Any]:
    return await _install_github_zip_tool("projectdiscovery/httpx", "httpx", PD_HTTPX_DIR, detect_httpx)


def get_feroxbuster_bin_path() -> Optional[str]:
    exe = "feroxbuster.exe" if platform.system() == "Windows" else "feroxbuster"
    return _find_bin_in_dir(FEROX_DIR, exe) or shutil.which("feroxbuster")


def detect_feroxbuster() -> Dict[str, Any]:
    path = get_feroxbuster_bin_path()
    if not path:
        return {"installed": False, "version": "", "path": ""}
    out = _run_ver_cmd([path, "--version"])
    m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", out)
    return {"installed": True, "version": f"v{m.group(1)}" if m else "Available", "path": path}


async def install_feroxbuster() -> Dict[str, Any]:
    det = detect_feroxbuster()
    if det["installed"]:
        return {"success": True, "version": det["version"], "path": det["path"], "message": f"Feroxbuster already installed: {det['path']} ({det['version']})"}

    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    if sys_name == "windows":
        wanted = ("x86_64-windows-feroxbuster.exe.zip", "windows-feroxbuster")
    elif sys_name == "darwin":
        arch = "aarch64-macos" if machine in ("arm64", "aarch64") else "x86_64-macos"
        wanted = (f"{arch}-feroxbuster.zip", "macos-feroxbuster")
    else:
        arch = "aarch64-linux" if machine in ("arm64", "aarch64") else "x86_64-linux"
        wanted = (f"{arch}-feroxbuster.zip", f"{arch}-feroxbuster.tar.gz")

    try:
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
            resp = await client.get(
                "https://api.github.com/repos/epi052/feroxbuster/releases/latest",
                headers={"User-Agent": "UrielScan-Installer/1.0"},
            )
            if resp.status_code != 200:
                return {"success": False, "version": "", "path": "", "message": f"GitHub API HTTP {resp.status_code} for feroxbuster"}
            assets = resp.json().get("assets", []) or []

        dl_url = None
        for token in wanted:
            for a in assets:
                name = str(a.get("name", "")).lower()
                if ".deb." in name:
                    continue
                if token in name and (name.endswith(".zip") or name.endswith(".tar.gz")):
                    dl_url = a.get("browser_download_url")
                    break
            if dl_url:
                break

        if not dl_url:
            return {"success": False, "version": "", "path": "", "message": "No compatible feroxbuster release asset found."}

        FEROX_DIR.mkdir(parents=True, exist_ok=True)
        is_tar = dl_url.lower().endswith(".tar.gz")
        arch_path = BIN_DIR / ("feroxbuster_dl.tar.gz" if is_tar else "feroxbuster_dl.zip")
        await stream_download(dl_url, arch_path, timeout=240.0)
        try:
            if is_tar:
                safe_extract_tar(arch_path, FEROX_DIR)
            else:
                safe_extract_zip(arch_path, FEROX_DIR)
        finally:
            arch_path.unlink(missing_ok=True)

        if platform.system() != "Windows":
            for p in FEROX_DIR.rglob("feroxbuster"):
                if p.is_file():
                    try:
                        os.chmod(str(p), 0o755)
                    except Exception:
                        pass

        after = detect_feroxbuster()
        if after["installed"]:
            return {"success": True, "version": after["version"], "path": after["path"], "message": f"Feroxbuster installed ({after['version']})"}
        return {"success": False, "version": "", "path": "", "message": "Feroxbuster archive extracted but executable not found."}
    except Exception as exc:
        return {"success": False, "version": "", "path": "", "message": f"Feroxbuster install failed: {exc}"}


def _load_subzy_fingerprints() -> List[Dict[str, Any]]:
    if not SUBZY_FP_PATH.is_file():
        return []
    try:
        data = json.loads(SUBZY_FP_PATH.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def detect_subzy() -> Dict[str, Any]:
    fps = _load_subzy_fingerprints()
    exe = "subzy.exe" if platform.system() == "Windows" else "subzy"
    subzy_bin = _find_bin_in_dir(SUBZY_DIR, exe) or shutil.which("subzy")
    if not fps and not subzy_bin:
        return {"installed": False, "version": "", "path": "", "fingerprints_count": 0}
    ver = f"{len(fps)} fingerprints" if fps else "CLI Ready"
    if subzy_bin and fps:
        ver = f"CLI + {len(fps)} fingerprints"
    return {
        "installed": True,
        "version": ver,
        "path": subzy_bin or str(SUBZY_FP_PATH),
        "fingerprints_count": len(fps),
    }


async def install_subzy() -> Dict[str, Any]:
    """Download/update official can-i-take-over-xyz fingerprints DB for cross-platform takeover detection."""
    try:
        SUBZY_DIR.mkdir(parents=True, exist_ok=True)
        tmp = SUBZY_DIR / ".fingerprints.downloading"
        await stream_download(FINGERPRINTS_URL, tmp, timeout=60.0)
        data = json.loads(tmp.read_text(encoding="utf-8"))
        if not isinstance(data, list) or len(data) < 10:
            tmp.unlink(missing_ok=True)
            return {"success": False, "version": "", "path": "", "message": "Invalid takeover fingerprints payload."}
        tmp.replace(SUBZY_FP_PATH)
        det = detect_subzy()
        return {
            "success": True,
            "version": det["version"],
            "path": det["path"],
            "message": f"Subzy / Takeover DB ready ({len(data)} fingerprints)",
        }
    except Exception as exc:
        return {"success": False, "version": "", "path": "", "message": f"Failed to fetch Subzy fingerprints: {exc}"}


# ==========================================
# SUBRAPTOR AGGREGATOR, DNS ZONE & TAKEOVER
# ==========================================

def extract_domain_targets(targets_str: str) -> List[str]:
    """Extract clean, valid domain targets from comma/whitespace target lists (skips raw IPs/CIDRs)."""
    domains: List[str] = []
    for raw in re.split(r"[\s,;]+", targets_str or ""):
        tok = raw.strip().lower()
        if not tok:
            continue
        if "://" in tok:
            parsed = urllib.parse.urlparse(tok)
            tok = parsed.hostname or ""
        else:
            tok = tok.split("/")[0].split(":")[0]
        if not tok or tok == "localhost":
            continue
        try:
            ipaddress.ip_address(tok)
            continue
        except ValueError:
            pass
        if _DOMAIN_RE.match(tok) and tok not in domains:
            domains.append(tok)
    return domains


def normalize_subdomains(candidates: List[str], domain: str) -> List[str]:
    """Normalize, strip leading '*.' wildcards, validate syntax, and anchor strictly under target domain."""
    dom = domain.lower().strip(".")
    out: Set[str] = set()
    for item in candidates:
        s = (item or "").strip().lower().rstrip(".")
        while s.startswith("*."):
            s = s[2:]
        if not s or not _SAFE_SUB_RE.match(s):
            continue
        if s == dom or s.endswith("." + dom):
            if _DOMAIN_RE.match(s):
                out.add(s)
    return sorted(out)


def compute_subraptor_source_stats(source_sets: Dict[str, Tuple[str, Set[str]]]) -> Dict[str, Dict[str, Any]]:
    """Compute SubRaptor-style {status, found, unique} metrics across discovery sources."""
    stats: Dict[str, Dict[str, Any]] = {}
    names = list(source_sets.keys())
    for src in names:
        status, found_set = source_sets[src]
        others: Set[str] = set()
        for other in names:
            if other != src:
                others.update(source_sets[other][1])
        unique_n = len(found_set - others)
        stats[src] = {"status": status, "found": len(found_set), "unique": unique_n}
    return stats


async def _fetch_crtsh_subdomains(domain: str, proxy_url: Optional[str]) -> Tuple[str, List[str]]:
    httpx_proxy = to_httpx_proxy_url(proxy_url) if proxy_url else None
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    headers = {"User-Agent": "UrielScan-SubRaptor/2.2"}
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(
                proxy=httpx_proxy,
                timeout=httpx.Timeout(30.0, connect=15.0),
                follow_redirects=True,
            ) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    names: List[str] = []
                    if isinstance(data, list):
                        for entry in data:
                            nv = str(entry.get("name_value", ""))
                            for line in nv.splitlines():
                                if line.strip():
                                    names.append(line.strip())
                    return "ok", names
                if resp.status_code in (429, 502, 503, 504) and attempt == 0:
                    await asyncio.sleep(2.0)
                    continue
                return "failed", []
        except Exception:
            if attempt == 0:
                await asyncio.sleep(1.5)
    return "failed", []


async def _run_subfinder_source(domain: str, proxy_url: Optional[str]) -> Tuple[str, List[str]]:
    subfinder_bin = get_subfinder_bin_path()
    if not subfinder_bin:
        return "missing", []
    args = [subfinder_bin, "-d", domain, "-all", "-silent"]
    go_proxy = _normalize_go_proxy(proxy_url)
    if go_proxy:
        args.extend(["-proxy", go_proxy])
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return "timeout", []
        lines = [ln.strip() for ln in stdout.decode("utf-8", errors="replace").splitlines() if ln.strip()]
        return ("ok" if proc.returncode == 0 or lines else "failed"), lines
    except Exception:
        return "failed", []


async def _run_assetfinder_source(domain: str, proxy_url: Optional[str]) -> Tuple[str, List[str]]:
    if proxy_url:
        return "skipped", []  # assetfinder has no SOCKS5 proxy support
    af_bin = shutil.which("assetfinder")
    if not af_bin:
        return "missing", []
    try:
        proc = await asyncio.create_subprocess_exec(
            af_bin, "--subs-only", domain,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return "timeout", []
        lines = [ln.strip() for ln in stdout.decode("utf-8", errors="replace").splitlines() if ln.strip()]
        return "ok", lines
    except Exception:
        return "failed", []


async def _detect_wildcard_ips(domain: str, resolver: dns.asyncresolver.Resolver) -> Set[str]:
    wc_ips: Set[str] = set()
    for _ in range(2):
        bogus = f"uriel-wc-{uuid.uuid4().hex[:10]}.{domain}"
        try:
            ans = await asyncio.wait_for(resolver.resolve(bogus, "A"), timeout=2.5)
            for r in ans:
                wc_ips.add(str(r))
        except Exception:
            pass
    return wc_ips


async def _run_dns_bruteforce(
    domain: str,
    wordlist_id: str,
    max_words: int = 20000,
    time_budget: float = 45.0,
) -> Tuple[str, List[str]]:
    wpath = await resolve_wordlist_path("dns", wordlist_id)
    if not wpath or not wpath.is_file():
        return "missing", []

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0
    wildcard_ips = await _detect_wildcard_ips(domain, resolver)

    prefixes: List[str] = []
    with open(wpath, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().lower().lstrip(".")
            if not w or w.startswith("#") or " " in w:
                continue
            prefixes.append(w)
            if len(prefixes) >= max_words:
                break

    if not prefixes:
        return "ok", []

    found: List[str] = []
    sem = asyncio.Semaphore(100)
    deadline = time.monotonic() + time_budget

    async def _probe(prefix: str) -> None:
        if time.monotonic() >= deadline:
            return
        fqdn = f"{prefix}.{domain}"
        async with sem:
            if time.monotonic() >= deadline:
                return
            try:
                ans = await asyncio.wait_for(resolver.resolve(fqdn, "A"), timeout=2.5)
                ips = {str(r) for r in ans}
                if wildcard_ips and ips.issubset(wildcard_ips):
                    return
                found.append(fqdn)
            except Exception:
                pass

    # Run in chunks of 500 so deadline cleanly stops remaining work
    for idx in range(0, len(prefixes), 500):
        if time.monotonic() >= deadline:
            break
        batch = prefixes[idx:idx + 500]
        await asyncio.gather(*[_probe(p) for p in batch])

    return "ok", found


async def run_dns_zone_audit(domain: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    """Audit nameservers, test AXFR Zone Transfer, check wildcard DNS and SPF/DMARC/CAA records."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 4.0

    nameservers: List[str] = []
    axfr_vulnerable_ns: List[str] = []
    axfr_hosts: List[str] = []
    findings: List[Dict[str, Any]] = []

    try:
        ns_ans = await asyncio.wait_for(resolver.resolve(domain, "NS"), timeout=4.0)
        nameservers = sorted({str(r).rstrip(".").lower() for r in ns_ans})
    except Exception:
        pass

    def _try_axfr_sync(ns_host: str) -> List[str]:
        leaked: List[str] = []
        try:
            ns_ip = ns_host
            try:
                ipaddress.ip_address(ns_host)
            except ValueError:
                a_res = dns.resolver.resolve(ns_host, "A", lifetime=3.0)
                ns_ip = str(a_res[0])
            xfr = dns.query.xfr(ns_ip, domain, timeout=3.5, lifetime=5.0)
            zone = dns.zone.from_xfr(xfr)
            for name in zone.nodes.keys():
                s = str(name).strip(".")
                if s and s != "@":
                    leaked.append(f"{s}.{domain}")
        except Exception:
            pass
        return leaked

    for ns_host in nameservers[:4]:
        leaked = await asyncio.to_thread(_try_axfr_sync, ns_host)
        if leaked:
            axfr_vulnerable_ns.append(ns_host)
            axfr_hosts.extend(leaked)

    axfr_hosts = normalize_subdomains(axfr_hosts, domain)

    if axfr_vulnerable_ns:
        findings.append({
            "host": domain,
            "port": 53,
            "protocol": "tcp",
            "service": "dns",
            "title": f"DNS Zone Transfer (AXFR) Abilitato ({len(axfr_hosts)} record esposti)",
            "severity": "high",
            "cvss": 7.5,
            "cve_ids": "",
            "cwe_id": "CWE-200",
            "source_engine": "dns_zone",
            "description": f"I nameserver autoritativi ({', '.join(axfr_vulnerable_ns)}) consentono trasferimenti di zona AXFR non autenticati.",
            "evidence": "Nameserver vulnerabili: " + ", ".join(axfr_vulnerable_ns) + "\nCampione record: " + ", ".join(axfr_hosts[:20]),
            "remediation": "Limitare allow-transfer esclusivamente agli IP dei nameserver secondari autorizzati nella configurazione BIND/PowerDNS/CloudDNS.",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1590 - Gather Victim Network Information",
            "ai_insight": "Espone l'intera mappa interna dei sottodomini e degli IP di infrastruttura senza autenticazione.",
        })

    wildcard_ips = await _detect_wildcard_ips(domain, resolver)
    has_spf = False
    has_dmarc = False
    has_caa = False

    try:
        txt_ans = await asyncio.wait_for(resolver.resolve(domain, "TXT"), timeout=3.0)
        for r in txt_ans:
            if "v=spf1" in str(r).lower():
                has_spf = True
    except Exception:
        pass

    try:
        dmarc_ans = await asyncio.wait_for(resolver.resolve(f"_dmarc.{domain}", "TXT"), timeout=3.0)
        for r in dmarc_ans:
            if "v=dmarc1" in str(r).lower():
                has_dmarc = True
    except Exception:
        pass

    try:
        caa_ans = await asyncio.wait_for(resolver.resolve(domain, "CAA"), timeout=3.0)
        has_caa = len(list(caa_ans)) > 0
    except Exception:
        pass

    missing_email_dns = []
    if not has_spf:
        missing_email_dns.append("SPF (TXT)")
    if not has_dmarc:
        missing_email_dns.append("_dmarc DMARC (TXT)")

    if missing_email_dns:
        findings.append({
            "host": domain,
            "port": 53,
            "protocol": "udp",
            "service": "dns",
            "title": f"Record DNS Anti-Spoofing Assenti ({', '.join(missing_email_dns)})",
            "severity": "low",
            "cvss": 3.5,
            "cve_ids": "",
            "cwe_id": "CWE-290",
            "source_engine": "dns_zone",
            "description": "Il dominio non pubblica uno o più record TXT standard (SPF/DMARC) per prevenire lo spoofing delle email aziendali.",
            "evidence": f"Dominio: {domain}\nNameservers: {', '.join(nameservers) or 'N/A'}\nMancanti: {', '.join(missing_email_dns)}",
            "remediation": "Pubblicare un record TXT SPF restrittivo e una policy DMARC (_dmarc) con almeno p=quarantine/reject.",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1566 - Phishing",
            "ai_insight": "Riduce il rischio di spoofing del dominio in campagne di phishing verso dipendenti e clienti.",
        })

    zone_summary = {
        "domain": domain,
        "nameservers": nameservers,
        "axfr_vulnerable": len(axfr_vulnerable_ns) > 0,
        "axfr_nameservers": axfr_vulnerable_ns,
        "axfr_records_count": len(axfr_hosts),
        "wildcard_dns": len(wildcard_ips) > 0,
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "has_caa": has_caa,
    }
    return zone_summary, findings, axfr_hosts


async def run_httpx_probe(
    subdomains: List[str],
    proxy_url: Optional[str] = None,
    log_callback: Optional[Callable[[str, str], Any]] = None,
) -> List[Dict[str, Any]]:
    """Verify live web endpoints and extract status, title, tech stack, web server, IP, and CNAME via pd httpx (or Python fallback)."""
    def log(level: str, msg: str) -> None:
        if log_callback:
            try:
                log_callback(level, msg)
            except Exception:
                pass

    targets = subdomains[:150]
    if not targets:
        return []

    pd_bin = get_httpx_bin_path()
    live_rows: List[Dict[str, Any]] = []

    if pd_bin:
        tmp_list = BIN_DIR / f"httpx_targets_{os.getpid()}_{uuid.uuid4().hex[:8]}.txt"
        tmp_list.write_text("\n".join(targets), encoding="utf-8")
        args = [
            pd_bin,
            "-l", str(tmp_list),
            "-json",
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-web-server",
            "-content-length",
            "-ip",
            "-cname",
            "-follow-redirects",
            "-timeout", "10",
            "-threads", "25",
        ]
        go_proxy = _normalize_go_proxy(proxy_url)
        if go_proxy:
            args.extend(["-http-proxy", go_proxy])

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=150.0)
                for raw_ln in stdout.decode("utf-8", errors="replace").splitlines():
                    ln = raw_ln.strip()
                    if not ln:
                        continue
                    try:
                        obj = json.loads(ln)
                        final_url = str(obj.get("url") or obj.get("input") or "")
                        parsed = urllib.parse.urlparse(final_url if "://" in final_url else f"https://{final_url}")
                        sub_host = str(obj.get("input") or parsed.hostname or "").lower()
                        if "://" in sub_host:
                            sub_host = urllib.parse.urlparse(sub_host).hostname or sub_host
                        live_rows.append({
                            "subdomain": sub_host,
                            "url": final_url,
                            "status_code": int(obj.get("status_code") or obj.get("status-code") or 0),
                            "title": str(obj.get("title") or "")[:140],
                            "tech": [str(t) for t in (obj.get("tech") or [])][:10],
                            "webserver": str(obj.get("webserver") or "")[:80],
                            "ip": str(obj.get("host_ip") or obj.get("host") or obj.get("ip") or ""),
                            "cname": [str(c).rstrip(".") for c in (obj.get("cname") or [])] if isinstance(obj.get("cname"), list) else ([str(obj["cname"]).rstrip(".")] if obj.get("cname") else []),
                            "content_length": int(obj.get("content_length") or obj.get("content-length") or 0),
                        })
                    except Exception:
                        continue
                return live_rows
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                log("WARN", "[httpx] Timeout durante il probe HTTP; uso fallback nativo sui rimanenti.")
        except Exception as exc:
            log("WARN", f"[httpx] Esecuzione binaria fallita ({exc}); passo al fallback HTTPX nativo.")
        finally:
            tmp_list.unlink(missing_ok=True)

    # Pure-Python async fallback (also respects Tor / SOCKS5h proxy cleanly)
    httpx_proxy = to_httpx_proxy_url(proxy_url) if proxy_url else None
    sem = asyncio.Semaphore(20 if not httpx_proxy else 10)
    title_re = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    async with httpx.AsyncClient(
        proxy=httpx_proxy,
        verify=False,
        timeout=httpx.Timeout(10.0 if httpx_proxy else 6.0, connect=6.0),
        follow_redirects=True,
    ) as client:
        async def _probe_sub(sub: str) -> Optional[Dict[str, Any]]:
            async with sem:
                candidate_urls = [sub] if sub.startswith(("http://", "https://")) else [f"https://{sub}", f"http://{sub}"]
                for target_url in candidate_urls:
                    try:
                        resp = await client.get(target_url, headers={"User-Agent": "UrielScan-LiveProbe/1.0"})
                        title_m = title_re.search(resp.text[:8000] if resp.text else "")
                        title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:140] if title_m else ""
                        srv = resp.headers.get("server", "")
                        powered = resp.headers.get("x-powered-by", "")
                        tech = [t for t in (srv, powered) if t]
                        return {
                            "subdomain": sub,
                            "url": str(resp.url),
                            "status_code": resp.status_code,
                            "title": title,
                            "tech": tech,
                            "webserver": srv[:80],
                            "ip": "",
                            "cname": [],
                            "content_length": len(resp.content or b""),
                        }
                    except Exception:
                        continue
                return None

        results = await asyncio.gather(*[_probe_sub(s) for s in targets])
        live_rows = [r for r in results if r is not None]

    return live_rows


def _match_cname_fingerprint(cnames: List[str], fp: Dict[str, Any]) -> Optional[str]:
    fp_cnames = [str(c).lower().rstrip(".") for c in (fp.get("cname") or []) if c]
    if not fp_cnames:
        return None
    for cn in cnames:
        low_cn = cn.lower().rstrip(".")
        for pat in fp_cnames:
            if pat in low_cn:
                return low_cn
    return None


async def run_subzy_takeover_check(
    subdomains: List[str],
    live_rows: List[Dict[str, Any]],
    proxy_url: Optional[str] = None,
    onion_mode: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Check discovered subdomains for dangling CNAME / Subdomain Takeover using can-i-take-over-xyz fingerprints."""
    fps = _load_subzy_fingerprints()
    if not fps:
        res = await install_subzy()
        if res.get("success"):
            fps = _load_subzy_fingerprints()
    if not fps or not subdomains:
        return [], []

    live_map = {r["subdomain"]: r for r in live_rows}
    cname_map: Dict[str, List[str]] = {r["subdomain"]: list(r.get("cname") or []) for r in live_rows}

    # Resolve missing CNAMEs asynchronously when not under Tor onion_mode (avoid direct DNS leaks)
    if not onion_mode:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 3.5
        sem_dns = asyncio.Semaphore(40)

        async def _get_cname(sub: str) -> None:
            if cname_map.get(sub):
                return
            async with sem_dns:
                try:
                    ans = await asyncio.wait_for(resolver.resolve(sub, "CNAME"), timeout=3.0)
                    cname_map[sub] = [str(r.target).rstrip(".").lower() for r in ans]
                except Exception:
                    cname_map.setdefault(sub, [])

        await asyncio.gather(*[_get_cname(s) for s in subdomains[:120]])

    httpx_proxy = to_httpx_proxy_url(proxy_url) if proxy_url else None
    takeover_hits: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    async def _check_nxdomain(sub: str) -> bool:
        if onion_mode:
            return False
        res = dns.asyncresolver.Resolver()
        res.timeout = 2.0
        try:
            await asyncio.wait_for(res.resolve(sub, "A"), timeout=2.5)
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return False

    async with httpx.AsyncClient(
        proxy=httpx_proxy,
        verify=False,
        timeout=httpx.Timeout(8.0, connect=5.0),
        follow_redirects=True,
    ) as client:
        checked_bodies: Dict[str, Tuple[int, str]] = {}

        # Candidate filtering: check subdomains matching a service CNAME OR not cleanly returning 200 OK
        candidates: List[str] = []
        for sub in subdomains[:120]:
            cns = cname_map.get(sub, [])
            live_info = live_map.get(sub)
            has_fp_cname = any(_match_cname_fingerprint(cns, fp) for fp in fps)
            if has_fp_cname or not live_info or live_info.get("status_code", 0) in (400, 403, 404, 500, 502, 503):
                candidates.append(sub)

        sem_http = asyncio.Semaphore(15)

        async def _fetch_body(sub: str) -> None:
            async with sem_http:
                for scheme in ("https", "http"):
                    try:
                        r = await client.get(f"{scheme}://{sub}")
                        checked_bodies[sub] = (r.status_code, (r.text or "")[:20000])
                        return
                    except Exception:
                        continue

        await asyncio.gather(*[_fetch_body(s) for s in candidates[:60]])

        for sub in candidates[:60]:
            cns = cname_map.get(sub, [])
            body_pair = checked_bodies.get(sub)
            body_text = body_pair[1] if body_pair else ""
            status_code = body_pair[0] if body_pair else 0

            matched_fp: Optional[Dict[str, Any]] = None
            matched_cname = ""
            match_reason = ""

            for fp in fps:
                if not fp.get("vulnerable"):
                    continue
                cn_hit = _match_cname_fingerprint(cns, fp)
                if not cn_hit:
                    continue
                fp_str = str(fp.get("fingerprint") or "").strip()
                if fp_str and fp_str in body_text:
                    matched_fp = fp
                    matched_cname = cn_hit
                    match_reason = f"Body fingerprint matched: '{fp_str[:80]}'"
                    break
                if fp.get("nxdomain") and not body_pair:
                    if await _check_nxdomain(sub):
                        matched_fp = fp
                        matched_cname = cn_hit
                        match_reason = "CNAME target resolves to NXDOMAIN"
                        break

            if matched_fp:
                service = str(matched_fp.get("service", "Cloud Service"))
                fp_status = str(matched_fp.get("status", "Vulnerable"))
                sev = "high" if fp_status.lower() == "vulnerable" else "medium"
                cvss = 8.2 if sev == "high" else 5.3

                hit = {
                    "subdomain": sub,
                    "service": service,
                    "cname": matched_cname,
                    "status": fp_status,
                    "http_status": status_code,
                    "reason": match_reason,
                }
                takeover_hits.append(hit)
                findings.append({
                    "host": sub,
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "title": f"Potenziale Subdomain Takeover su {sub} ({service})",
                    "severity": sev,
                    "cvss": cvss,
                    "cve_ids": "",
                    "cwe_id": "CWE-284",
                    "source_engine": "subzy",
                    "description": f"Il sottodominio {sub} punta al record CNAME '{matched_cname}' ({service}) che risulta non reclamato o dereferenziato ({fp_status}).",
                    "evidence": f"Subdomain: {sub}\nCNAME: {matched_cname}\nService: {service}\n{match_reason}",
                    "remediation": "Rimuovere immediatamente il record CNAME orfano dal DNS oppure ri-registrare/reclamare la risorsa sul provider cloud target.",
                    "mitre_tactic": "Resource Development",
                    "mitre_technique": "T1584.001 - Compromise Infrastructure: Domains",
                    "ai_insight": "Permette ad attaccanti esterni di ospitare contenuti arbitrari sotto un dominio aziendale fidato (phishing, furto cookie, OAuth bypass).",
                })

    return takeover_hits, findings


async def run_subraptor_pipeline(
    targets: str,
    wordlist_id: Optional[str] = "passive_only",
    checks: Optional[List[str]] = None,
    proxy_url: Optional[str] = None,
    onion_mode: bool = False,
    log_callback: Optional[Callable[[str, str], Any]] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Execute SubRaptor passive + optional wordlist discovery, DNS Zone audit, httpx live check, and Subzy takeover audit."""
    def log(level: str, msg: str) -> None:
        if log_callback:
            try:
                log_callback(level, msg)
            except Exception:
                pass

    active_checks = set(checks or ["httpx", "takeover", "dns_zone"])
    domains = extract_domain_targets(targets)
    if not domains:
        log("WARN", "[SubRaptor] Nessun dominio valido nei target (IP puri o CIDR saltati per subdomain discovery).")
        return {"domains": [], "total_subdomains": 0, "live_subdomains": [], "takeovers": [], "dns_zones": [], "sources": {}}, []

    all_subs: Set[str] = set()
    agg_sources: Dict[str, Dict[str, Any]] = {}
    all_live_rows: List[Dict[str, Any]] = []
    all_takeovers: List[Dict[str, Any]] = []
    all_dns_zones: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    for dom in domains[:5]:
        log("INFO", f"[SubRaptor] Avvio aggregazione passiva per {dom} (subfinder, crt.sh, assetfinder)...")
        sf_task = _run_subfinder_source(dom, proxy_url)
        crt_task = _fetch_crtsh_subdomains(dom, proxy_url)
        af_task = _run_assetfinder_source(dom, proxy_url)
        (sf_st, sf_raw), (crt_st, crt_raw), (af_st, af_raw) = await asyncio.gather(sf_task, crt_task, af_task)

        source_sets: Dict[str, Tuple[str, Set[str]]] = {
            "subfinder": (sf_st, set(normalize_subdomains(sf_raw, dom))),
            "crtsh": (crt_st, set(normalize_subdomains(crt_raw, dom))),
            "assetfinder": (af_st, set(normalize_subdomains(af_raw, dom))),
        }

        if wordlist_id and wordlist_id != "passive_only":
            if onion_mode:
                log("WARN", f"[SubRaptor] Wordlist DNS bruteforce disabilitata in Onion Mode su {dom} per evitare DNS leak UDP.")
                source_sets["dns_bruteforce"] = ("skipped", set())
            else:
                log("INFO", f"[SubRaptor] Avvio DNS bruteforce controllato con wordlist '{wordlist_id}' su {dom}...")
                bf_st, bf_raw = await _run_dns_bruteforce(dom, wordlist_id)
                source_sets["dns_bruteforce"] = (bf_st, set(normalize_subdomains(bf_raw, dom)))

        if "dns_zone" in active_checks:
            if onion_mode:
                log("WARN", f"[DNS Zone Audit] Saltato in Onion Mode su {dom} per prevenire query DNS dirette.")
            else:
                log("INFO", f"[DNS Zone Audit] Verifica AXFR / Wildcard / SPF-DMARC per {dom}...")
                z_sum, z_findings, axfr_subs = await run_dns_zone_audit(dom)
                all_dns_zones.append(z_sum)
                findings.extend(z_findings)
                if axfr_subs:
                    source_sets["axfr_zone"] = ("ok", set(axfr_subs))

        dom_stats = compute_subraptor_source_stats(source_sets)
        agg_sources[dom] = dom_stats

        dom_subs: Set[str] = set()
        for _, s_set in source_sets.values():
            dom_subs.update(s_set)
        dom_subs.add(dom)
        all_subs.update(dom_subs)

        sorted_dom_subs = sorted(dom_subs)
        log("INFO", f"[SubRaptor] {dom}: {len(sorted_dom_subs)} sottodomini unici aggregati ({dom_stats}).")

        dom_live: List[Dict[str, Any]] = []
        if "httpx" in active_checks or "live" in active_checks:
            log("INFO", f"[httpx] Verifica endpoint web attivi e stack tecnologico su {min(len(sorted_dom_subs), 150)} sottodomini...")
            dom_live = await run_httpx_probe(sorted_dom_subs, proxy_url=proxy_url, log_callback=log_callback)
            all_live_rows.extend(dom_live)
            log("INFO", f"[httpx] Rilevati {len(dom_live)} sottodomini web raggiungibili per {dom}.")

        if "takeover" in active_checks or "subzy" in active_checks:
            log("INFO", f"[Subzy] Audit Subdomain Takeover (CNAME & fingerprint) per {dom}...")
            tk_hits, tk_findings = await run_subzy_takeover_check(
                sorted_dom_subs,
                dom_live,
                proxy_url=proxy_url,
                onion_mode=onion_mode,
            )
            all_takeovers.extend(tk_hits)
            findings.extend(tk_findings)
            if tk_hits:
                log("WARN", f"[Subzy] Rilevati {len(tk_hits)} potenziali Subdomain Takeover su {dom}!")

        if dom_subs:
            live_sample = ", ".join(r["url"] for r in dom_live[:15])
            findings.append({
                "host": dom,
                "port": 443,
                "protocol": "tcp",
                "service": "dns/http",
                "title": f"Superficie Sottodomini Rilevata: {len(sorted_dom_subs)} totali ({len(dom_live)} HTTP/S vivi)",
                "severity": "info",
                "cvss": 0.0,
                "cve_ids": "",
                "cwe_id": "CWE-200",
                "source_engine": "subraptor",
                "description": f"SubRaptor ha aggregato {len(sorted_dom_subs)} sottodomini unici per {dom}; {len(dom_live)} rispondono su HTTP/HTTPS.",
                "evidence": f"Fonti: {json.dumps(dom_stats)}\nCampione sottodomini: {', '.join(sorted_dom_subs[:25])}\nEndpoint vivi: {live_sample or 'N/D'}",
                "remediation": "Verificare periodicamente la superficie esterna esposta, dismettere sottodomini staging non utilizzati e restringere l'accesso ai pannelli non pubblici.",
                "mitre_tactic": "Reconnaissance",
                "mitre_technique": "T1590.002 - Gather Victim Network Information: DNS",
                "ai_insight": "Mappa la reale superficie esposta e i sottodomini legacy spesso esclusi dal perimetro principale.",
            })

    recon_data = {
        "domains": domains,
        "total_subdomains": len(all_subs),
        "subdomains": sorted(all_subs)[:500],
        "sources": agg_sources,
        "live_subdomains": all_live_rows,
        "takeovers": all_takeovers,
        "dns_zones": all_dns_zones,
    }
    return recon_data, findings


# ==========================================
# FEROXBUSTER DIRECTORY ENUMERATION
# ==========================================

_HIGH_SENSITIVE_KEYWORDS = (
    ".git", ".env", "backup", ".bak", ".sql", "dump", "phpinfo",
    "phpmyadmin", "adminer", "wp-config", ".htpasswd", "id_rsa", "credentials", "secret",
)
_MED_SENSITIVE_KEYWORDS = (
    "admin", "login", "dashboard", "console", "swagger", "api-docs",
    "graphql", "actuator", "debug", "server-status", "metrics", "config",
)


def parse_feroxbuster_jsonl(jsonl_text: str) -> List[Dict[str, Any]]:
    """Parse Feroxbuster --json JSONL output lines cleanly into directory discovery records."""
    entries: List[Dict[str, Any]] = []
    seen_urls: Set[str] = set()
    for raw in (jsonl_text or "").splitlines():
        ln = raw.strip()
        if not ln or not ln.startswith("{"):
            continue
        try:
            obj = json.loads(ln)
            if obj.get("type") != "response":
                continue
            url = str(obj.get("url") or "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            entries.append({
                "url": url,
                "path": str(obj.get("path") or urllib.parse.urlparse(url).path or "/"),
                "status": int(obj.get("status") or 0),
                "content_length": int(obj.get("content_length") or 0),
                "words": int(obj.get("word_count") or 0),
                "lines": int(obj.get("line_count") or 0),
                "content_type": str((obj.get("headers") or {}).get("content-type", ""))[:60],
            })
        except Exception:
            continue
    return entries


def classify_feroxbuster_results(entries: List[Dict[str, Any]], base_url: str) -> List[Dict[str, Any]]:
    """Convert discovered directories into prioritized security findings without flooding info items."""
    if not entries:
        return []
    parsed_base = urllib.parse.urlparse(base_url)
    host = parsed_base.hostname or base_url
    port = parsed_base.port or (443 if base_url.startswith("https://") else 80)

    findings: List[Dict[str, Any]] = []
    general_paths: List[str] = []

    for ent in entries:
        status = ent.get("status", 0)
        url = ent.get("url", "")
        path_low = ent.get("path", "").lower()

        if status < 200 or status >= 404:
            if status != 403 and status != 401:
                continue

        if any(k in path_low for k in _HIGH_SENSITIVE_KEYWORDS) and status in (200, 206, 301, 302):
            findings.append({
                "host": host,
                "port": port,
                "protocol": "tcp",
                "service": "http/https",
                "title": f"Directory / File Critico Esposto: {ent['path']} (HTTP {status})",
                "severity": "high",
                "cvss": 7.5,
                "cve_ids": "",
                "cwe_id": "CWE-538",
                "source_engine": "feroxbuster",
                "description": f"L'enumerazione Feroxbuster ha rilevato una risorsa altamente sensibile accessibile su {url}.",
                "evidence": f"URL: {url}\nHTTP Status: {status}\nContent-Length: {ent.get('content_length', 0)}",
                "remediation": "Bloccare l'accesso pubblico tramite web server (deny all) e rimuovere file di backup, debug o metadata VCS dalla webroot.",
                "mitre_tactic": "Discovery",
                "mitre_technique": "T1083 - File and Directory Discovery",
                "ai_insight": "Può esporre credenziali applicative, codice sorgente o database dump.",
            })
        elif any(k in path_low for k in _MED_SENSITIVE_KEYWORDS) and status in (200, 301, 302, 401, 403):
            findings.append({
                "host": host,
                "port": port,
                "protocol": "tcp",
                "service": "http/https",
                "title": f"Endpoint Sensibile / Gestionale Esposto: {ent['path']} (HTTP {status})",
                "severity": "medium",
                "cvss": 5.3,
                "cve_ids": "",
                "cwe_id": "CWE-200",
                "source_engine": "feroxbuster",
                "description": f"Individuato endpoint gestionale, API spec o pannello di diagnostica su {url}.",
                "evidence": f"URL: {url}\nHTTP Status: {status}\nContent-Length: {ent.get('content_length', 0)}",
                "remediation": "Limitare l'accesso ad IP fidati o VPN e disabilitare interfacce Swagger/Actuator/Debug in produzione.",
                "mitre_tactic": "Discovery",
                "mitre_technique": "T1595.003 - Active Scanning: Wordlist Scanning",
                "ai_insight": "Aumenta la superficie d'attacco per attacchi di credential stuffing o privilege escalation.",
            })
        else:
            general_paths.append(f"[{status}] {ent['path']} ({ent.get('content_length', 0)}B)")

    if general_paths:
        findings.append({
            "host": host,
            "port": port,
            "protocol": "tcp",
            "service": "http/https",
            "title": f"Directory & Risorse Web Scoperte ({len(general_paths)} endpoint)",
            "severity": "info",
            "cvss": 0.0,
            "cve_ids": "",
            "cwe_id": "CWE-200",
            "source_engine": "feroxbuster",
            "description": f"Feroxbuster ha enumerato {len(general_paths)} percorsi aggiuntivi su {base_url}.",
            "evidence": "\n".join(general_paths[:50]),
            "remediation": "Verificare che nessuna directory non intenzionale sia esposta pubblicamente.",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1083 - File and Directory Discovery",
            "ai_insight": "Completa la mappatura dei contenuti web raggiungibili sul target.",
        })

    return findings


async def run_feroxbuster_scan(
    urls: List[str],
    wordlist_id: Optional[str] = "dirbuster_medium",
    extensions: Optional[str] = None,
    recursion: bool = False,
    max_depth: int = 2,
    rate_limit: int = 100,
    time_limit: int = 180,
    proxy_url: Optional[str] = None,
    log_callback: Optional[Callable[[str, str], Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Run controlled Feroxbuster directory enumeration across target web URLs."""
    def log(level: str, msg: str) -> None:
        if log_callback:
            try:
                log_callback(level, msg)
            except Exception:
                pass

    ferox_bin = get_feroxbuster_bin_path()
    if not ferox_bin:
        log("INFO", "[Feroxbuster] Binario assente: installazione automatica da GitHub Releases...")
        inst = await install_feroxbuster()
        if not inst.get("success"):
            log("ERROR", f"[Feroxbuster] Impossibile installare Feroxbuster: {inst.get('message')}")
            return [], []
        ferox_bin = inst["path"]

    wpath = await resolve_wordlist_path("web", wordlist_id or "dirbuster_medium")
    if not wpath or not wpath.is_file():
        log("ERROR", f"[Feroxbuster] Wordlist non disponibile: {wordlist_id}")
        return [], []

    safe_rl = max(10, min(int(rate_limit or 100), 500))
    safe_tl = max(30, min(int(time_limit or 180), 600))
    safe_depth = max(1, min(int(max_depth or 2), 10))
    clean_ext = ""
    if extensions and _EXT_CLEAN_RE.match(extensions.strip()):
        clean_ext = extensions.strip()

    all_dirs: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []

    for u in urls[:6]:
        log("INFO", f"[Feroxbuster] Enumerazione directory su {u} (wordlist: {wpath.name}, rate={safe_rl}/s, limit={safe_tl}s)...")
        args = [
            ferox_bin,
            "--url", u,
            "--wordlist", str(wpath),
            "--json",
            "--silent",
            "--no-state",
            "--auto-tune",
            "--insecure",
            "--threads", "25",
            "--rate-limit", str(safe_rl),
            "--time-limit", f"{safe_tl}s",
        ]
        if recursion:
            args.extend(["--depth", str(safe_depth)])
        else:
            args.append("--no-recursion")

        if clean_ext:
            args.extend(["--extensions", clean_ext])

        if proxy_url:
            validated_p = validate_proxy_url(proxy_url)
            if validated_p:
                args.extend(["--proxy", validated_p])

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=float(safe_tl) + 30.0)
            except asyncio.TimeoutError:
                proc.kill()
                stdout, stderr = await proc.communicate()
                log("WARN", f"[Feroxbuster] Timeout su {u}: raccolti risultati parziali.")

            if proc.returncode not in (0, None):
                err_txt = stderr.decode("utf-8", errors="replace").strip()
                if err_txt:
                    log("WARN", f"[Feroxbuster] Exit code {proc.returncode} su {u}: {err_txt[:300]}")

            parsed = parse_feroxbuster_jsonl(stdout.decode("utf-8", errors="replace"))
            log("INFO", f"[Feroxbuster] {u}: rilevati {len(parsed)} percorsi validi.")
            all_dirs.extend(parsed)
            all_findings.extend(classify_feroxbuster_results(parsed, u))
        except Exception as exc:
            log("ERROR", f"[Feroxbuster] Errore durante scansione su {u}: {exc}")

    return all_dirs[:300], all_findings
