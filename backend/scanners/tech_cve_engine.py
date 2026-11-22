import asyncio
import json
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import httpx

from backend.database import get_db_connection
from backend.scanners.recon_engine import run_httpx_probe
from backend.scanners.tor_engine import to_httpx_proxy_url

_WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 3000, 5000, 8888, 9000}

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://api.first.org/data/v1/epss"
_POC_GH_BASE = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"

# (vendor, cpe_product, category)
_CPE_MAP: Dict[str, Tuple[str, str, str]] = {
    "nginx": ("f5", "nginx", "Web Server"),
    "apache": ("apache", "http_server", "Web Server"),
    "apache http server": ("apache", "http_server", "Web Server"),
    "apache httpd": ("apache", "http_server", "Web Server"),
    "httpd": ("apache", "http_server", "Web Server"),
    "microsoft-iis": ("microsoft", "internet_information_services", "Web Server"),
    "iis": ("microsoft", "internet_information_services", "Web Server"),
    "lighttpd": ("lighttpd", "lighttpd", "Web Server"),
    "caddy": ("caddyserver", "caddy", "Web Server"),
    "traefik": ("traefik", "traefik", "Reverse Proxy"),
    "haproxy": ("haproxy", "haproxy", "Reverse Proxy"),
    "tomcat": ("apache", "tomcat", "App Server"),
    "apache tomcat": ("apache", "tomcat", "App Server"),
    "jetty": ("eclipse", "jetty", "App Server"),
    "openssh": ("openbsd", "openssh", "Remote Access"),
    "openssl": ("openssl", "openssl", "Crypto / TLS"),
    "php": ("php", "php", "Runtime / Language"),
    "python": ("python", "python", "Runtime / Language"),
    "node.js": ("nodejs", "node.js", "Runtime / Language"),
    "nodejs": ("nodejs", "node.js", "Runtime / Language"),
    "express": ("expressjs", "express", "Web Framework"),
    "django": ("djangoproject", "django", "Web Framework"),
    "laravel": ("laravel", "laravel", "Web Framework"),
    "spring": ("vmware", "spring_framework", "Web Framework"),
    "next.js": ("vercel", "next.js", "Frontend Framework"),
    "nuxt.js": ("nuxt", "nuxt", "Frontend Framework"),
    "react": ("facebook", "react", "Frontend Library"),
    "vue.js": ("vuejs", "vue", "Frontend Library"),
    "vue": ("vuejs", "vue", "Frontend Library"),
    "angular": ("google", "angular", "Frontend Framework"),
    "jquery": ("jquery", "jquery", "JavaScript Library"),
    "bootstrap": ("getbootstrap", "bootstrap", "UI Framework"),
    "wordpress": ("wordpress", "wordpress", "CMS"),
    "drupal": ("drupal", "drupal", "CMS"),
    "joomla": ("joomla", "joomla\\!", "CMS"),
    "ghost": ("ghost", "ghost", "CMS"),
    "typo3": ("typo3", "typo3", "CMS"),
    "magento": ("magento", "magento", "E-Commerce"),
    "grafana": ("grafana", "grafana", "Observability"),
    "kibana": ("elastic", "kibana", "Observability"),
    "elasticsearch": ("elastic", "elasticsearch", "Search / Data"),
    "jenkins": ("jenkins", "jenkins", "CI/CD"),
    "gitlab": ("gitlab", "gitlab", "DevOps"),
    "phpmyadmin": ("phpmyadmin", "phpmyadmin", "Admin Panel"),
    "roundcube": ("roundcube", "webmail", "Webmail"),
    "proxmox": ("proxmox", "virtual_environment", "Virtualization"),
    "fortios": ("fortinet", "fortios", "Security Appliance"),
    "swagger ui": ("smartbear", "swagger_ui", "API Docs"),
    "redis": ("redis", "redis", "Database / Cache"),
    "postgresql": ("postgresql", "postgresql", "Database"),
    "mysql": ("oracle", "mysql", "Database"),
    "mariadb": ("mariadb", "mariadb", "Database"),
    "vsftpd": ("vsftpd_project", "vsftpd", "FTP Server"),
    "samba": ("samba", "samba", "File Sharing"),
    "dovecot": ("dovecot", "dovecot", "Mail Server"),
    "postfix": ("postfix", "postfix", "Mail Server"),
    "exim": ("exim", "exim", "Mail Server"),
    "bind": ("isc", "bind", "DNS Server"),
    "squid": ("squid-cache", "squid", "Proxy Server"),
    "asp.net": ("microsoft", "asp.net", "Web Framework"),
    "simplehttp": ("python", "python", "Web Server"),
}

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3}(?:[a-zA-Z0-9._-]*)?)")
_META_GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{2,100})["\']'
    r'|<meta[^>]+content=["\']([^"\']{2,100})["\'][^>]+name=["\']generator["\']',
    re.IGNORECASE,
)
_ASSET_RE = re.compile(r'(?:src|href)=["\']([^"\']{3,300})["\']', re.IGNORECASE)
_CVE_YEAR_RE = re.compile(r"^CVE-(\d{4})-\d+$", re.IGNORECASE)


def _norm_host_from_url(url_or_host: str) -> str:
    raw = str(url_or_host or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        return (urllib.parse.urlparse(raw).hostname or "").lower()
    return raw.split("/")[0].split(":")[0].lower()


def _nmap_cpe_to_23(cpe: str) -> str:
    """Convert Nmap CPE 2.2 URI (cpe:/a:vendor:product:ver) into CPE 2.3 string."""
    s = (cpe or "").strip()
    if not s:
        return ""
    if s.startswith("cpe:2.3:"):
        parts = s.split(":")
        while len(parts) < 13:
            parts.append("*")
        return ":".join(parts[:13])
    if s.startswith("cpe:/"):
        body = s[5:]
        segs = body.split(":")
        part = segs[0] if segs else "a"
        vendor = segs[1] if len(segs) > 1 else "*"
        product = segs[2] if len(segs) > 2 else "*"
        ver = segs[3] if len(segs) > 3 and segs[3] else "*"
        return f"cpe:2.3:{part}:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
    return ""


def _lookup_cpe_meta(name: str) -> Tuple[str, str, str]:
    key = (name or "").strip().lower()
    if key in _CPE_MAP:
        return _CPE_MAP[key]
    for alias, meta in _CPE_MAP.items():
        if key == alias or key.startswith(f"{alias} ") or key.startswith(f"{alias}/"):
            return meta
    return "", "", "Technology"


def _build_cpe23(name: str, version: str, raw_cpe: str = "") -> str:
    if raw_cpe:
        conv = _nmap_cpe_to_23(raw_cpe)
        if conv:
            return conv
    vendor, product, _ = _lookup_cpe_meta(name)
    ver_clean = (version or "").strip()
    if vendor and product and ver_clean:
        safe_ver = re.sub(r"[^a-zA-Z0-9._-]", "", ver_clean)
        if safe_ver:
            return f"cpe:2.3:a:{vendor}:{product}:{safe_ver}:*:*:*:*:*:*:*"
    return ""


def _parse_product_version_token(token: str) -> Tuple[str, str]:
    """Split tokens like 'nginx/1.24.0', 'Python:3.13.3', 'WordPress 6.4.2' cleanly."""
    raw = (token or "").strip()
    if not raw:
        return "", ""
    # ProjectDiscovery httpx uses Name:Version (ignoring scheme)
    if ":" in raw and "://" not in raw:
        left, right = raw.split(":", 1)
        m = _VERSION_RE.search(right)
        if m:
            return left.strip(), m.group(1)
    m_slash = re.match(r"^([A-Za-z][A-Za-z0-9._ -]{1,40})[/ ](?:v)?(\d+(?:\.\d+)+[a-zA-Z0-9._-]*)", raw)
    if m_slash:
        return m_slash.group(1).strip(), m_slash.group(2).strip()
    return raw, ""


def _parse_banner_tokens(banner: str) -> List[Tuple[str, str]]:
    """Extract multiple product/version pairs from a Server or X-Powered-By header."""
    results: List[Tuple[str, str]] = []
    if not banner:
        return results
    # Match Name/Version pairs like "Apache/2.4.57 (Debian) OpenSSL/3.0.11"
    for m in re.finditer(r"([A-Za-z][A-Za-z0-9._-]{1,35})/(\d+(?:\.\d+)+[a-zA-Z0-9._-]*)", banner):
        results.append((m.group(1), m.group(2)))
    if not results:
        clean = banner.split("(")[0].strip()
        if clean and len(clean) <= 45:
            results.append((clean, ""))
    return results


def _detect_from_html_and_headers(
    url: str,
    headers: Dict[str, str],
    html_text: str,
) -> List[Dict[str, Any]]:
    """Extract technology & version hints from HTTP response headers, HTML & cookies."""
    items: List[Dict[str, Any]] = []
    host = _norm_host_from_url(url)

    def _add(name: str, version: str = "", category: Optional[str] = None, source: str = "http_header") -> None:
        clean_name = (name or "").strip()
        if not clean_name:
            return
        _, _, mapped_cat = _lookup_cpe_meta(clean_name)
        items.append({
            "name": clean_name,
            "version": (version or "").strip(),
            "category": category or mapped_cat,
            "host": host,
            "url": url,
            "port": urllib.parse.urlparse(url).port or (443 if url.startswith("https://") else 80),
            "source": source,
            "cpe": _build_cpe23(clean_name, version),
        })

    low_headers = {k.lower(): v for k, v in headers.items()}

    for hdr_key in ("server", "x-powered-by", "x-aspnet-version", "via"):
        val = low_headers.get(hdr_key, "")
        if not val:
            continue
        if hdr_key == "x-aspnet-version":
            _add("ASP.NET", val.strip(), "Web Framework", "http_header")
        else:
            for pname, pver in _parse_banner_tokens(val):
                _add(pname, pver, None, "http_header")

    if "x-generator" in low_headers:
        pname, pver = _parse_product_version_token(low_headers["x-generator"])
        _add(pname, pver, None, "http_header")
    if "x-drupal-cache" in low_headers:
        _add("Drupal", "", "CMS", "http_header")
    if "x-varnish" in low_headers:
        _add("Varnish", "", "Reverse Proxy", "http_header")

    cookies = low_headers.get("set-cookie", "").lower()
    if "phpsessid" in cookies:
        _add("PHP", "", "Runtime / Language", "http_cookie")
    if "jsessionid" in cookies:
        _add("Java", "", "Runtime / Language", "http_cookie")
    if "asp.net_sessionid" in cookies:
        _add("ASP.NET", "", "Web Framework", "http_cookie")
    if "laravel_session" in cookies:
        _add("Laravel", "", "Web Framework", "http_cookie")
    if "csrftoken" in cookies and "django" in html_text.lower():
        _add("Django", "", "Web Framework", "http_cookie")

    snippet = (html_text or "")[:120000]
    for m in _META_GEN_RE.finditer(snippet):
        gen_val = (m.group(1) or m.group(2) or "").strip()
        if gen_val:
            pname, pver = _parse_product_version_token(gen_val)
            _add(pname, pver, "CMS", "html_meta")

    # Asset URL fingerprinting (script src / link href)
    seen_assets: Set[str] = set()
    for am in _ASSET_RE.finditer(snippet):
        href = am.group(1)
        low = href.lower()
        if "/_next/" in low and "next" not in seen_assets:
            seen_assets.add("next")
            _add("Next.js", "", "Frontend Framework", "html_asset")
        if "/_nuxt/" in low and "nuxt" not in seen_assets:
            seen_assets.add("nuxt")
            _add("Nuxt.js", "", "Frontend Framework", "html_asset")
        if "swagger-ui" in low and "swagger" not in seen_assets:
            seen_assets.add("swagger")
            vm = re.search(r"swagger-ui[^\d]{0,12}(\d+\.\d+(?:\.\d+)?)", low)
            _add("Swagger UI", vm.group(1) if vm else "", "API Docs", "html_asset")
        for lib_key, lib_label in (
            ("jquery", "jQuery"),
            ("bootstrap", "Bootstrap"),
            ("react", "React"),
            ("vue", "Vue.js"),
            ("angular", "Angular"),
        ):
            if lib_key in low and lib_key not in seen_assets:
                vm = re.search(rf"{lib_key}[.-]v?(\d+\.\d+(?:\.\d+)?)", low) or re.search(r"[?&]ver=(\d+\.\d+(?:\.\d+)?)", low)
                if vm:
                    seen_assets.add(lib_key)
                    _add(lib_label, vm.group(1), None, "html_asset")
        wp_plg = re.search(r"/wp-content/plugins/([a-z0-9_-]+)/.*?(?:\?ver=([0-9.]+))?", low)
        if wp_plg:
            plg_name = f"WordPress {wp_plg.group(1)}"
            if plg_name not in seen_assets:
                seen_assets.add(plg_name)
                _add(plg_name, wp_plg.group(2) or "", "CMS Plugin", "html_asset")

    return items


async def run_tech_fingerprint(
    urls: List[str],
    hosts_dict: Dict[str, Dict[str, Any]],
    existing_live_rows: Optional[List[Dict[str, Any]]] = None,
    proxy_url: Optional[str] = None,
    log_callback: Optional[Callable[[str, str], Any]] = None,
) -> List[Dict[str, Any]]:
    """Module 1: Standalone Wappalyzer/httpx + HTML/Header + Nmap CPE Tech Fingerprinter."""
    def log(level: str, msg: str) -> None:
        if log_callback:
            try:
                log_callback(level, msg)
            except Exception:
                pass

    # Derive web URLs from hosts_dict open web ports as well as explicit target URLs
    derived_urls: List[str] = list(urls or [])
    for h_key, h_obj in (hosts_dict or {}).items():
        ip_or_host = str(h_obj.get("hostname") or h_obj.get("ip") or h_key).strip()
        if not ip_or_host:
            continue
        for p in h_obj.get("ports", []):
            pnum = int(p.get("port") or 0)
            svc = str(p.get("service") or "").lower()
            if pnum in _WEB_PORTS or "http" in svc:
                scheme = "https" if (pnum in {443, 8443} or "https" in svc or "ssl" in svc) else "http"
                port_part = "" if (scheme == "http" and pnum == 80) or (scheme == "https" and pnum == 443) else f":{pnum}"
                derived_urls.append(f"{scheme}://{ip_or_host}{port_part}")

    unique_urls = list(dict.fromkeys(u.strip() for u in derived_urls if u and u.strip()))[:16]
    collected: List[Dict[str, Any]] = []

    # 1. Reuse existing SubRaptor httpx rows if available; probe any remaining web URLs independently
    live_rows: List[Dict[str, Any]] = list(existing_live_rows or [])
    already_probed_urls: Set[str] = {str(r.get("url") or "").rstrip("/").lower() for r in live_rows if r.get("url")}
    already_probed_hosts: Set[str] = {str(r.get("subdomain") or "").lower() for r in live_rows if r.get("subdomain")}

    missing_urls = [
        u for u in unique_urls
        if u.rstrip("/").lower() not in already_probed_urls and _norm_host_from_url(u) not in already_probed_hosts
    ]
    if missing_urls:
        log("INFO", f"[TechFingerprint] Esecuzione httpx -tech-detect (Wappalyzer) su {len(missing_urls)} endpoint Web...")
        extra_rows = await run_httpx_probe(missing_urls, proxy_url=proxy_url, log_callback=log_callback)
        live_rows.extend(extra_rows)

    for lr in live_rows:
        lr_url = str(lr.get("url") or "")
        lr_host = str(lr.get("subdomain") or _norm_host_from_url(lr_url)).lower()
        lr_port = urllib.parse.urlparse(lr_url).port or (443 if lr_url.startswith("https://") else 80)
        for tech_tok in lr.get("tech") or []:
            tname, tver = _parse_product_version_token(str(tech_tok))
            if tname:
                _, _, cat = _lookup_cpe_meta(tname)
                collected.append({
                    "name": tname,
                    "version": tver,
                    "category": cat,
                    "host": lr_host,
                    "url": lr_url,
                    "port": lr_port,
                    "source": "httpx_wappalyzer",
                    "cpe": _build_cpe23(tname, tver),
                })
        for pname, pver in _parse_banner_tokens(str(lr.get("webserver") or "")):
            _, _, cat = _lookup_cpe_meta(pname)
            collected.append({
                "name": pname,
                "version": pver,
                "category": cat,
                "host": lr_host,
                "url": lr_url,
                "port": lr_port,
                "source": "httpx_banner",
                "cpe": _build_cpe23(pname, pver),
            })

    # 2. Lightweight HTML / Header / Cookie version extractor (works for local LAN & external sites)
    probe_urls = list(dict.fromkeys([r.get("url") for r in live_rows if r.get("url")] + unique_urls))[:12]
    if probe_urls:
        httpx_proxy = to_httpx_proxy_url(proxy_url) if proxy_url else None
        sem = asyncio.Semaphore(6)
        async with httpx.AsyncClient(
            proxy=httpx_proxy,
            verify=False,
            timeout=httpx.Timeout(8.0 if not httpx_proxy else 12.0, connect=5.0),
            follow_redirects=True,
        ) as client:
            async def _fetch_meta(u: str) -> List[Dict[str, Any]]:
                async with sem:
                    try:
                        resp = await client.get(u, headers={"User-Agent": "UrielScan-TechProbe/1.0"})
                        return _detect_from_html_and_headers(str(resp.url or u), dict(resp.headers), resp.text or "")
                    except Exception:
                        return []

            html_batches = await asyncio.gather(*[_fetch_meta(u) for u in probe_urls])
            for batch in html_batches:
                collected.extend(batch)

    # 3. Fuse Nmap CPE & service versions from hosts_dict (covers internal non-web services too)
    for h_key, h_obj in (hosts_dict or {}).items():
        h_name = str(h_obj.get("ip") or h_obj.get("hostname") or h_key).lower()
        for p in h_obj.get("ports", []):
            pnum = int(p.get("port") or 0)
            raw_pname = str(p.get("product_name") or "").strip()
            raw_ver = str(p.get("version") or "").strip()
            raw_cpes = p.get("cpe") or []
            first_cpe = str(raw_cpes[0]) if raw_cpes else ""

            if not raw_pname:
                prod_field = str(p.get("product") or "").strip()
                if prod_field and prod_field.lower() not in {"unknown", "http", "https", "tcpwrapped"}:
                    parsed_n, parsed_v = _parse_product_version_token(prod_field)
                    raw_pname = parsed_n
                    raw_ver = raw_ver or parsed_v

            if not raw_pname:
                continue

            _, _, cat = _lookup_cpe_meta(raw_pname)
            collected.append({
                "name": raw_pname,
                "version": raw_ver,
                "category": cat,
                "host": h_name,
                "url": "",
                "port": pnum,
                "source": "nmap_cpe" if first_cpe else "nmap_service",
                "cpe": _build_cpe23(raw_pname, raw_ver, first_cpe),
            })

    # 4. Deduplicate by (host, normalized_name), keeping richest version + CPE + merged sources
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in collected:
        norm_name = str(item.get("name") or "").strip()
        host = str(item.get("host") or "").strip().lower()
        if not norm_name or not host:
            continue
        key = (host, norm_name.lower())
        existing = merged.get(key)
        if not existing:
            merged[key] = dict(item)
            continue

        # Merge richer metadata (prefer non-empty version, CPE, URL)
        if not existing.get("version") and item.get("version"):
            existing["version"] = item["version"]
        if not existing.get("cpe") and item.get("cpe"):
            existing["cpe"] = item["cpe"]
        if not existing.get("url") and item.get("url"):
            existing["url"] = item["url"]
        if not existing.get("port") and item.get("port"):
            existing["port"] = item["port"]
        if existing.get("category") == "Technology" and item.get("category") != "Technology":
            existing["category"] = item["category"]
        srcs = {s.strip() for s in f"{existing.get('source', '')},{item.get('source', '')}".split(",") if s.strip()}
        existing["source"] = ", ".join(sorted(srcs))

    final_stack = sorted(merged.values(), key=lambda x: (x["host"], x["category"], x["name"].lower()))
    if final_stack:
        versioned = sum(1 for x in final_stack if x.get("version"))
        log("INFO", f"[TechFingerprint] Identificate {len(final_stack)} tecnologie ({versioned} con versione esatta).")
    return final_stack


# ---------------------------------------------------------------------
# Module 2: Version-Based CVE + CISA KEV + EPSS + PoC-in-GitHub Intel
# ---------------------------------------------------------------------

def _cache_get(cache_key: str, ttl_hours: int = 24) -> Optional[Any]:
    try:
        conn = get_db_connection()
        row = conn.execute(
            "SELECT payload_json, updated_at FROM cve_intel_cache WHERE cache_key = ?;",
            (cache_key,),
        ).fetchone()
        conn.close()
        if not row:
            return None
        updated = datetime.fromisoformat(row["updated_at"])
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - updated > timedelta(hours=ttl_hours):
            return None
        return json.loads(row["payload_json"])
    except Exception:
        return None


def _cache_set(cache_key: str, payload: Any) -> None:
    try:
        conn = get_db_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        with conn:
            conn.execute(
                """
                INSERT INTO cve_intel_cache (cache_key, payload_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at;
                """,
                (cache_key, json.dumps(payload), now_iso),
            )
        conn.close()
    except Exception:
        pass


def _cvss_to_severity(cvss: float, is_kev: bool = False) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0 or is_kev:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _extract_nvd_cvss_and_desc(cve_obj: Dict[str, Any]) -> Tuple[float, str]:
    metrics = cve_obj.get("metrics") or {}
    cvss = 0.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr and isinstance(arr, list):
            try:
                cvss = float(arr[0].get("cvssData", {}).get("baseScore") or 0.0)
                break
            except Exception:
                pass
    desc = ""
    for d in cve_obj.get("descriptions") or []:
        if d.get("lang") == "en" and d.get("value"):
            desc = str(d["value"])
            break
    if not desc and (cve_obj.get("descriptions") or []):
        desc = str(cve_obj["descriptions"][0].get("value") or "")
    return cvss, desc


async def _fetch_cisa_kev(client: httpx.AsyncClient) -> Dict[str, Dict[str, Any]]:
    cached = _cache_get("cisa_kev_catalog", ttl_hours=24)
    if isinstance(cached, dict):
        return cached
    try:
        resp = await client.get(_CISA_KEV_URL)
        if resp.status_code != 200:
            return {}
        data = resp.json()
        kev_map: Dict[str, Dict[str, Any]] = {}
        for v in data.get("vulnerabilities") or []:
            cid = str(v.get("cveID") or "").upper()
            if cid:
                kev_map[cid] = {
                    "due_date": str(v.get("dueDate") or ""),
                    "ransomware": str(v.get("knownRansomwareCampaignUse") or ""),
                    "name": str(v.get("vulnerabilityName") or ""),
                }
        _cache_set("cisa_kev_catalog", kev_map)
        return kev_map
    except Exception:
        return {}


async def _fetch_nvd_cves(
    client: httpx.AsyncClient,
    name: str,
    version: str,
    cpe: str,
) -> List[Dict[str, Any]]:
    query_id = f"nvd:{cpe}" if cpe else f"nvd:kw:{name.lower()}:{version.lower()}"
    cached = _cache_get(query_id, ttl_hours=24)
    if isinstance(cached, list):
        return cached

    params: Dict[str, str] = {"resultsPerPage": "20"}
    if cpe and cpe.startswith("cpe:2.3:"):
        params["cpeName"] = cpe
    else:
        params["keywordSearch"] = f"{name} {version}"
        params["keywordExactMatch"] = ""

    try:
        resp = await client.get(_NVD_URL, params=params, headers={"User-Agent": "UrielScan-CVEIntel/1.0"})
        # Polite pacing for NVD unauthenticated public rate limit
        await asyncio.sleep(0.35)
        if resp.status_code != 200:
            return []
        data = resp.json()
        rows: List[Dict[str, Any]] = []
        for entry in data.get("vulnerabilities") or []:
            cve_obj = entry.get("cve") or {}
            cid = str(cve_obj.get("id") or "").upper()
            if not cid:
                continue
            cvss, desc = _extract_nvd_cvss_and_desc(cve_obj)
            if cvss < 4.0:
                continue
            rows.append({
                "cve_id": cid,
                "cvss": round(cvss, 1),
                "published": str(cve_obj.get("published") or "")[:10],
                "summary": desc[:400],
            })
        _cache_set(query_id, rows)
        return rows
    except Exception:
        return []


async def _fetch_epss_scores(client: httpx.AsyncClient, cve_ids: List[str]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    missing: List[str] = []
    for cid in cve_ids:
        cval = _cache_get(f"epss:{cid}", ttl_hours=24)
        if isinstance(cval, (int, float)):
            out[cid] = float(cval)
        else:
            missing.append(cid)

    if not missing:
        return out

    # Query FIRST EPSS in chunks of 30 CVE IDs
    for idx in range(0, len(missing), 30):
        chunk = missing[idx:idx + 30]
        try:
            resp = await client.get(_EPSS_URL, params={"cve": ",".join(chunk)})
            if resp.status_code != 200:
                continue
            data = resp.json()
            for row in data.get("data") or []:
                cid = str(row.get("cve") or "").upper()
                if not cid:
                    continue
                try:
                    score = round(float(row.get("epss") or 0.0), 4)
                except Exception:
                    score = 0.0
                out[cid] = score
                _cache_set(f"epss:{cid}", score)
        except Exception:
            continue
    return out


async def _fetch_poc_links(client: httpx.AsyncClient, cve_id: str, sem: asyncio.Semaphore) -> List[str]:
    cached = _cache_get(f"poc:{cve_id}", ttl_hours=24)
    if isinstance(cached, list):
        return cached

    ym = _CVE_YEAR_RE.match(cve_id)
    if not ym:
        return []
    year = ym.group(1)
    url = f"{_POC_GH_BASE}/{year}/{cve_id}.json"

    async with sem:
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                _cache_set(f"poc:{cve_id}", [])
                return []
            arr = resp.json()
            links: List[str] = []
            if isinstance(arr, list):
                for repo in arr:
                    if not isinstance(repo, dict):
                        continue
                    html_u = str(repo.get("html_url") or "").strip()
                    if not html_u:
                        clone_u = str(repo.get("clone_url") or "").strip()
                        html_u = clone_u[:-4] if clone_u.endswith(".git") else clone_u
                    if html_u and html_u not in links:
                        links.append(html_u)
                    if len(links) >= 3:
                        break
            _cache_set(f"poc:{cve_id}", links)
            return links
        except Exception:
            return []


async def run_cve_intel_correlation(
    tech_stack: List[Dict[str, Any]],
    proxy_url: Optional[str] = None,
    max_cves_per_tech: int = 5,
    log_callback: Optional[Callable[[str, str], Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Module 2: Correlate versioned technologies with NVD CVEs, CISA KEV, EPSS & PoC-in-GitHub."""
    def log(level: str, msg: str) -> None:
        if log_callback:
            try:
                log_callback(level, msg)
            except Exception:
                pass

    # Only correlate technologies with an explicit numeric version to avoid false positives
    versioned_items = [
        item for item in (tech_stack or [])
        if str(item.get("version") or "").strip()
        and _VERSION_RE.search(str(item.get("version") or ""))
    ]
    if not versioned_items:
        return [], []

    # Deduplicate (name, version, cpe) lookup keys and cap to 15 per scan
    lookup_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in versioned_items:
        k = (str(item["name"]).strip().lower(), str(item["version"]).strip().lower())
        if k not in lookup_groups:
            lookup_groups[k] = {
                "name": str(item["name"]).strip(),
                "version": str(item["version"]).strip(),
                "cpe": str(item.get("cpe") or "").strip(),
                "instances": [],
            }
        elif not lookup_groups[k]["cpe"] and item.get("cpe"):
            lookup_groups[k]["cpe"] = str(item["cpe"]).strip()
        lookup_groups[k]["instances"].append(item)

    capped_groups = list(lookup_groups.values())[:15]
    log("INFO", f"[CVE Intel] Correlazione NVD / CISA KEV / EPSS / PoC-in-GitHub su {len(capped_groups)} componenti versionati...")

    httpx_proxy = to_httpx_proxy_url(proxy_url) if proxy_url else None
    raw_matches: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(
        proxy=httpx_proxy,
        verify=True,
        timeout=httpx.Timeout(12.0, connect=8.0),
        follow_redirects=True,
    ) as client:
        kev_map = await _fetch_cisa_kev(client)

        all_unique_cves: Set[str] = set()
        group_results: List[Tuple[Dict[str, Any], List[Dict[str, Any]]]] = []
        for grp in capped_groups:
            nvd_rows = await _fetch_nvd_cves(client, grp["name"], grp["version"], grp["cpe"])
            if not nvd_rows:
                continue
            enriched_rows = []
            for r in nvd_rows:
                cid = r["cve_id"]
                kev_info = kev_map.get(cid)
                enriched_rows.append({
                    **r,
                    "is_kev": bool(kev_info),
                    "kev_info": kev_info,
                })
            enriched_rows.sort(
                key=lambda x: (1 if x["is_kev"] else 0, x["cvss"], x["published"]),
                reverse=True,
            )
            top_rows = enriched_rows[:max_cves_per_tech]
            for r in top_rows:
                all_unique_cves.add(r["cve_id"])
            group_results.append((grp, top_rows))

        if not all_unique_cves:
            log("INFO", "[CVE Intel] Nessuna CVE critica/rilevante associata alle versioni rilevate.")
            return [], []

        epss_map = await _fetch_epss_scores(client, sorted(all_unique_cves))
        poc_sem = asyncio.Semaphore(6)
        cve_list_sorted = sorted(all_unique_cves)
        poc_lists = await asyncio.gather(*[_fetch_poc_links(client, cid, poc_sem) for cid in cve_list_sorted])
        poc_map: Dict[str, List[str]] = dict(zip(cve_list_sorted, poc_lists))

        for grp, top_rows in group_results:
            for r in top_rows:
                cid = r["cve_id"]
                is_kev = r["is_kev"]
                cvss = float(r["cvss"])
                sev = _cvss_to_severity(cvss, is_kev=is_kev)
                epss_val = epss_map.get(cid)
                poc_urls = poc_map.get(cid) or []
                for inst in grp["instances"]:
                    raw_matches.append({
                        "cve_id": cid,
                        "product": grp["name"],
                        "version": grp["version"],
                        "host": inst.get("host") or "",
                        "url": inst.get("url") or "",
                        "port": int(inst.get("port") or 0),
                        "cvss": cvss,
                        "severity": sev,
                        "is_kev": is_kev,
                        "epss": epss_val,
                        "published": r["published"],
                        "summary": r["summary"],
                        "poc_urls": poc_urls,
                    })

    # Convert matches into structured UrielScan findings with transparent VERSION-BASED framing
    intel_findings: List[Dict[str, Any]] = []
    seen_finding_keys: Set[Tuple[str, str, str]] = set()
    for m in raw_matches:
        fkey = (m["host"], m["product"].lower(), m["cve_id"])
        if fkey in seen_finding_keys:
            continue
        seen_finding_keys.add(fkey)

        prefix = "[CISA KEV]" if m["is_kev"] else "[CVE Intel]"
        epss_pct = f"{m['epss'] * 100:.2f}%" if isinstance(m.get("epss"), float) else "N/A"
        poc_block = "\n".join(f"- {u}" for u in m.get("poc_urls") or []) or "Nessun PoC pubblico indicizzato"

        evidence = (
            f"[VERSION-BASED INTEL - Da verificare rispetto a eventuale backporting OS]\n"
            f"Componente rilevato: {m['product']} {m['version']}\n"
            f"Target: {m.get('url') or m.get('host')}\n"
            f"Pubblicata: {m.get('published') or 'N/D'} | CISA KEV: {'SI (Sfruttata attivamente)' if m['is_kev'] else 'No'} | EPSS: {epss_pct}\n"
            f"Public PoC links:\n{poc_block}"
        )
        remediation = (
            f"Verificare la build esatta di {m['product']} ({m['version']}) ed aggiornare a una release non vulnerabile a {m['cve_id']}. "
            "Se gestito tramite repository di distribuzione Linux (Debian/Ubuntu/RHEL), confermare l'eventuale patch backportata."
        )

        intel_findings.append({
            "host": m["host"],
            "port": m["port"],
            "protocol": "tcp",
            "service": m["product"].lower(),
            "title": f"{prefix} {m['cve_id']} su {m['product']} {m['version']}",
            "severity": m["severity"],
            "cvss": m["cvss"],
            "cve_ids": m["cve_id"],
            "cwe_id": "",
            "source_engine": "cve_intel",
            "description": m["summary"] or f"Vulnerabilità potenziale associata alla versione {m['version']} di {m['product']}.",
            "evidence": evidence,
            "remediation": remediation,
            "mitre_tactic": "Initial Access" if m["is_kev"] else "Discovery",
            "mitre_technique": "T1190 - Exploit Public-Facing Application",
        })

    # Deduplicate cve_matches table rows by (host, product, cve_id)
    unique_matches: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for m in raw_matches:
        uk = (m["host"], m["product"].lower(), m["cve_id"])
        if uk not in unique_matches:
            unique_matches[uk] = m

    sorted_matches = sorted(
        unique_matches.values(),
        key=lambda x: (1 if x.get("is_kev") else 0, x.get("cvss") or 0.0, x.get("epss") or 0.0),
        reverse=True,
    )
    log("INFO", f"[CVE Intel] Correlate {len(sorted_matches)} associazioni CVE/PoC ({sum(1 for m in sorted_matches if m.get('is_kev'))} CISA KEV).")
    return sorted_matches, intel_findings
