"""External Passive OSINT Intelligence Engine (Shodan InternetDB + RIPEstat + GreyNoise Community)."""

import asyncio
import ipaddress
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

import httpx

from backend.scanners.nat_guard import resolve_target_ips
from backend.scanners.tech_cve_engine import _cache_get, _cache_set
from backend.scanners.tor_engine import to_httpx_proxy_url

_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
_RIPESTAT_NET_URL = "https://stat.ripe.net/data/network-info/data.json?resource={ip}"
_RIPESTAT_AS_URL = "https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"
_GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"

_RISKY_SHODAN_TAGS = {"compromised", "doublepulsar", "eol-os", "malware", "ransomware"}
_SENSITIVE_PORTS = {22, 23, 445, 3389, 5900, 6379, 9200, 27017}


def _is_public_global_ip(raw: str) -> Optional[str]:
    """Validate and normalize an IP string if it is globally routable (excludes RFC1918/loopback)."""
    try:
        ip_obj = ipaddress.ip_address(str(raw).strip())
        if ip_obj.is_global and not ip_obj.is_multicast:
            return str(ip_obj)
    except ValueError:
        pass
    return None


def _extract_public_ips(
    targets: Union[str, Sequence[str], None],
    hosts_dict: Optional[Dict[str, Any]] = None,
    max_ips: int = 8,
) -> List[str]:
    """Collect unique globally routable IPs from scan targets and discovered hosts."""
    candidates: List[str] = []
    seen = set()

    def _add(ip_str: Optional[str]) -> None:
        if not ip_str:
            return
        norm = _is_public_global_ip(ip_str)
        if norm and norm not in seen:
            seen.add(norm)
            candidates.append(norm)

    if isinstance(targets, str):
        target_tokens = [tok.strip() for tok in re.split(r"[\s,;]+", targets) if tok.strip()]
    else:
        target_tokens = [str(tok).strip() for tok in (targets or []) if str(tok).strip()]

    for target in target_tokens:
        for ip in resolve_target_ips(target):
            _add(ip)

    if isinstance(hosts_dict, dict):
        for h_key, h_obj in hosts_dict.items():
            _add(h_key)
            if isinstance(h_obj, dict):
                _add(h_obj.get("ip"))

    return candidates[:max_ips]


async def _fetch_shodan_internetdb(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    """Fetch passive port/CPE/CVE/tag metadata for a public IP from Shodan InternetDB."""
    cache_key = f"osint:idb:{ip}"
    cached = _cache_get(cache_key, ttl_hours=24)
    if isinstance(cached, dict):
        return cached
    default_payload: Dict[str, Any] = {
        "ip": ip,
        "ports": [],
        "hostnames": [],
        "cpes": [],
        "vulns": [],
        "tags": [],
    }
    try:
        resp = await client.get(_INTERNETDB_URL.format(ip=ip))
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                payload = {
                    "ip": ip,
                    "ports": sorted({int(p) for p in (data.get("ports") or []) if isinstance(p, (int, str)) and str(p).isdigit()}),
                    "hostnames": [str(h) for h in (data.get("hostnames") or [])[:12]],
                    "cpes": [str(c) for c in (data.get("cpes") or [])[:20]],
                    "vulns": [str(v).upper() for v in (data.get("vulns") or [])[:40]],
                    "tags": [str(t).lower() for t in (data.get("tags") or [])[:20]],
                }
                _cache_set(cache_key, payload)
                return payload
        elif resp.status_code == 404:
            _cache_set(cache_key, default_payload)
            return default_payload
    except Exception:
        pass
    return default_payload


async def _fetch_ripestat_asn(client: httpx.AsyncClient, ip: str) -> Dict[str, str]:
    """Fetch ASN, announced prefix, and holder organization from RIPEstat."""
    cache_key = f"osint:ripe:{ip}"
    cached = _cache_get(cache_key, ttl_hours=24)
    if isinstance(cached, dict):
        return cached
    result = {"asn": "", "prefix": "", "org": ""}
    try:
        net_resp = await client.get(_RIPESTAT_NET_URL.format(ip=ip))
        if net_resp.status_code == 200:
            net_data = (net_resp.json() or {}).get("data") or {}
            asns = net_data.get("asns") or []
            raw_asn = str(asns[0]).lstrip("ASas").strip() if asns else ""
            result["prefix"] = str(net_data.get("prefix") or "")
            if raw_asn:
                result["asn"] = f"AS{raw_asn}"
                try:
                    as_resp = await client.get(_RIPESTAT_AS_URL.format(asn=raw_asn))
                    if as_resp.status_code == 200:
                        as_data = (as_resp.json() or {}).get("data") or {}
                        result["org"] = str(as_data.get("holder") or "")
                except Exception:
                    pass
            _cache_set(cache_key, result)
    except Exception:
        pass
    return result


async def _fetch_greynoise_community(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    """Fetch noise/RIOT/classification context from the free GreyNoise Community API."""
    cache_key = f"osint:gn:{ip}"
    cached = _cache_get(cache_key, ttl_hours=24)
    if isinstance(cached, dict):
        return cached
    not_observed: Dict[str, Any] = {
        "noise": False,
        "riot": False,
        "classification": "unknown",
        "name": "not observed",
        "link": "",
    }
    try:
        resp = await client.get(_GREYNOISE_URL.format(ip=ip))
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                payload = {
                    "noise": bool(data.get("noise")),
                    "riot": bool(data.get("riot")),
                    "classification": str(data.get("classification") or "unknown").lower(),
                    "name": str(data.get("name") or ""),
                    "link": str(data.get("link") or ""),
                }
                _cache_set(cache_key, payload)
                return payload
        elif resp.status_code == 404:
            _cache_set(cache_key, not_observed)
            return not_observed
    except Exception:
        pass
    return not_observed


def _build_osint_findings(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert notable external OSINT signals into UrielScan findings."""
    findings: List[Dict[str, Any]] = []
    ip = row["ip"]
    ports = row.get("ports") or []
    tags = row.get("tags") or []
    vulns = row.get("vulns") or []
    asn_meta = " | ".join(p for p in (row.get("asn"), row.get("org"), row.get("prefix")) if p) or "N/A"

    risky_tags = sorted(set(tags) & _RISKY_SHODAN_TAGS)
    if risky_tags:
        findings.append({
            "host": ip,
            "port": 0,
            "protocol": "tcp",
            "service": "osint",
            "title": "Shodan InternetDB Risky Exposure Tag(s) Detected",
            "severity": "high",
            "cvss": 7.5,
            "cve_ids": ", ".join(vulns[:5]),
            "cwe_id": "CWE-200",
            "source_engine": "osint",
            "description": f"Shodan InternetDB passively flagged external IP {ip} with high-risk exposure tag(s): {', '.join(risky_tags)}.",
            "evidence": f"ASN/Org: {asn_meta}\nRisky tags: {', '.join(risky_tags)}\nIndexed ports: {', '.join(str(p) for p in ports) or 'None'}",
            "remediation": "Verify exposed services on this perimeter IP immediately, decommission EOL/compromised endpoints, and restrict public ingress.",
            "mitre_tactic": "Reconnaissance",
            "mitre_technique": "T1595 - Active Scanning",
        })

    if row.get("greynoise_classification") == "malicious":
        gn_name = row.get("greynoise_name") or "Unknown Actor"
        gn_link = row.get("greynoise_link") or f"https://viz.greynoise.io/ip/{ip}"
        findings.append({
            "host": ip,
            "port": 0,
            "protocol": "tcp",
            "service": "osint",
            "title": "Public IP Flagged Malicious by GreyNoise",
            "severity": "high",
            "cvss": 7.4,
            "cve_ids": "",
            "cwe_id": "CWE-284",
            "source_engine": "osint",
            "description": f"GreyNoise Community API classifies {ip} as malicious internet-scanning noise ({gn_name}). If this IP belongs to your asset, investigate for compromise or abuse.",
            "evidence": f"Classification: malicious\nActor/Name: {gn_name}\nASN/Org: {asn_meta}\nReference: {gn_link}",
            "remediation": "Audit outbound/inbound traffic, host compromise indicators, and abuse logs if this IP is owned by the organization.",
            "mitre_tactic": "Command and Control",
            "mitre_technique": "T1584 - Compromise Infrastructure",
        })

    exposed_sensitive = sorted(set(ports) & _SENSITIVE_PORTS)
    if exposed_sensitive:
        findings.append({
            "host": ip,
            "port": exposed_sensitive[0],
            "protocol": "tcp",
            "service": "osint",
            "title": "Shodan InternetDB: Sensitive Management/Data Port(s) Externally Exposed",
            "severity": "medium",
            "cvss": 5.8,
            "cve_ids": "",
            "cwe_id": "CWE-284",
            "source_engine": "osint",
            "description": f"Passive Shodan InternetDB records show sensitive administrative or database ports publicly reachable on {ip}: {', '.join(str(p) for p in exposed_sensitive)}.",
            "evidence": f"Sensitive exposed ports: {', '.join(str(p) for p in exposed_sensitive)}\nAll Shodan ports: {', '.join(str(p) for p in ports)}\nASN/Org: {asn_meta}",
            "remediation": "Restrict administrative/database ports (SSH, RDP, SMB, VNC, Redis, MongoDB, Elasticsearch) behind VPN or IP allowlists.",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1133 - External Remote Services",
        })

    if vulns:
        findings.append({
            "host": ip,
            "port": ports[0] if ports else 0,
            "protocol": "tcp",
            "service": "osint",
            "title": f"Shodan InternetDB: {len(vulns)} Known CVE(s) Indexed on External IP",
            "severity": "medium",
            "cvss": 5.3,
            "cve_ids": ", ".join(vulns[:10]),
            "cwe_id": "",
            "source_engine": "osint",
            "description": f"Passive Shodan InternetDB CPE/banner matching associates {len(vulns)} CVE(s) with external IP {ip}. Verify patch level/backporting before remediation.",
            "evidence": f"[PASSIVE SHODAN INTERNETDB INDEX - Verify distro backporting]\nTop CVEs: {', '.join(vulns[:10])}\nCPEs: {', '.join(row.get('cpes') or []) or 'N/A'}",
            "remediation": "Validate banner versions directly on the perimeter host and apply vendor security patches for applicable CVEs.",
            "mitre_tactic": "Reconnaissance",
            "mitre_technique": "T1592 - Gather Victim Host Information",
        })

    return findings


async def run_external_osint(
    targets: Union[str, Sequence[str], None],
    hosts_dict: Optional[Dict[str, Any]] = None,
    proxy_url: Optional[str] = None,
    log_callback: Optional[Callable[[str, str], None]] = None,
    max_ips: int = 8,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Enrich public global target IPs via Shodan InternetDB, RIPEstat, and GreyNoise Community."""
    def log(level: str, msg: str) -> None:
        if log_callback:
            try:
                log_callback(level, msg)
            except Exception:
                pass

    public_ips = _extract_public_ips(targets, hosts_dict, max_ips=max_ips)
    if not public_ips:
        log("INFO", "External OSINT: no public global IPs in scope (RFC1918/loopback skipped).")
        return [], []

    log("INFO", f"[External OSINT] Querying Shodan InternetDB, RIPEstat & GreyNoise for {len(public_ips)} public IP(s)...")
    httpx_proxy = to_httpx_proxy_url(proxy_url) if proxy_url else None
    sem = asyncio.Semaphore(4)

    async def _enrich_ip(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
        async with sem:
            idb, ripe, gn = await asyncio.gather(
                _fetch_shodan_internetdb(client, ip),
                _fetch_ripestat_asn(client, ip),
                _fetch_greynoise_community(client, ip),
            )
        return {
            "ip": ip,
            "hostnames": idb.get("hostnames") or [],
            "asn": ripe.get("asn") or "",
            "prefix": ripe.get("prefix") or "",
            "org": ripe.get("org") or "",
            "ports": idb.get("ports") or [],
            "cpes": idb.get("cpes") or [],
            "vulns": idb.get("vulns") or [],
            "tags": idb.get("tags") or [],
            "greynoise_classification": gn.get("classification") or "unknown",
            "greynoise_name": gn.get("name") or "",
            "greynoise_noise": bool(gn.get("noise")),
            "greynoise_riot": bool(gn.get("riot")),
            "greynoise_link": gn.get("link") or "",
        }

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(8.0, connect=5.0),
        follow_redirects=True,
        proxy=httpx_proxy,
        headers={"User-Agent": "UrielScan-OSINT/1.0", "Accept": "application/json"},
    ) as client:
        osint_rows: List[Dict[str, Any]] = list(
            await asyncio.gather(*[_enrich_ip(client, ip) for ip in public_ips])
        )

    osint_findings: List[Dict[str, Any]] = []
    for row in osint_rows:
        osint_findings.extend(_build_osint_findings(row))

    log("INFO", f"[External OSINT] Enriched {len(osint_rows)} public IP(s), generated {len(osint_findings)} exposure alert(s).")
    return osint_rows, osint_findings
