"""NAT Loopback / Hairpinning detection & external WAN verification guard."""

import ipaddress
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

import certifi

LAN_HAIRPIN_ONLY_PORTS: Set[int] = {
    22, 23, 53, 80, 139, 443, 445, 1900, 3389, 5000, 5353, 8000, 8080, 8443
}

_EGRESS_IP_CACHE: Dict[str, Any] = {"ip": None, "ts": 0.0}
_EGRESS_TTL_SEC = 60.0

_PUBLIC_IP_PROVIDERS = (
    ("https://api.ipify.org?format=json", "json"),
    ("https://ifconfig.me/ip", "text"),
    ("https://icanhazip.com", "text"),
)


def _ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=certifi.where())


def _is_valid_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


def get_egress_public_ip(timeout: float = 2.5, force_refresh: bool = False) -> Optional[str]:
    """Return this host's current public egress IPv4/IPv6 address with a short 60s TTL cache."""
    now = time.monotonic()
    if (
        not force_refresh
        and _EGRESS_IP_CACHE["ip"]
        and (now - _EGRESS_IP_CACHE["ts"]) < _EGRESS_TTL_SEC
    ):
        return _EGRESS_IP_CACHE["ip"]

    ctx = _ssl_context()
    for url, fmt in _PUBLIC_IP_PROVIDERS:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "UrielScan-NATGuard/1.0", "Accept": "application/json, text/plain"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read(512).decode("utf-8", errors="ignore").strip()
            candidate = json.loads(raw).get("ip", "").strip() if fmt == "json" else raw.splitlines()[0].strip()
            if _is_valid_public_ip(candidate):
                _EGRESS_IP_CACHE["ip"] = candidate
                _EGRESS_IP_CACHE["ts"] = now
                return candidate
        except Exception:
            continue
    return None


def _extract_host(target: str) -> Optional[str]:
    cleaned = (target or "").strip()
    if not cleaned:
        return None
    if "://" in cleaned:
        parsed = urllib.parse.urlparse(cleaned)
        host = parsed.hostname or ""
    else:
        # Strip path if present and avoid treating CIDR as port
        no_path = cleaned.split("/", 1)[0]
        if "/" in cleaned:
            # Might be CIDR; skip large CIDRs (> single /32) for loopback DNS lookup
            try:
                net = ipaddress.ip_network(cleaned, strict=False)
                return str(net.network_address) if net.num_addresses == 1 else None
            except ValueError:
                pass
        # Host:port handling (ignore bare IPv6 with colons unless bracketed)
        if no_path.startswith("["):
            host = no_path[1:].split("]", 1)[0]
        elif no_path.count(":") == 1:
            host = no_path.split(":", 1)[0]
        else:
            host = no_path
    return host.strip() or None


def resolve_target_ips(target: str) -> List[str]:
    """Resolve a target URL, domain, IP, or /32 CIDR to unique IP strings."""
    host = _extract_host(target)
    if not host:
        return []
    try:
        ip_obj = ipaddress.ip_address(host)
        return [str(ip_obj)]
    except ValueError:
        pass

    ips: List[str] = []
    try:
        for info in socket.getaddrinfo(host, None):
            addr = info[4][0]
            if addr and addr not in ips:
                ips.append(addr)
    except Exception:
        pass
    return ips


def check_targets_nat_loopback(
    targets: List[str],
    egress_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Check whether any scan targets resolve to the scanner's own public WAN egress IP."""
    detected_egress = egress_ip if egress_ip is not None else get_egress_public_ip()
    loopback_targets: List[str] = []
    details: List[Dict[str, Any]] = []

    for target in targets:
        t_clean = (target or "").strip()
        if not t_clean:
            continue
        resolved = resolve_target_ips(t_clean)
        is_self = bool(detected_egress and detected_egress in resolved)
        if is_self and t_clean not in loopback_targets:
            loopback_targets.append(t_clean)
        details.append({
            "target": t_clean,
            "host": _extract_host(t_clean) or t_clean,
            "resolved_ips": resolved,
            "is_nat_loopback": is_self,
        })

    return {
        "egress_public_ip": detected_egress,
        "has_nat_loopback": len(loopback_targets) > 0,
        "loopback_targets": loopback_targets,
        "details": details,
    }


def query_external_wan_internetdb(public_ip: str, timeout: float = 4.0) -> Dict[str, Any]:
    """Query Shodan InternetDB for externally observable WAN exposure of a public IP."""
    if not _is_valid_public_ip(public_ip):
        return {
            "ok": False,
            "ip": public_ip,
            "ports": [],
            "vulns": [],
            "cpes": [],
            "hostnames": [],
            "tags": [],
            "error": "Not a valid public IP",
        }

    url = f"https://internetdb.shodan.io/{urllib.parse.quote(public_ip)}"
    req = urllib.request.Request(url, headers={"User-Agent": "UrielScan-NATGuard/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore") or "{}")
        return {
            "ok": True,
            "ip": data.get("ip", public_ip),
            "ports": [int(p) for p in (data.get("ports") or []) if isinstance(p, (int, str)) and str(p).isdigit()],
            "vulns": list(data.get("vulns") or []),
            "cpes": list(data.get("cpes") or []),
            "hostnames": list(data.get("hostnames") or []),
            "tags": list(data.get("tags") or []),
            "error": None,
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # 404 from InternetDB means no open external WAN ports were observed for this IP
            return {
                "ok": True,
                "ip": public_ip,
                "ports": [],
                "vulns": [],
                "cpes": [],
                "hostnames": [],
                "tags": [],
                "error": None,
            }
        return {
            "ok": False,
            "ip": public_ip,
            "ports": [],
            "vulns": [],
            "cpes": [],
            "hostnames": [],
            "tags": [],
            "error": f"HTTP {exc.code}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "ip": public_ip,
            "ports": [],
            "vulns": [],
            "cpes": [],
            "hostnames": [],
            "tags": [],
            "error": str(exc),
        }


def filter_loopback_artifacts(
    loopback_details: List[Dict[str, Any]],
    all_hosts: List[Dict[str, Any]],
    all_findings: List[Dict[str, Any]],
    wan_info: Dict[str, Any],
    egress_ip: str,
    locale: str = "en",
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Suppress internal router hairpinning false positives when scanning own public WAN IP from inside LAN.
    Returns (filtered_hosts, filtered_findings, stats).
    """
    loopback_hosts: Set[str] = {egress_ip}
    for item in loopback_details:
        if item.get("is_nat_loopback"):
            if item.get("host"):
                loopback_hosts.add(item["host"])
            if item.get("target"):
                loopback_hosts.add(item["target"])
            for rip in item.get("resolved_ips") or []:
                loopback_hosts.add(rip)

    wan_verified = bool(wan_info.get("ok"))
    confirmed_wan_ports: Set[int] = set(wan_info.get("ports") or [])

    def _is_port_hairpin_fp(port_val: Any) -> bool:
        if port_val is None or port_val == "" or port_val == 0:
            return False
        try:
            p_int = int(port_val)
        except (TypeError, ValueError):
            return False
        if wan_verified:
            return p_int not in confirmed_wan_ports
        return p_int in LAN_HAIRPIN_ONLY_PORTS

    suppressed_ports_count = 0
    filtered_hosts: List[Dict[str, Any]] = []
    for host_entry in all_hosts:
        h_ip = str(host_entry.get("ip") or "").strip()
        h_name = str(host_entry.get("hostname") or "").strip()
        if h_ip in loopback_hosts or h_name in loopback_hosts:
            kept_ports = []
            for port_obj in host_entry.get("ports") or []:
                p_num = port_obj.get("port") if isinstance(port_obj, dict) else port_obj
                if _is_port_hairpin_fp(p_num):
                    suppressed_ports_count += 1
                else:
                    kept_ports.append(port_obj)
            updated_host = dict(host_entry)
            updated_host["ports"] = kept_ports
            updated_host["nat_loopback_filtered"] = True
            filtered_hosts.append(updated_host)
        else:
            filtered_hosts.append(host_entry)

    suppressed_findings_count = 0
    filtered_findings: List[Dict[str, Any]] = []
    for f in all_findings:
        f_host = str(f.get("host") or "").strip()
        f_host_extracted = _extract_host(f_host) or f_host
        is_lb_host = f_host in loopback_hosts or f_host_extracted in loopback_hosts
        if is_lb_host and _is_port_hairpin_fp(f.get("port")):
            suppressed_findings_count += 1
            continue
        filtered_findings.append(f)

    it = (locale or "en").lower().startswith("it")
    ports_str = ", ".join(str(p) for p in sorted(confirmed_wan_ports)) if confirmed_wan_ports else ("nessuna" if it else "none")
    if wan_verified:
        desc = (
            f"Il target corrisponde all'IP pubblico di uscita locale ({egress_ip}). La scansione dall'interno della LAN ha "
            f"attivato il NAT Loopback/Hairpinning verso il router interno. UrielScan ha verificato l'esposizione WAN esterna "
            f"tramite Shodan InternetDB: porte esterne confermate = [{ports_str}]; soppressi {suppressed_findings_count} finding "
            f"e {suppressed_ports_count} porte interne del router per prevenire falsi positivi."
            if it else
            f"Target resolves to this scanner's own public egress IP ({egress_ip}). Scanning from inside the LAN triggers "
            f"NAT Loopback/Hairpinning against the local router interface. UrielScan verified true external WAN exposure via "
            f"Shodan InternetDB: confirmed external WAN ports = [{ports_str}]; suppressed {suppressed_findings_count} hairpin findings "
            f"and {suppressed_ports_count} router LAN ports to prevent false positives."
        )
        remediation = (
            "Per un test attivo dall'esterno reale, eseguire la scansione tramite una Remote Probe esterna (es. VPS o rete 4G/5G)."
            if it else
            "For active external testing from outside the perimeter, run the scan via an external Remote Probe (e.g. cloud VPS or external network)."
        )
    else:
        desc = (
            f"Il target corrisponde all'IP pubblico di uscita locale ({egress_ip}) causando NAT Loopback/Hairpinning sul router LAN. "
            f"Verifica esterna InternetDB non disponibile ({wan_info.get('error')}); filtrate le porte tipiche di gestione router LAN "
            f"({suppressed_findings_count} finding e {suppressed_ports_count} porte soppressi)."
            if it else
            f"Target resolves to this scanner's own public egress IP ({egress_ip}), causing LAN NAT Loopback/Hairpinning. "
            f"External InternetDB verification unavailable ({wan_info.get('error')}); filtered typical router LAN management ports "
            f"({suppressed_findings_count} findings and {suppressed_ports_count} ports suppressed)."
        )
        remediation = (
            "Utilizzare una Remote Probe posizionata all'esterno della rete per evitare il NAT Hairpinning del router."
            if it else
            "Use an externally hosted Remote Probe outside this LAN to bypass router NAT Hairpinning."
        )

    vulns_note = f"\nExternal CVEs (InternetDB): {', '.join(wan_info.get('vulns') or [])}" if wan_info.get("vulns") else ""
    filtered_findings.append({
        "host": egress_ip,
        "port": None,
        "protocol": "tcp",
        "service": "nat-loopback-guard",
        "title": "NAT Loopback / Hairpinning Guard Attivato — Falsi Positivi Filtrati" if it else "NAT Loopback / Hairpinning Guard Active — False Positives Filtered",
        "severity": "info",
        "cvss": 0.0,
        "cve_ids": ", ".join(wan_info.get("vulns") or []),
        "cwe_id": "CWE-16",
        "source_engine": "nat_guard",
        "description": desc,
        "evidence": f"Egress WAN IP: {egress_ip}\nInternetDB Verified: {wan_verified}\nConfirmed External Ports: {sorted(confirmed_wan_ports)}{vulns_note}\nSuppressed Hairpin Ports: {suppressed_ports_count}\nSuppressed Hairpin Findings: {suppressed_findings_count}",
        "remediation": remediation,
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery",
        "ai_insight": desc,
    })

    stats = {
        "nat_loopback_detected": True,
        "egress_public_ip": egress_ip,
        "confirmed_wan_ports": sorted(confirmed_wan_ports),
        "internetdb_verified": wan_verified,
        "suppressed_ports": suppressed_ports_count,
        "suppressed_findings": suppressed_findings_count,
    }
    return filtered_hosts, filtered_findings, stats
