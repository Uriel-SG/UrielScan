import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_RANK: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

ENGINE_ORDER: Dict[str, int] = {
    "zap": 0,
    "nuclei": 1,
    "nmap": 2,
    "native_web": 3,
    "native_ssl": 4,
    "native_net": 5,
    "native_probe": 6,
    "native": 7,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

_SIGNATURE_RULES: List[Tuple[str, Tuple[str, ...]]] = [
    ("missing_hsts", ("strict-transport-security", "hsts")),
    ("missing_csp", ("content-security-policy", "csp not set", "csp header")),
    ("missing_xfo", ("x-frame-options", "clickjacking", "cwe-1021", "anti-clickjacking")),
    ("missing_xcto", ("x-content-type-options", "nosniff", "mime-sniffing", "mime sniffing")),
    ("missing_referrer_policy", ("referrer-policy",)),
    ("missing_permissions_policy", ("permissions-policy", "feature-policy")),
    ("server_banner_disclosure", ("server leaks version", "x-powered-by", "server header", "server banner", "version disclosure")),
    ("cookie_no_httponly", ("httponly", "cwe-1004")),
    ("cookie_no_secure", ("cookie without secure", "secure flag", "cwe-614")),
    ("cookie_no_samesite", ("samesite",)),
    ("cors_misconfig", ("cors", "access-control-allow-origin")),
    ("weak_tls", ("tls 1.0", "tls 1.1", "tlsv1.0", "tlsv1.1", "sslv3", "sslv2", "weak cipher", "deprecated tls", "protocollo crittografico deprecato")),
    ("cert_issue", ("certificate expired", "self-signed", "certificato scaduto", "untrusted certificate")),
    ("exposed_git", (".git", "git repository")),
    ("exposed_env", (".env",)),
    ("directory_listing", ("directory browsing", "directory listing", "index of")),
    ("sql_injection", ("sql injection", "sqli", "cwe-89")),
    ("xss", ("cross-site scripting", "cross site scripting", "xss", "cwe-79")),
    ("open_redirect", ("open redirect", "cwe-601")),
    ("csrf_missing", ("anti-csrf", "cross-site request forgery", "cwe-352")),
    ("http_trace", ("http trace", "cross-site tracing", "xst")),
    ("path_traversal", ("path traversal", "directory traversal", "cwe-22")),
]


def _norm_severity(sev: Any) -> str:
    s = str(sev or "info").strip().lower()
    return s if s in SEVERITY_RANK else "info"


def _norm_host_and_port(finding: Dict[str, Any]) -> Tuple[str, int]:
    raw_host = str(finding.get("host") or "").strip().lower()
    raw_port = finding.get("port")
    try:
        port = int(raw_port or 0)
    except Exception:
        port = 0

    if raw_host.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(raw_host)
        raw_host = (parsed.hostname or raw_host).lower()
        if not port:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
    else:
        if "/" in raw_host:
            raw_host = raw_host.split("/", 1)[0]
        if raw_host.startswith("[") and "]" in raw_host:
            bracket_host = raw_host[1:raw_host.index("]")]
            rest = raw_host[raw_host.index("]") + 1:]
            if rest.startswith(":") and rest[1:].isdigit() and not port:
                port = int(rest[1:])
            raw_host = bracket_host
        elif raw_host.count(":") == 1:
            hp, pp = raw_host.rsplit(":", 1)
            if pp.isdigit():
                if not port:
                    port = int(pp)
                raw_host = hp

    if not port:
        svc = str(finding.get("service") or "").lower()
        if svc == "https":
            port = 443
        elif svc == "http":
            port = 80

    return raw_host, port


def _extract_cves(finding: Dict[str, Any]) -> List[str]:
    blob = " ".join([
        str(finding.get("cve_ids") or ""),
        str(finding.get("title") or ""),
        str(finding.get("description") or "")[:300],
    ])
    found = [c.upper() for c in _CVE_RE.findall(blob)]
    return list(dict.fromkeys(found))


def _canonical_signature(finding: Dict[str, Any], cves: List[str]) -> str:
    if cves:
        return f"cve:{cves[0]}"

    title = str(finding.get("title") or "")
    cwe = str(finding.get("cwe_id") or "")
    desc = str(finding.get("description") or "")[:120]
    haystack = f"{title} {cwe} {desc}".lower()

    # Handle contextual keyword matching without false overlaps (e.g. .env vs server)
    for sig, keywords in _SIGNATURE_RULES:
        for kw in keywords:
            if kw in (".git", ".env"):
                if re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", haystack):
                    return sig
            elif kw == "xss":
                if re.search(r"\bxss\b", haystack):
                    return sig
            elif kw == "cors":
                if re.search(r"\bcors\b", haystack):
                    return sig
            elif kw in haystack:
                return sig

    norm_title = re.sub(r"[^a-z0-9]+", "", title.lower())
    return f"title:{norm_title or 'untitled'}"


def _split_engines(engine_str: Any) -> List[str]:
    parts = [p.strip().lower() for p in str(engine_str or "native").split("+") if p.strip()]
    return parts or ["native"]


def _join_engines(engines: List[str]) -> str:
    unique = list(dict.fromkeys(engines))
    unique.sort(key=lambda e: (ENGINE_ORDER.get(e, 99), e))
    return "+".join(unique)


def sort_findings_by_severity(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sorts findings strictly from Critical -> High -> Medium -> Low -> Info, then CVSS DESC."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_RANK.get(_norm_severity(f.get("severity")), 4),
            -float(f.get("cvss") or 0.0),
            str(f.get("host") or "").lower(),
            int(f.get("port") or 0),
            str(f.get("title") or "").lower(),
        ),
    )


def _format_evidence_with_engine(engine: str, evidence: str) -> str:
    ev = evidence.strip()
    if not ev:
        return ""
    tag = f"[{engine.upper()}]"
    if ev.startswith(tag):
        return ev
    return f"{tag} {ev}"


def consolidate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicates and merges overlapping findings across ZAP, Nuclei, Nmap NSE, and Native engines,
    preserving highest severity/CVSS, union of CVEs, combined evidence, and sorted severity order.
    """
    merged: Dict[Tuple[str, int, str], Dict[str, Any]] = {}

    for raw in findings:
        if not isinstance(raw, dict):
            continue
        f = dict(raw)
        host, port = _norm_host_and_port(f)
        if not f.get("host"):
            f["host"] = host
        if not f.get("port") and port:
            f["port"] = port

        cves = _extract_cves(f)
        sig = _canonical_signature(f, cves)
        key = (host, port, sig)

        sev = _norm_severity(f.get("severity"))
        try:
            cvss = float(f.get("cvss") or 0.0)
        except Exception:
            cvss = 0.0
        engines = _split_engines(f.get("source_engine"))

        if key not in merged:
            f["severity"] = sev
            f["cvss"] = cvss
            f["cve_ids"] = ", ".join(cves) if cves else str(f.get("cve_ids") or "")
            f["source_engine"] = _join_engines(engines)
            merged[key] = f
            continue

        cur = merged[key]
        cur_sev = _norm_severity(cur.get("severity"))
        cur_cvss = float(cur.get("cvss") or 0.0)

        # Promote severity/CVSS to highest detected across engines
        if SEVERITY_RANK.get(sev, 4) < SEVERITY_RANK.get(cur_sev, 4):
            cur["severity"] = sev
        if cvss > cur_cvss:
            cur["cvss"] = cvss

        # Union CVE IDs
        existing_cves = [c.strip().upper() for c in str(cur.get("cve_ids") or "").split(",") if c.strip()]
        combined_cves = list(dict.fromkeys(existing_cves + cves))
        cur["cve_ids"] = ", ".join(combined_cves)

        # Fill missing CWE or MITRE metadata
        if not cur.get("cwe_id") and f.get("cwe_id"):
            cur["cwe_id"] = f["cwe_id"]
        if (not cur.get("mitre_technique") or cur.get("mitre_technique") == "T1046 - Network Service Discovery") and f.get("mitre_technique"):
            cur["mitre_technique"] = f["mitre_technique"]
        if (not cur.get("mitre_tactic") or cur.get("mitre_tactic") == "Discovery") and f.get("mitre_tactic"):
            cur["mitre_tactic"] = f["mitre_tactic"]

        # Prefer longer description and remediation
        new_desc = str(f.get("description") or "").strip()
        if len(new_desc) > len(str(cur.get("description") or "").strip()):
            cur["description"] = new_desc

        new_rem = str(f.get("remediation") or "").strip()
        if len(new_rem) > len(str(cur.get("remediation") or "").strip()):
            cur["remediation"] = new_rem

        # Merge distinct evidence chunks without duplicates
        cur_ev = str(cur.get("evidence") or "").strip()
        new_ev = str(f.get("evidence") or "").strip()
        if new_ev:
            cur_ev_tagged = _format_evidence_with_engine(_split_engines(cur.get("source_engine"))[0], cur_ev) if cur_ev and not cur_ev.startswith("[") else cur_ev
            new_ev_tagged = _format_evidence_with_engine(engines[0], new_ev)
            if new_ev.lower() not in cur_ev.lower():
                cur["evidence"] = f"{cur_ev_tagged}\n{new_ev_tagged}".strip() if cur_ev_tagged else new_ev_tagged

        # Merge engine attribution in canonical priority order
        all_engines = _split_engines(cur.get("source_engine")) + engines
        cur["source_engine"] = _join_engines(all_engines)

    return sort_findings_by_severity(list(merged.values()))
