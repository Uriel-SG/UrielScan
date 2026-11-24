import asyncio
import io
import json
import os
import platform
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import httpx

from backend.ai_engine import analyze_findings
from backend.database import DATA_DIR, get_db_connection, get_organization_by_id, get_scan_by_id, get_settings
from backend.scanners.archive_utils import safe_extract_zip

BASE_DIR = Path(__file__).resolve().parent.parent.parent
BIN_DIR = BASE_DIR / "bin"
NETEXEC_DIR = BIN_DIR / "netexec"
NXC_VENV_DIR = BIN_DIR / "nxc_venv"
BH_VENV_DIR = BIN_DIR / "bloodhound_venv"
AZUREHOUND_DIR = BIN_DIR / "azurehound"
ENUM4LINUX_DIR = BIN_DIR / "enum4linux-ng"
EXPORTS_DIR = DATA_DIR / "bloodhound_exports"

NETEXEC_PROTOCOLS: List[str] = ["smb", "ldap", "winrm", "rdp", "mssql", "ssh"]
NETEXEC_CHECKS: List[str] = [
    "smb_signing",
    "smbv1",
    "null_shares",
    "ldap_anon",
    "pass_pol",
    "kerberoast",
    "asrep",
    "adcs",
    "delegation",
    "laps",
]

_HIGH_RISK_GRAPH_ROLES = {
    "rolemanagement.readwrite.directory",
    "approleassignment.readwrite.all",
    "application.readwrite.all",
    "directory.readwrite.all",
    "privilegedroleadministrator",
}

_SAFE_ARG_RE = re.compile(r"^[a-zA-Z0-9._:/,@-]+$")


# ---------------------------------------------------------------------
# Tool Detection & Isolated Installers
# ---------------------------------------------------------------------

def _venv_exe(venv_dir: Path, names: List[str]) -> Optional[Path]:
    sub = "Scripts" if os.name == "nt" else "bin"
    for n in names:
        p = venv_dir / sub / n
        if p.is_file():
            return p
    return None


def _find_netexec_binary() -> Optional[Path]:
    """Locate standalone NetExec binary in bin/netexec, legacy venv, or system PATH."""
    target_names = ("nxc.exe", "netexec.exe") if os.name == "nt" else ("nxc", "netexec")
    if NETEXEC_DIR.is_dir():
        for name in target_names:
            for p in NETEXEC_DIR.rglob(name):
                if p.is_file():
                    return p
    venv_hit = _venv_exe(NXC_VENV_DIR, ["nxc.exe", "netexec.exe", "nxc", "netexec"])
    if venv_hit:
        return venv_hit
    if w := (shutil.which("nxc") or shutil.which("netexec")):
        return Path(w)
    return None


def detect_internal_tools() -> Dict[str, Dict[str, Any]]:
    nxc_bin = _find_netexec_binary()
    bh_bin = _venv_exe(BH_VENV_DIR, ["bloodhound-python.exe", "bloodhound-python"]) or (
        Path(w) if (w := shutil.which("bloodhound-python")) else None
    )
    ah_bin = (
        next((p for p in AZUREHOUND_DIR.glob("azurehound*") if p.is_file() and (p.suffix in (".exe", "") or os.access(p, os.X_OK))), None)
        or (Path(w) if (w := shutil.which("azurehound")) else None)
    )
    e4l_local = ENUM4LINUX_DIR / "enum4linux-ng.py"
    e4l_bin = e4l_local if e4l_local.is_file() else (
        Path(w) if (w := shutil.which("enum4linux-ng") or shutil.which("enum4linux-ng.py")) else None
    )
    resp_bin = shutil.which("responder") or shutil.which("Responder.py")

    def _entry(bin_p: Optional[Path], version_hint: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "installed": bin_p is not None,
            "path": str(bin_p) if bin_p else "",
            "version": version_hint if bin_p else "Not installed",
            **(extra or {}),
        }

    return {
        "netexec": _entry(nxc_bin, "NetExec CLI"),
        "bloodhound": _entry(bh_bin, "bloodhound-python"),
        "azurehound": _entry(ah_bin, "AzureHound CLI"),
        "enum4linux_ng": _entry(
            e4l_bin,
            "enum4linux-ng (Linux native / JSON)" if platform.system() != "Windows" else "Script ready (Samba tools Linux-only)",
        ),
        "responder": {
            "installed": True,  # Native Python passive sniffer always works cross-platform
            "active_binary": bool(resp_bin),
            "path": str(resp_bin or "native-passive-udp"),
            "version": "Responder Active + Native Passive" if resp_bin else "Native Passive UDP Sniffer (Active requires Linux responder)",
        },
    }


async def install_internal_tool(tool_name: str) -> Dict[str, Any]:
    """Provision an Internal/AD tool inside isolated bin/ directories."""
    t = (tool_name or "").strip().lower()
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    py_name = "python.exe" if os.name == "nt" else "python"
    sub = "Scripts" if os.name == "nt" else "bin"

    try:
        if t == "netexec":
            NETEXEC_DIR.mkdir(parents=True, exist_ok=True)
            sys_name = platform.system()

            def _match_nxc_asset(assets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
                for a in assets:
                    nm = str(a.get("name") or "").lower()
                    if sys_name == "Windows" and ("windows" in nm or nm in ("nxc.exe", "nxc.exe.zip")):
                        return a
                    if sys_name == "Darwin" and ("macos" in nm or "darwin" in nm or nm == "nxc-macos"):
                        return a
                    if sys_name not in ("Windows", "Darwin") and ("ubuntu" in nm or "linux" in nm or nm == "nxc"):
                        return a
                return None

            async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
                rel_resp = await client.get("https://api.github.com/repos/Pennyw0rth/NetExec/releases?per_page=10")
                rel_resp.raise_for_status()
                releases = rel_resp.json() if isinstance(rel_resp.json(), list) else []
                chosen_tag = ""
                chosen_asset: Optional[Dict[str, Any]] = None
                for rel in releases:
                    asset = _match_nxc_asset(rel.get("assets") or [])
                    if asset:
                        chosen_tag = str(rel.get("tag_name") or "")
                        chosen_asset = asset
                        break

                if chosen_asset:
                    dl = await client.get(chosen_asset["browser_download_url"])
                    dl.raise_for_status()
                    aname = str(chosen_asset["name"])
                    target_path = NETEXEC_DIR / aname
                    target_path.write_bytes(dl.content)
                    if aname.lower().endswith(".zip"):
                        safe_extract_zip(target_path, NETEXEC_DIR)
                        target_path.unlink(missing_ok=True)
                    elif sys_name != "Windows":
                        norm_bin = NETEXEC_DIR / "nxc"
                        if target_path != norm_bin:
                            shutil.move(str(target_path), str(norm_bin))
                        os.chmod(norm_bin, 0o755)
                    bin_found = _find_netexec_binary()
                    if bin_found and sys_name != "Windows":
                        os.chmod(bin_found, 0o755)
                    det = detect_internal_tools()["netexec"]
                    if det["installed"]:
                        return {
                            "success": True,
                            "message": f"NetExec {chosen_tag} installato in bin/netexec.".strip(),
                            **det,
                        }

            # Source archive fallback only if GitHub binary assets were unavailable
            py_v = NXC_VENV_DIR / sub / py_name
            if not py_v.is_file():
                p1 = await asyncio.create_subprocess_exec(
                    sys.executable, "-m", "venv", str(NXC_VENV_DIR),
                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                _, err1 = await asyncio.wait_for(p1.communicate(), timeout=120.0)
                if p1.returncode != 0 or not py_v.is_file():
                    return {"success": False, "message": f"Errore creazione venv netexec: {err1.decode('utf-8', errors='replace')[:250]}"}
            p2 = await asyncio.create_subprocess_exec(
                str(py_v), "-m", "pip", "install", "--upgrade", "pip",
                "https://github.com/Pennyw0rth/NetExec/archive/refs/heads/main.zip",
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out2, err2 = await asyncio.wait_for(p2.communicate(), timeout=600.0)
            if p2.returncode != 0:
                return {"success": False, "message": f"Installazione NetExec fallita: {(err2 or out2).decode('utf-8', errors='replace')[-300:]}"}
            det = detect_internal_tools()["netexec"]
            return {"success": det["installed"], "message": "NetExec installato in bin/nxc_venv.", **det}

        if t == "bloodhound":
            venv_dir = BH_VENV_DIR
            pkg = "bloodhound"
            py_v = venv_dir / sub / py_name
            if not py_v.is_file():
                p1 = await asyncio.create_subprocess_exec(
                    sys.executable, "-m", "venv", str(venv_dir),
                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                _, err1 = await asyncio.wait_for(p1.communicate(), timeout=120.0)
                if p1.returncode != 0 or not py_v.is_file():
                    return {"success": False, "message": f"Errore creazione venv {t}: {err1.decode('utf-8', errors='replace')[:250]}"}
            p2 = await asyncio.create_subprocess_exec(
                str(py_v), "-m", "pip", "install", "--upgrade", "pip", pkg,
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out2, err2 = await asyncio.wait_for(p2.communicate(), timeout=600.0)
            if p2.returncode != 0:
                return {"success": False, "message": f"Installazione {pkg} fallita: {(err2 or out2).decode('utf-8', errors='replace')[-300:]}"}
            det = detect_internal_tools()[t]
            return {"success": det["installed"], "message": f"{t} installato.", **det}

        if t == "azurehound":
            AZUREHOUND_DIR.mkdir(parents=True, exist_ok=True)
            sys_os = "windows" if platform.system() == "Windows" else ("darwin" if platform.system() == "Darwin" else "linux")
            arch = "amd64" if platform.machine().lower() in ("x86_64", "amd64") else "arm64"
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                rel = await client.get("https://api.github.com/repos/SpecterOps/AzureHound/releases/latest")
                rel.raise_for_status()
                assets = rel.json().get("assets") or []
                asset = next(
                    (a for a in assets if sys_os in a["name"].lower() and arch in a["name"].lower() and a["name"].endswith(".zip")),
                    None,
                )
                if not asset:
                    return {"success": False, "message": f"Nessuna release AzureHound trovata per {sys_os}/{arch}."}
                dl = await client.get(asset["browser_download_url"])
                dl.raise_for_status()
                zpath = AZUREHOUND_DIR / asset["name"]
                zpath.write_bytes(dl.content)
                safe_extract_zip(zpath, AZUREHOUND_DIR)
                zpath.unlink(missing_ok=True)
            det = detect_internal_tools()["azurehound"]
            return {"success": det["installed"], "message": "AzureHound estratto in bin/azurehound.", **det}

        if t == "enum4linux_ng":
            ENUM4LINUX_DIR.mkdir(parents=True, exist_ok=True)
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                dl = await client.get("https://github.com/cddmp/enum4linux-ng/archive/refs/heads/master.zip")
                dl.raise_for_status()
                tmp_zip = BIN_DIR / "enum4linux_ng_tmp.zip"
                tmp_zip.write_bytes(dl.content)
                tmp_dir = BIN_DIR / "_e4l_extract"
                shutil.rmtree(tmp_dir, ignore_errors=True)
                safe_extract_zip(tmp_zip, tmp_dir)
                tmp_zip.unlink(missing_ok=True)
                src_sub = tmp_dir / "enum4linux-ng-master"
                if src_sub.is_dir():
                    for f in src_sub.iterdir():
                        dest = ENUM4LINUX_DIR / f.name
                        if f.is_dir():
                            shutil.copytree(f, dest, dirs_exist_ok=True)
                        else:
                            shutil.copy2(f, dest)
                shutil.rmtree(tmp_dir, ignore_errors=True)
            det = detect_internal_tools()["enum4linux_ng"]
            return {"success": det["installed"], "message": "enum4linux-ng installato in bin/enum4linux-ng.", **det}

        return {"success": False, "message": f"Tool non supportato: {tool_name}"}
    except Exception as exc:
        return {"success": False, "message": f"Errore installazione {tool_name}: {exc}"}


# ---------------------------------------------------------------------
# Pure-Python Parsers & BloodHound / AzureHound Analyzers
# ---------------------------------------------------------------------

def parse_netexec_output(raw_text: str, target: str, protocol: str = "smb") -> List[Dict[str, Any]]:
    """Convert NetExec stdout into structured UrielScan findings."""
    findings: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    proto = (protocol or "smb").lower()
    default_port = {"smb": 445, "ldap": 389, "winrm": 5985, "rdp": 3389, "mssql": 1433, "ssh": 22}.get(proto, 445)

    def _push(host: str, title: str, sev: str, cvss: float, ev: str, rem: str) -> None:
        key = (host, title)
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "host": host or target,
            "port": default_port,
            "protocol": "tcp",
            "service": proto,
            "title": title,
            "severity": sev,
            "cvss": cvss,
            "cve_ids": "",
            "cwe_id": "",
            "source_engine": "netexec",
            "description": f"Rilevato da NetExec ({proto.upper()}) durante audit interno su {host or target}.",
            "evidence": ev,
            "remediation": rem,
            "mitre_tactic": "Lateral Movement" if "signing" in title.lower() else "Discovery",
            "mitre_technique": "T1557 - Adversary-in-the-Middle" if "signing" in title.lower() else "T1046 - Network Service Discovery",
        })

    for raw_ln in (raw_text or "").splitlines():
        ln = raw_ln.strip()
        if not ln:
            continue
        ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", ln)
        host = ip_m.group(1) if ip_m else target

        if "signing:False" in ln or "signing:false" in ln:
            _push(
                host,
                "[NetExec] SMB Signing Disabilitato (Vettore NTLM Relay)",
                "high", 7.8, ln,
                "Abilitare 'Require Security Signature' (SMB Signing) tramite GPO su tutti gli endpoint e server Windows.",
            )
        if "SMBv1:True" in ln or "smbv1:true" in ln:
            _push(
                host,
                "[NetExec] Protocollo SMBv1 Abilitato",
                "high", 8.1, ln,
                "Disabilitare immediatamente SMBv1 via PowerShell/GPO e mantenere solo SMBv2/SMBv3.",
            )
        if re.search(r"\b(READ|WRITE)\b", ln) and ("IPC$" not in ln):
            has_write = "WRITE" in ln
            _push(
                host,
                f"[NetExec] Share SMB Accessibile ({'WRITE' if has_write else 'READ'} senza restrizioni)",
                "high" if has_write else "medium",
                7.5 if has_write else 5.3,
                ln,
                "Rimuovere permessi Everyone/Guest/Anonymous sulla share SMB e applicare principio del minimo privilegio NTFS + Share.",
            )
        if proto == "ldap" and ("anonymous" in ln.lower() or "[+]" in ln):
            if "signing" not in ln.lower() and "kerberoast" not in ln.lower():
                _push(
                    host,
                    "[NetExec] LDAP Bind Anonimo / Enumerazione AD Possibile",
                    "medium", 5.5, ln,
                    "Richiedere LDAP Signing & Channel Binding (LDAPS 636) e disabilitare bind anonimi.",
                )
        if "kerberoast" in ln.lower() or "$krb5tgs$" in ln:
            _push(
                host,
                "[NetExec] Account Kerberoastable Rilevato in Active Directory",
                "high", 7.5, ln[:400],
                "Migrare gli account di servizio a gMSA o password >= 25 caratteri casuali con cifratura AES256.",
            )
        if "asreproast" in ln.lower() or "$krb5asrep$" in ln:
            _push(
                host,
                "[NetExec] Account AS-REP Roastable (Pre-Authentication Disabilitata)",
                "high", 7.8, ln[:400],
                "Riabilitare Kerberos Pre-Authentication ('Do not require Kerberos preauthentication' OFF).",
            )
        if re.search(r"\bESC[1-8]\b", ln):
            _push(
                host,
                "[NetExec] Template ADCS Vulnerabile Rilevato",
                "critical", 9.1, ln[:400],
                "Disabilitare enrollment non privilegiato o rimuovere CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT sul template certificato ADCS.",
            )

    return findings


def parse_enum4linux_ng_json(raw_json_str: str, target: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Parse enum4linux-ng -oJ output into structured summary & findings."""
    findings: List[Dict[str, Any]] = []
    open_shares: List[str] = []
    users_count = 0
    try:
        data = json.loads(raw_json_str or "{}")
    except Exception:
        return {"open_shares": [], "users_count": 0}, []

    shares = data.get("shares") or {}
    if isinstance(shares, dict):
        for sname, sinfo in shares.items():
            if not isinstance(sinfo, dict) or sname.upper() in ("IPC$", "ADMIN$"):
                continue
            access = str(sinfo.get("access") or sinfo.get("type") or "").lower()
            if sinfo.get("read") or sinfo.get("write") or "mapping: ok" in access or "read" in access:
                open_shares.append(sname)
                is_write = bool(sinfo.get("write") or "write" in access)
                findings.append({
                    "host": target,
                    "port": 445,
                    "protocol": "tcp",
                    "service": "smb",
                    "title": f"[Enum4linux-ng] Share Aperta: {sname} ({'WRITE' if is_write else 'READ'})",
                    "severity": "high" if is_write else "medium",
                    "cvss": 7.5 if is_write else 5.3,
                    "cve_ids": "",
                    "cwe_id": "CWE-284",
                    "source_engine": "enum4linux_ng",
                    "description": f"La share di rete '{sname}' è accessibile durante enumerazione SMB.",
                    "evidence": json.dumps({sname: sinfo})[:450],
                    "remediation": f"Limitare le ACL di '{sname}' ai soli gruppi autorizzati e disabilitare accesso Guest.",
                    "mitre_tactic": "Discovery",
                    "mitre_technique": "T1135 - Network Share Discovery",
                })

    users = data.get("users") or {}
    if isinstance(users, dict) and len(users) > 0:
        users_count = len(users)
        findings.append({
            "host": target,
            "port": 445,
            "protocol": "tcp",
            "service": "smb",
            "title": f"[Enum4linux-ng] Enumerazione Utenti via Null Session / RID ({users_count} utenti)",
            "severity": "medium",
            "cvss": 5.0,
            "cve_ids": "",
            "cwe_id": "CWE-200",
            "source_engine": "enum4linux_ng",
            "description": "Gli account locali/dominio risultano enumerabili senza credenziali elevate via RPC/SMB.",
            "evidence": f"Utenti rilevati: {', '.join(list(users.keys())[:10])}",
            "remediation": "Impostare RestrictAnonymous=1 / 'Network access: Do not allow anonymous enumeration of SAM accounts'.",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1087 - Account Discovery",
        })

    pp = data.get("password_policy") or {}
    if isinstance(pp, dict):
        min_len = int(pp.get("min_pw_length") or 99)
        lockout = int(pp.get("lockout_threshold") or 99) if pp.get("lockout_threshold") is not None else 99
        if min_len < 8 or lockout == 0:
            findings.append({
                "host": target,
                "port": 445,
                "protocol": "tcp",
                "service": "ldap",
                "title": "[Enum4linux-ng] Password Policy Debole (Lunghezza Min / Lockout)",
                "severity": "medium",
                "cvss": 5.5,
                "cve_ids": "",
                "cwe_id": "CWE-521",
                "source_engine": "enum4linux_ng",
                "description": "La password policy consente password corte o non applica blocco tentativi (Account Lockout=0).",
                "evidence": json.dumps(pp)[:350],
                "remediation": "Configurare lunghezza minima >= 12-14 caratteri e Account Lockout Threshold = 5 tentativi.",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110 - Brute Force",
            })

    return {"open_shares": open_shares, "users_count": users_count}, findings


def _load_bh_json_entries(raw_bytes: bytes, filename: str) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Extract (section_type, records) pairs from BloodHound .zip or raw .json."""
    out: List[Tuple[str, List[Dict[str, Any]]]] = []

    def _push_json(fname: str, txt: str) -> None:
        try:
            obj = json.loads(txt)
        except Exception:
            return
        if isinstance(obj, dict) and isinstance(obj.get("data"), list):
            meta_t = str((obj.get("meta") or {}).get("type") or fname).lower()
            out.append((meta_t, [r for r in obj["data"] if isinstance(r, dict)]))
        elif isinstance(obj, list):
            out.append((fname.lower(), [r for r in obj if isinstance(r, dict)]))

    if filename.lower().endswith(".zip") or raw_bytes[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
            for member in zf.namelist():
                if member.lower().endswith(".json"):
                    _push_json(member, zf.read(member).decode("utf-8", errors="replace"))
    else:
        _push_json(filename, raw_bytes.decode("utf-8", errors="replace"))
    return out


def analyze_bloodhound_archive(
    raw_bytes: bytes,
    filename: str = "bloodhound.zip",
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Native BloodHound/SharpHound analyzer: detects delegation, ASREP, Kerberoast, dangerous ACLs & hygiene."""
    sections = _load_bh_json_entries(raw_bytes, filename)
    findings: List[Dict[str, Any]] = []
    unconstrained: List[str] = []
    asrep_users: List[str] = []
    kerb_admins: List[str] = []
    pwd_never_exp: List[str] = []
    dangerous_acls: List[str] = []
    domain_admins: List[str] = []
    domain_name = "AD-DOMAIN"

    for sec_name, recs in sections:
        for r in recs:
            props = r.get("Properties") or {}
            if not isinstance(props, dict):
                props = {}
            name = str(props.get("name") or r.get("Name") or r.get("ObjectIdentifier") or "UNKNOWN")
            if props.get("domain") and domain_name == "AD-DOMAIN":
                domain_name = str(props["domain"])
            enabled = props.get("enabled", True)

            # Computers checks
            if "computer" in sec_name or "operatingsystem" in props:
                is_dc = bool(props.get("isdc")) or str(r.get("PrimaryGroupSID") or "").endswith("-516")
                if props.get("unconstraineddelegation") and not is_dc and enabled is not False:
                    unconstrained.append(name)

            # Users checks
            if "user" in sec_name or "dontreqpreauth" in props or "hasspn" in props:
                if props.get("dontreqpreauth") and enabled is not False:
                    asrep_users.append(name)
                if props.get("hasspn") and props.get("admincount") and enabled is not False and "krbtgt" not in name.lower():
                    kerb_admins.append(name)
                if props.get("pwdneverexpires") and enabled is not False:
                    pwd_never_exp.append(name)

            # Domain Admins group size
            if "group" in sec_name and "DOMAIN ADMINS@" in name.upper():
                members = r.get("Members") or []
                if isinstance(members, list):
                    domain_admins.extend(str(m.get("ObjectIdentifier") or m.get("MemberId") or "") for m in members if isinstance(m, dict))

            # Dangerous ACE / ACL edges targeting high-value objects (Domains, GPOs, Domain Admins, Computers)
            aces = r.get("Aces") or []
            if isinstance(aces, list) and (
                "domain" in sec_name or "gpo" in sec_name or "DOMAIN ADMINS@" in name.upper() or props.get("highvalue")
            ):
                for ace in aces:
                    if not isinstance(ace, dict):
                        continue
                    right = str(ace.get("RightName") or "")
                    prin = str(ace.get("PrincipalSID") or ace.get("PrincipalName") or "")
                    if right in ("GenericAll", "WriteDacl", "WriteOwner", "GetChangesAll", "AllExtendedRights"):
                        # Skip well-known SYSTEM / Enterprise Admins / Domain Admins SIDs (-512, -519, S-1-5-18)
                        if not prin.endswith(("-512", "-519")) and prin != "S-1-5-18":
                            dangerous_acls.append(f"{prin} --[{right}]--> {name}")

    if unconstrained:
        findings.append({
            "host": domain_name,
            "port": 389,
            "protocol": "tcp",
            "service": "ldap",
            "title": f"[BloodHound AD] Unconstrained Delegation su {len(unconstrained)} Host non-DC",
            "severity": "critical",
            "cvss": 9.4,
            "cve_ids": "",
            "cwe_id": "CWE-269",
            "source_engine": "bloodhound",
            "description": "Computer non-DC con Unconstrained Delegation possono catturare TGT Kerberos (inclusi Domain Admin) in memoria.",
            "evidence": ", ".join(unconstrained[:12]),
            "remediation": "Disabilitare 'Trusted for delegation' sugli host non-DC o migrare a Constrained / Resource-Based Constrained Delegation.",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1558 - Steal or Forge Kerberos Tickets",
        })

    if dangerous_acls:
        findings.append({
            "host": domain_name,
            "port": 389,
            "protocol": "tcp",
            "service": "ldap",
            "title": f"[BloodHound AD] {len(dangerous_acls)} ACL Critiche su Oggetti High-Value / DCSync",
            "severity": "critical",
            "cvss": 9.3,
            "cve_ids": "",
            "cwe_id": "CWE-732",
            "source_engine": "bloodhound",
            "description": "Permessi AD eccessivi (GenericAll/WriteDacl/WriteOwner/DCSync) consentono escalation verso Domain Admin.",
            "evidence": "\n".join(dangerous_acls[:15]),
            "remediation": "Revisionare le ACL sugli oggetti sensibili, rimuovere deleghe non essenziali e proteggere gli account nel gruppo Protected Users.",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1098 - Account Manipulation",
        })

    if kerb_admins:
        findings.append({
            "host": domain_name,
            "port": 88,
            "protocol": "tcp",
            "service": "kerberos",
            "title": f"[BloodHound AD] {len(kerb_admins)} Account Privilegiati Kerberoastable",
            "severity": "high",
            "cvss": 8.0,
            "cve_ids": "",
            "cwe_id": "CWE-522",
            "source_engine": "bloodhound",
            "description": "Account con flag AdminCount e SPN impostato espongono ticket TGS crackabili offline.",
            "evidence": ", ".join(kerb_admins[:15]),
            "remediation": "Rimuovere SPN non necessari da account admin o migrare a Group Managed Service Accounts (gMSA).",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1558.003 - Kerberoasting",
        })

    if asrep_users:
        findings.append({
            "host": domain_name,
            "port": 88,
            "protocol": "tcp",
            "service": "kerberos",
            "title": f"[BloodHound AD] {len(asrep_users)} Utenti AS-REP Roastable",
            "severity": "high",
            "cvss": 7.6,
            "cve_ids": "",
            "cwe_id": "CWE-287",
            "source_engine": "bloodhound",
            "description": "Account con Kerberos Pre-Authentication disabilitata (DontReqPreAuth=True).",
            "evidence": ", ".join(asrep_users[:15]),
            "remediation": "Abilitare Kerberos Pre-Authentication per tutti gli utenti interessati.",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1558.004 - AS-REP Roasting",
        })

    if len(pwd_never_exp) > 0:
        findings.append({
            "host": domain_name,
            "port": 389,
            "protocol": "tcp",
            "service": "ldap",
            "title": f"[BloodHound AD] {len(pwd_never_exp)} Account Attivi con Password Never Expires",
            "severity": "medium",
            "cvss": 5.0,
            "cve_ids": "",
            "cwe_id": "CWE-262",
            "source_engine": "bloodhound",
            "description": "Account abilitati con scadenza password disattivata aumentano l'esposizione di credenziali datate.",
            "evidence": ", ".join(pwd_never_exp[:15]),
            "remediation": "Applicare rotazione periodica o password lunghe con MFA + monitoraggio compromissione.",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1078 - Valid Accounts",
        })

    summary = {
        "domain": domain_name,
        "unconstrained_delegation": len(unconstrained),
        "dangerous_acls": len(dangerous_acls),
        "kerberoastable_admins": len(kerb_admins),
        "asrep_roastable": len(asrep_users),
        "pwd_never_expires": len(pwd_never_exp),
        "domain_admins_count": len(domain_admins),
    }
    return summary, findings


def analyze_azurehound_json(
    raw_bytes: bytes,
    filename: str = "azurehound.json",
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Native AzureHound Entra ID analyzer for Global Admins, high-risk Graph permissions & app ownership."""
    items: List[Dict[str, Any]] = []
    if filename.lower().endswith(".zip") or raw_bytes[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
            for member in zf.namelist():
                if member.lower().endswith(".json"):
                    try:
                        parsed = json.loads(zf.read(member).decode("utf-8", errors="replace"))
                        if isinstance(parsed, dict) and isinstance(parsed.get("data"), list):
                            items.extend(parsed["data"])
                        elif isinstance(parsed, list):
                            items.extend(parsed)
                    except Exception:
                        continue
    else:
        parsed = json.loads(raw_bytes.decode("utf-8", errors="replace"))
        if isinstance(parsed, dict) and isinstance(parsed.get("data"), list):
            items = parsed["data"]
        elif isinstance(parsed, list):
            items = parsed

    tenant_name = "Entra-ID"
    global_admins: List[str] = []
    risky_apps: List[str] = []
    privileged_guests: List[str] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "").lower()
        data = item.get("data") if isinstance(item.get("data"), dict) else item
        if data.get("tenantId") and tenant_name == "Entra-ID":
            tenant_name = str(data["tenantId"])

        if kind in ("azroleassignment", "azglobaladmin") or "global administrator" in str(data.get("roleName") or "").lower():
            rname = str(data.get("roleName") or data.get("displayName") or "").lower()
            if "global administrator" in rname or "62e90394-69f5-4237-9190-012177145e10" in str(data.get("roleDefinitionId") or ""):
                pname = str(data.get("principalDisplayName") or data.get("principalId") or "principal")
                global_admins.append(pname)

        if "approle" in kind or "permission" in kind or data.get("appRoles") or data.get("permissionName"):
            perm = str(data.get("permissionName") or data.get("roleValue") or "").lower()
            if perm in _HIGH_RISK_GRAPH_ROLES:
                app_lbl = str(data.get("principalDisplayName") or data.get("appDisplayName") or data.get("appId") or "ServicePrincipal")
                risky_apps.append(f"{app_lbl} -> {perm}")

        if kind == "azuser" or data.get("userType") == "Guest":
            if str(data.get("userType") or "").lower() == "guest" and data.get("accountEnabled", True) and data.get("isPrivileged"):
                privileged_guests.append(str(data.get("userPrincipalName") or data.get("displayName") or "Guest"))

    findings: List[Dict[str, Any]] = []
    if len(global_admins) > 5:
        findings.append({
            "host": tenant_name,
            "port": 443,
            "protocol": "api",
            "service": "entra-id",
            "title": f"[AzureHound] Numero Eccessivo di Global Administrator ({len(global_admins)})",
            "severity": "high",
            "cvss": 7.8,
            "cve_ids": "",
            "cwe_id": "CWE-269",
            "source_engine": "azurehound",
            "description": "Oltre 5 Global Administrator permanenti aumentano drasticamente la superficie di compromissione tenant Entra ID.",
            "evidence": ", ".join(global_admins[:15]),
            "remediation": "Ridurre i Global Admin permanenti (<= 2-4) e adottare Privileged Identity Management (PIM) Just-In-Time + MFA FIDO2.",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1078.004 - Cloud Accounts",
        })

    if risky_apps:
        findings.append({
            "host": tenant_name,
            "port": 443,
            "protocol": "api",
            "service": "entra-id",
            "title": f"[AzureHound] App / Service Principal con Permessi MS Graph Critici ({len(risky_apps)})",
            "severity": "critical",
            "cvss": 9.1,
            "cve_ids": "",
            "cwe_id": "CWE-269",
            "source_engine": "azurehound",
            "description": "Service Principal con permessi di scrittura ruoli/directory su Microsoft Graph consentono takeover del tenant.",
            "evidence": "\n".join(risky_apps[:15]),
            "remediation": "Rimuovere RoleManagement.ReadWrite.Directory / AppRoleAssignment.ReadWrite.All o proteggere rigorosamente gli Owner dell'app.",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1098.003 - Additional Cloud Roles",
        })

    if privileged_guests:
        findings.append({
            "host": tenant_name,
            "port": 443,
            "protocol": "api",
            "service": "entra-id",
            "title": f"[AzureHound] Account Guest B2B Privilegiati in Entra ID ({len(privileged_guests)})",
            "severity": "high",
            "cvss": 7.5,
            "cve_ids": "",
            "cwe_id": "CWE-284",
            "source_engine": "azurehound",
            "description": "Account esterni Guest con privilegi amministrativi nel tenant.",
            "evidence": ", ".join(privileged_guests[:10]),
            "remediation": "Revocare ruoli privilegiati a utenti esterni B2B o applicare Conditional Access + Access Reviews periodici.",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1078.004 - Cloud Accounts",
        })

    summary = {
        "tenant": tenant_name,
        "global_admins": len(global_admins),
        "risky_graph_apps": len(risky_apps),
        "privileged_guests": len(privileged_guests),
    }
    return summary, findings


# ---------------------------------------------------------------------
# OS Network Interfaces & Standalone Decoupled Responder Session Manager
# ---------------------------------------------------------------------

DEFAULT_RESPONDER_PROTOCOLS: Dict[str, bool] = {
    "llmnr": True,
    "nbns": True,
    "mdns": True,
    "smb": True,
    "http": True,
    "https": True,
    "ldap": True,
    "sql": True,
    "ftp": True,
    "dns": True,
}

DEFAULT_RESPONDER_OPTIONS: Dict[str, bool] = {
    "wpad": False,
    "force_wpad_auth": False,
    "basic_auth": False,
    "dhcp": False,
}

_RESPONDER_LOCK = threading.Lock()
_RESPONDER_STATE: Dict[str, Any] = {
    "running": False,
    "mode": "passive",
    "interface": "all",
    "bind_ip": "0.0.0.0",
    "protocols": dict(DEFAULT_RESPONDER_PROTOCOLS),
    "options": dict(DEFAULT_RESPONDER_OPTIONS),
    "started_at": "",
    "started_ts": 0.0,
    "hosts_seen": [],
    "protocols_seen": [],
    "packets_count": 0,
    "logs": [],
    "error": "",
    "stop_event": None,
    "proc": None,
}


def list_network_interfaces() -> List[Dict[str, str]]:
    """Enumerate available local IPv4 network interfaces for Responder binding."""
    items: List[Dict[str, str]] = [
        {"name": "all", "ip": "0.0.0.0", "label": "All Interfaces (0.0.0.0)"}
    ]
    seen_ips: Set[str] = {"0.0.0.0", "127.0.0.1"}

    try:
        if platform.system() == "Windows":
            proc = subprocess.run(
                ["ipconfig"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=5,
            )
            raw = proc.stdout.decode("utf-8", errors="ignore")
            cur_adapter = "Interface"
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if not line[0].isspace() and stripped.endswith(":"):
                    header = stripped[:-1].strip()
                    header = re.sub(
                        r"^(?:Ethernet adapter|Wireless LAN adapter|Unknown adapter|Tunnel adapter|Scheda LAN wireless|Scheda Ethernet|Scheda Unknown|Scheda tunnel)\s+",
                        "",
                        header,
                        flags=re.IGNORECASE,
                    ).strip()
                    cur_adapter = header or stripped[:-1].strip()
                    continue
                m = re.search(r"(?:IPv4|Indirizzo IPv4)[^:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})", stripped, re.IGNORECASE)
                if m:
                    ip = m.group(1)
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        items.append({"name": cur_adapter, "ip": ip, "label": f"{cur_adapter} ({ip})"})
        else:
            proc = subprocess.run(
                ["ip", "-4", "-o", "addr", "show"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=5,
            )
            raw = proc.stdout.decode("utf-8", errors="ignore")
            for line in raw.splitlines():
                m = re.search(r"^\d+:\s+([^\s:]+)\s+inet\s+(\d{1,3}(?:\.\d{1,3}){3})/", line.strip())
                if m:
                    iface, ip = m.group(1), m.group(2)
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        items.append({"name": iface, "ip": ip, "label": f"{iface} ({ip})"})
    except Exception:
        pass

    return items


def _append_responder_log(level: str, msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    with _RESPONDER_LOCK:
        logs = _RESPONDER_STATE["logs"]
        logs.append({"time": ts, "level": level, "msg": msg})
        if len(logs) > 300:
            del logs[:-300]


def get_responder_session_status() -> Dict[str, Any]:
    """Return a JSON-safe snapshot of the standalone live Responder listener."""
    with _RESPONDER_LOCK:
        running = bool(_RESPONDER_STATE["running"])
        started_ts = float(_RESPONDER_STATE["started_ts"] or 0.0)
        elapsed = int(max(0.0, time.monotonic() - started_ts)) if (running and started_ts > 0.0) else 0
        return {
            "running": running,
            "mode": _RESPONDER_STATE["mode"],
            "interface": _RESPONDER_STATE["interface"],
            "bind_ip": _RESPONDER_STATE["bind_ip"],
            "protocols": dict(_RESPONDER_STATE["protocols"]),
            "options": dict(_RESPONDER_STATE["options"]),
            "started_at": _RESPONDER_STATE["started_at"],
            "elapsed_sec": elapsed,
            "hosts_seen": list(_RESPONDER_STATE["hosts_seen"]),
            "protocols_seen": list(_RESPONDER_STATE["protocols_seen"]),
            "packets_count": int(_RESPONDER_STATE["packets_count"]),
            "logs": list(_RESPONDER_STATE["logs"]),
            "error": _RESPONDER_STATE["error"],
        }


def start_responder_session(
    mode: str = "passive",
    active_authorized: bool = False,
    interface: str = "all",
    bind_ip: str = "0.0.0.0",
    protocols: Optional[Dict[str, bool]] = None,
    options: Optional[Dict[str, bool]] = None,
) -> Dict[str, Any]:
    """Start standalone live Responder / passive UDP broadcast listener independently of scans."""
    m = (mode or "passive").strip().lower()
    if m not in ("passive", "active"):
        raise ValueError("Modalità Responder non valida (usa 'passive' o 'active').")
    if m == "active" and not active_authorized:
        raise ValueError("Responder Active Mode richiede l'esplicita conferma di autorizzazione del cliente.")

    merged_protos = dict(DEFAULT_RESPONDER_PROTOCOLS)
    if isinstance(protocols, dict):
        for k in DEFAULT_RESPONDER_PROTOCOLS:
            if k in protocols:
                merged_protos[k] = bool(protocols[k])

    merged_opts = dict(DEFAULT_RESPONDER_OPTIONS)
    if isinstance(options, dict):
        for k in DEFAULT_RESPONDER_OPTIONS:
            if k in options:
                merged_opts[k] = bool(options[k])

    if m == "passive" and not any(merged_protos.get(k) for k in ("llmnr", "nbns", "mdns")):
        raise ValueError("Abilita almeno un protocollo broadcast (LLMNR, NBT-NS o mDNS).")

    with _RESPONDER_LOCK:
        if _RESPONDER_STATE["running"]:
            return get_responder_session_status()

    iface_clean = (interface or "all").strip()
    bind_clean = (bind_ip or "0.0.0.0").strip()
    try:
        socket.inet_aton(bind_clean)
    except OSError:
        bind_clean = "0.0.0.0"

    resp_bin: Optional[str] = None
    if m == "active":
        resp_bin = shutil.which("responder") or shutil.which("Responder.py")
        if not resp_bin:
            raise RuntimeError("Binario Responder non trovato su questo host (Active Mode richiede Linux/root; usa Passive Mode su Windows).")

    stop_evt = threading.Event()
    now_iso = datetime.now(timezone.utc).isoformat()
    with _RESPONDER_LOCK:
        _RESPONDER_STATE.update({
            "running": True,
            "mode": m,
            "interface": iface_clean,
            "bind_ip": bind_clean,
            "protocols": merged_protos,
            "options": merged_opts,
            "started_at": now_iso,
            "started_ts": time.monotonic(),
            "hosts_seen": [],
            "protocols_seen": [],
            "packets_count": 0,
            "logs": [],
            "error": "",
            "stop_event": stop_evt,
            "proc": None,
        })

    if m == "active" and resp_bin:
        iface_arg = iface_clean if (iface_clean != "all" and _SAFE_ARG_RE.match(iface_clean)) else "eth0"
        cli_cmd = [resp_bin, "-I", iface_arg]
        if merged_opts.get("wpad"):
            cli_cmd.append("-w")
        if merged_opts.get("force_wpad_auth"):
            cli_cmd.append("-F")
        if merged_opts.get("basic_auth"):
            cli_cmd.append("-b")
        if merged_opts.get("dhcp"):
            cli_cmd.append("-d")
        proto_summary = ", ".join(f"{k.upper()}={'On' if v else 'Off'}" for k, v in merged_protos.items())
        _append_responder_log("WARN", f"[AUTHORIZED ACTIVE] Launching {' '.join(cli_cmd)}")
        _append_responder_log("INFO", f"[Responder.conf Targets] {proto_summary}")

        def _active_worker() -> None:
            proc = None
            try:
                proc = subprocess.Popen(
                    cli_cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                with _RESPONDER_LOCK:
                    _RESPONDER_STATE["proc"] = proc
                if proc.stdout:
                    for raw_ln in iter(proc.stdout.readline, ""):
                        if stop_evt.is_set():
                            break
                        ln = raw_ln.rstrip()
                        if ln:
                            _append_responder_log("INFO", ln)
                            ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", ln)
                            if ip_m:
                                with _RESPONDER_LOCK:
                                    if ip_m.group(1) not in _RESPONDER_STATE["hosts_seen"]:
                                        _RESPONDER_STATE["hosts_seen"].append(ip_m.group(1))
                                    _RESPONDER_STATE["packets_count"] += 1
            except Exception as exc:
                with _RESPONDER_LOCK:
                    _RESPONDER_STATE["error"] = str(exc)
                _append_responder_log("ERROR", f"Responder Active error: {exc}")
            finally:
                if proc and proc.poll() is None:
                    try:
                        proc.terminate()
                        proc.wait(timeout=3)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                with _RESPONDER_LOCK:
                    if _RESPONDER_STATE.get("stop_event") is stop_evt:
                        _RESPONDER_STATE["running"] = False
                        _RESPONDER_STATE["proc"] = None

        threading.Thread(target=_active_worker, daemon=True).start()
        return get_responder_session_status()

    passive_specs = [
        spec
        for key, spec in (
            ("llmnr", (5355, "LLMNR", "224.0.0.252")),
            ("nbns", (137, "NBT-NS", "")),
            ("mdns", (5353, "mDNS", "224.0.0.251")),
        )
        if merged_protos.get(key)
    ]
    disabled_protos = [k.upper() for k, v in merged_protos.items() if not v]
    _append_responder_log(
        "INFO",
        f"[PASSIVE LISTENER] Binding {', '.join(f'UDP/{p} ({lbl})' for p, lbl, _ in passive_specs)} on {iface_clean} ({bind_clean}) — zero packets sent..."
        + (f" | Disabled: {', '.join(disabled_protos)}" if disabled_protos else ""),
    )

    def _passive_worker() -> None:
        sock_map: Dict[socket.socket, Tuple[int, str]] = {}
        try:
            for port, proto_lbl, mcast_ip in passive_specs:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((bind_clean, port))
                    if mcast_ip:
                        try:
                            mreq = struct.pack("4s4s", socket.inet_aton(mcast_ip), socket.inet_aton(bind_clean))
                            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                        except OSError:
                            pass
                    sock.setblocking(False)
                    sock_map[sock] = (port, proto_lbl)
                except OSError as exc:
                    _append_responder_log("WARN", f"UDP/{port} ({proto_lbl}) unavailable on {bind_clean}: {exc}")

            if sock_map:
                bound_desc = ", ".join(f"{p}/{lbl}" for p, lbl in sock_map.values())
                _append_responder_log("INFO", f"Listening passively on {bound_desc}. Waiting for LAN broadcast queries...")
            else:
                _append_responder_log("WARN", "No UDP broadcast ports could be bound (check permissions or port conflicts).")

            while not stop_evt.is_set():
                if not sock_map:
                    stop_evt.wait(0.5)
                    continue
                try:
                    readable, _, _ = select.select(list(sock_map.keys()), [], [], 0.5)
                except Exception:
                    stop_evt.wait(0.5)
                    continue
                for s in readable:
                    port, proto_lbl = sock_map[s]
                    try:
                        data, addr = s.recvfrom(4096)
                        src_ip = addr[0]
                        is_new_host = False
                        with _RESPONDER_LOCK:
                            _RESPONDER_STATE["packets_count"] += 1
                            if src_ip not in _RESPONDER_STATE["hosts_seen"]:
                                _RESPONDER_STATE["hosts_seen"].append(src_ip)
                                is_new_host = True
                            if proto_lbl not in _RESPONDER_STATE["protocols_seen"]:
                                _RESPONDER_STATE["protocols_seen"].append(proto_lbl)
                        tag = "WARN" if is_new_host else "INFO"
                        _append_responder_log(tag, f"[{proto_lbl}:{port}] {src_ip}:{addr[1]} -> {len(data)}B broadcast query (passive, 0 spoofing)")
                    except OSError:
                        continue
        finally:
            for s in sock_map:
                try:
                    s.close()
                except Exception:
                    pass
            with _RESPONDER_LOCK:
                if _RESPONDER_STATE.get("stop_event") is stop_evt:
                    _RESPONDER_STATE["running"] = False

    threading.Thread(target=_passive_worker, daemon=True).start()
    return get_responder_session_status()


def stop_responder_session() -> Dict[str, Any]:
    """Stop the standalone live Responder / passive UDP broadcast listener."""
    with _RESPONDER_LOCK:
        stop_evt = _RESPONDER_STATE.get("stop_event")
        proc = _RESPONDER_STATE.get("proc")
        was_running = bool(_RESPONDER_STATE.get("running"))
        if stop_evt is not None:
            stop_evt.set()
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
        _RESPONDER_STATE["running"] = False
    if was_running:
        _append_responder_log("INFO", "Responder listener stopped by user.")
    return get_responder_session_status()


# ---------------------------------------------------------------------
# Live LAN Broadcast / Responder Runner (Passive Default + Auth Active)
# ---------------------------------------------------------------------

async def run_lan_broadcast_audit(
    duration_sec: int = 30,
    mode: str = "passive",
    active_authorized: bool = False,
    interface: str = "",
    log_callback: Optional[Callable[[str, str], Any]] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Audit LLMNR/NBT-NS/mDNS broadcast exposure (passive zero-spoofing by default)."""
    def log(level: str, msg: str) -> None:
        if log_callback:
            try:
                log_callback(level, msg)
            except Exception:
                pass

    dur = max(10, min(int(duration_sec or 30), 120))
    m = (mode or "passive").strip().lower()

    if m == "active":
        if not active_authorized:
            raise ValueError("Responder Active Mode richiede autorizzazione esplicita del cliente.")
        resp_bin = shutil.which("responder") or shutil.which("Responder.py")
        if not resp_bin:
            raise RuntimeError("Responder binario non disponibile per Active Mode (richiesto ambiente Linux/root).")
        log("WARN", f"[Responder] [AUTHORIZED ACTIVE MODE] Avvio Responder su interfaccia '{interface or 'eth0'}' per {dur}s...")
        args = [resp_bin, "-I", interface.strip() if interface and _SAFE_ARG_RE.match(interface.strip()) else "eth0", "-wF"]
        proc = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=float(dur))
        except asyncio.TimeoutError:
            proc.terminate()
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            except Exception:
                proc.kill()
                stdout, _ = await proc.communicate()
        raw = stdout.decode("utf-8", errors="replace")
        ips = sorted(set(re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", raw)))
        findings = []
        if ips:
            findings.append({
                "host": ips[0],
                "port": 5355,
                "protocol": "udp",
                "service": "llmnr/nbns",
                "title": f"[Responder Active] Host vulnerabili a Poisoning LLMNR/NBT-NS ({len(ips)} IP)",
                "severity": "high",
                "cvss": 8.0,
                "cve_ids": "",
                "cwe_id": "CWE-290",
                "source_engine": "responder",
                "description": "Durante il test attivo autorizzato Responder ha intercettato query di broadcast LLMNR/NBT-NS vulnerabili.",
                "evidence": f"Host osservati: {', '.join(ips[:15])}",
                "remediation": "Disabilitare LLMNR (GPO Turn off multicast name resolution) e NetBIOS over TCP/IP.",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1557.001 - LLMNR/NBT-NS Poisoning",
            })
        return {"mode": "active", "duration": dur, "hosts_seen": ips}, findings

    # Passive Mode (zero packets transmitted; cross-platform UDP listener)
    log("INFO", f"[LAN Sniffer] Avvio ascolto passivo UDP (LLMNR:5355, NBT-NS:137, mDNS:5353) per {dur}s (zero spoofing)...")
    observed: Dict[str, Set[str]] = {}
    transports: List[asyncio.DatagramTransport] = []
    loop = asyncio.get_running_loop()

    class _PassiveProto(asyncio.DatagramProtocol):
        def __init__(self, proto_label: str) -> None:
            self.proto_label = proto_label

        def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
            src_ip = addr[0]
            observed.setdefault(src_ip, set()).add(self.proto_label)

    for port, lbl in ((5355, "LLMNR"), (137, "NBT-NS"), (5353, "mDNS")):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            tr, _ = await loop.create_datagram_endpoint(lambda l=lbl: _PassiveProto(l), sock=sock)
            transports.append(tr)
        except Exception:
            continue

    try:
        await asyncio.sleep(float(dur))
    finally:
        for tr in transports:
            try:
                tr.close()
            except Exception:
                pass

    findings: List[Dict[str, Any]] = []
    for ip, protos in sorted(observed.items()):
        findings.append({
            "host": ip,
            "port": 5355 if "LLMNR" in protos else (137 if "NBT-NS" in protos else 5353),
            "protocol": "udp",
            "service": "/".join(sorted(protos)),
            "title": f"[Responder Passive] Traffico {', '.join(sorted(protos))} Rilevato su {ip}",
            "severity": "high" if ("LLMNR" in protos or "NBT-NS" in protos) else "medium",
            "cvss": 7.5 if ("LLMNR" in protos or "NBT-NS" in protos) else 5.0,
            "cve_ids": "",
            "cwe_id": "CWE-290",
            "source_engine": "responder",
            "description": f"L'host {ip} trasmette query broadcast {'/'.join(sorted(protos))} intercettabili in LAN (test passivo a zero pacchetti).",
            "evidence": f"Protocolli rilevati in ascolto passivo ({dur}s): {', '.join(sorted(protos))}",
            "remediation": "Disabilitare LLMNR via GPO ('Turn off multicast name resolution') e NetBIOS over TCP/IP sulle interfacce LAN.",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1557.001 - LLMNR/NBT-NS Poisoning",
        })

    log("INFO", f"[LAN Sniffer] Ascolto passivo completato: {len(observed)} host rilevati.")
    return {"mode": "passive", "duration": dur, "hosts_seen": sorted(observed.keys())}, findings


# ---------------------------------------------------------------------
# Background Orchestrator for Live Internal & AD Scans
# ---------------------------------------------------------------------

def start_internal_ad_scan_in_background(scan_id: int, payload: Dict[str, Any]) -> None:
    def _worker() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run_internal_ad_pipeline(scan_id, payload))
        finally:
            try:
                loop.close()
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True).start()


async def execute_internal_ad_modules(
    scan_id: int,
    targets: str,
    payload: Dict[str, Any],
    append_log: Callable[[str, str], Any],
    update_progress: Callable[[int, str], Any],
    base_progress: int = 20,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Execute enabled Internal/AD modules (NetExec, Enum4linux-ng, BloodHound, AzureHound, optional Responder)."""
    targets = str(targets or payload.get("targets") or "").strip()
    domain = str(payload.get("domain") or "").strip()
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    tools = detect_internal_tools()
    all_findings: List[Dict[str, Any]] = []
    internal_summary: Dict[str, Any] = {"targets": targets, "domain": domain}

    # NetExec
    if payload.get("enable_netexec"):
        update_progress(min(89, base_progress), "Esecuzione NetExec (audit protocolli interni)...")
        if not tools["netexec"]["installed"]:
            append_log("WARN", "[NetExec] Binario non installato: installalo dal pannello Internal & AD.")
        else:
            protos = [p for p in (payload.get("netexec_protocols") or ["smb"]) if p in NETEXEC_PROTOCOLS]
            checks = set(payload.get("netexec_checks") or [])
            for proto in protos:
                args = [tools["netexec"]["path"], proto, targets]
                if username and password:
                    args.extend(["-u", username, "-p", password])
                    if domain:
                        args.extend(["-d", domain])
                else:
                    args.extend(["-u", "", "-p", ""])
                if proto == "smb":
                    if "null_shares" in checks:
                        args.append("--shares")
                    if "pass_pol" in checks and username:
                        args.append("--pass-pol")
                if proto == "ldap" and username:
                    if "kerberoast" in checks:
                        args.extend(["--kerberoasting", "-"])
                    if "asrep" in checks:
                        args.extend(["--asreproast", "-"])
                proc = await asyncio.create_subprocess_exec(
                    *args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=240.0)
                parsed_nxc = parse_netexec_output(stdout.decode("utf-8", errors="replace"), targets, proto)
                all_findings.extend(parsed_nxc)
                append_log("INFO", f"[NetExec/{proto.upper()}] Generati {len(parsed_nxc)} finding.")

    # Enum4linux-ng
    if payload.get("enable_enum4linux"):
        update_progress(min(89, base_progress + 2), "Esecuzione Enum4linux-ng...")
        if not tools["enum4linux_ng"]["installed"] or platform.system() == "Windows":
            append_log("WARN", "[Enum4linux-ng] Esecuzione diretta disponibile su Linux con samba/rpcclient installati.")
        else:
            with tempfile.TemporaryDirectory() as tmp:
                out_prefix = str(Path(tmp) / "e4l")
                e4l_args = [sys.executable, tools["enum4linux_ng"]["path"], "-A", "-oJ", out_prefix, targets.split(",")[0].strip()]
                if username and password:
                    e4l_args.extend(["-u", username, "-p", password])
                proc = await asyncio.create_subprocess_exec(
                    *e4l_args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(proc.communicate(), timeout=240.0)
                jfile = Path(f"{out_prefix}.json")
                if jfile.is_file():
                    e_sum, e_findings = parse_enum4linux_ng_json(jfile.read_text(encoding="utf-8", errors="replace"), targets)
                    internal_summary["enum4linux"] = e_sum
                    all_findings.extend(e_findings)

    # BloodHound AD Collector
    if payload.get("enable_bloodhound"):
        update_progress(min(89, base_progress + 4), "Raccolta grafo Active Directory (BloodHound)...")
        if not tools["bloodhound"]["installed"]:
            append_log("WARN", "[BloodHound] bloodhound-python non installato.")
        elif not (domain and username and password):
            append_log("WARN", "[BloodHound] Richiesti Domain, Username e Password AD per raccolta live.")
        else:
            with tempfile.TemporaryDirectory() as tmp:
                dc_ip = targets.split(",")[0].strip()
                bh_args = [tools["bloodhound"]["path"], "-d", domain, "-u", username, "-p", password, "-c", "Default", "--zip"]
                if dc_ip and _SAFE_ARG_RE.match(dc_ip):
                    bh_args.extend(["-ns", dc_ip])
                proc = await asyncio.create_subprocess_exec(
                    *bh_args, cwd=tmp, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(proc.communicate(), timeout=300.0)
                zips = list(Path(tmp).glob("*.zip"))
                if zips:
                    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
                    dest_zip = EXPORTS_DIR / f"scan_{scan_id}.zip"
                    shutil.copy2(zips[0], dest_zip)
                    ad_sum, bh_findings = analyze_bloodhound_archive(dest_zip.read_bytes(), dest_zip.name)
                    internal_summary["bloodhound"] = ad_sum
                    internal_summary["export_available"] = True
                    all_findings.extend(bh_findings)

    # AzureHound Entra ID Collector
    if payload.get("enable_azurehound"):
        update_progress(min(89, base_progress + 6), "Raccolta identità Entra ID (AzureHound)...")
        az_t = str(payload.get("azure_tenant_id") or "").strip()
        az_c = str(payload.get("azure_client_id") or "").strip()
        az_s = str(payload.get("azure_client_secret") or "").strip()
        if not tools["azurehound"]["installed"]:
            append_log("WARN", "[AzureHound] Binario azurehound non installato.")
        elif not (az_t and az_c and az_s):
            append_log("WARN", "[AzureHound] Richiesti Tenant ID, Client ID e Client Secret per raccolta live.")
        else:
            with tempfile.TemporaryDirectory() as tmp:
                out_json = Path(tmp) / "azurehound.json"
                ah_args = [
                    tools["azurehound"]["path"], "list",
                    "--tenant", az_t, "--app", az_c, "--secret", az_s,
                    "-o", str(out_json),
                ]
                proc = await asyncio.create_subprocess_exec(
                    *ah_args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(proc.communicate(), timeout=300.0)
                if out_json.is_file():
                    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
                    dest_zip = EXPORTS_DIR / f"scan_{scan_id}.zip"
                    with zipfile.ZipFile(dest_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        zf.write(out_json, arcname="azurehound.json")
                    entra_sum, ah_findings = analyze_azurehound_json(out_json.read_bytes(), "azurehound.json")
                    internal_summary["azurehound"] = entra_sum
                    internal_summary["export_available"] = True
                    all_findings.extend(ah_findings)

    # Optional Responder / Passive LAN Sniffer
    if payload.get("enable_responder"):
        update_progress(min(89, base_progress + 7), "Audit broadcast LAN (LLMNR / NBT-NS / mDNS)...")
        lan_sum, lan_findings = await run_lan_broadcast_audit(
            duration_sec=int(payload.get("responder_duration_sec") or 30),
            mode=str(payload.get("responder_mode") or "passive"),
            active_authorized=bool(payload.get("responder_active_authorized")),
            interface=str(payload.get("responder_interface") or ""),
            log_callback=append_log,
        )
        internal_summary["lan_broadcast"] = lan_sum
        all_findings.extend(lan_findings)

    return internal_summary, all_findings


async def _run_internal_ad_pipeline(scan_id: int, payload: Dict[str, Any]) -> None:
    conn = get_db_connection()
    logs: List[Dict[str, str]] = []

    def append_log(level: str, msg: str) -> None:
        logs.append({"ts": datetime.now(timezone.utc).strftime("%H:%M:%S"), "level": level, "msg": msg})
        try:
            with conn:
                conn.execute("UPDATE scans SET logs_json = ? WHERE id = ?;", (json.dumps(logs[-250:]), scan_id))
        except Exception:
            pass

    def update_progress(pct: int, task: str) -> None:
        try:
            with conn:
                conn.execute("UPDATE scans SET progress = ?, current_task = ?, status = 'running' WHERE id = ?;", (pct, task, scan_id))
        except Exception:
            pass

    try:
        scan = get_scan_by_id(scan_id)
        if not scan:
            return

        targets = str(payload.get("targets") or "").strip()
        internal_summary, all_findings = await execute_internal_ad_modules(
            scan_id=scan_id,
            targets=targets,
            payload=payload,
            append_log=append_log,
            update_progress=update_progress,
            base_progress=20,
        )

        # Persist Findings & Summary
        update_progress(92, "Consolidamento risultati Internal & AD Security...")
        now_iso = datetime.now(timezone.utc).isoformat()
        with conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?;", (scan_id,))
            for f in all_findings:
                conn.execute(
                    """
                    INSERT INTO findings (
                        scan_id, org_id, host, port, protocol, service,
                        title, severity, cvss, cve_ids, cwe_id, source_engine,
                        description, evidence, remediation, mitre_tactic, mitre_technique,
                        ai_insight, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, '', 'open', ?);
                    """,
                    (
                        scan_id, scan["org_id"], f.get("host", ""), int(f.get("port") or 0),
                        f.get("protocol", "tcp"), f.get("service", ""), f.get("title", ""),
                        f.get("severity", "info"), float(f.get("cvss") or 0.0), f.get("cwe_id", ""),
                        f.get("source_engine", "netexec"), f.get("description", ""),
                        f.get("evidence", ""), f.get("remediation", ""),
                        f.get("mitre_tactic", "Discovery"), f.get("mitre_technique", ""), now_iso,
                    ),
                )

        crit = sum(1 for f in all_findings if f["severity"] == "critical")
        high = sum(1 for f in all_findings if f["severity"] == "high")
        med = sum(1 for f in all_findings if f["severity"] == "medium")
        low = sum(1 for f in all_findings if f["severity"] == "low")
        info = sum(1 for f in all_findings if f["severity"] == "info")
        risk_score = min(100, int((crit * 25) + (high * 15) + (med * 5) + (low * 2)))
        risk_label = "CRITICO" if risk_score >= 75 else ("ALTO" if risk_score >= 50 else ("MEDIO" if risk_score >= 25 else "BASSO"))

        summary = {
            "total_hosts": 1,
            "up_hosts": 1,
            "total_ports": 0,
            "total_findings": len(all_findings),
            "critical": crit, "high": high, "medium": med, "low": low, "info": info,
            "risk_score": risk_score, "risk_label": risk_label,
            "engines_used": ["internal_ad"],
            "internal_ad": internal_summary,
        }
        ai_res = await analyze_findings(scan=scan, findings=all_findings, settings=get_settings(), org=get_organization_by_id(scan["org_id"]) or {}, mode="purple")
        with conn:
            conn.execute(
                """
                UPDATE scans SET status='completed', progress=100, current_task='Audit Internal & AD completato',
                    completed_at=?, summary_json=?, ai_analysis_json=? WHERE id=?;
                """,
                (now_iso, json.dumps(summary), json.dumps(ai_res), scan_id),
            )
    except Exception as exc:
        append_log("ERROR", f"[Internal & AD] Audit fallito: {exc}")
        with conn:
            conn.execute(
                "UPDATE scans SET status='failed', current_task=?, completed_at=? WHERE id=?;",
                (f"Errore: {str(exc)[:180]}", datetime.now(timezone.utc).isoformat(), scan_id),
            )
    finally:
        conn.close()
