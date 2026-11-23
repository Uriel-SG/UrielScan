import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.ai_engine import analyze_findings
from backend.database import DATA_DIR, get_db_connection, get_organization_by_id, get_scan_by_id, get_settings

BASE_DIR = Path(__file__).resolve().parent.parent.parent
BIN_DIR = BASE_DIR / "bin"
PROWLER_VENV_DIR = BIN_DIR / "prowler_venv"
CLOUD_KEY_PATH = DATA_DIR / ".cloud_key"

COMPLIANCE_FRAMEWORKS: List[Dict[str, str]] = [
    {"id": "", "label": "All Default Checks (Full Audit)"},
    {"id": "cis_3.0_aws", "label": "CIS AWS Foundations Benchmark v3.0"},
    {"id": "cis_2.1_azure", "label": "CIS Microsoft Azure Foundations v2.1"},
    {"id": "cis_2.0_gcp", "label": "CIS Google Cloud Platform v2.0"},
    {"id": "iso27001_2022", "label": "ISO/IEC 27001:2022"},
    {"id": "nis2", "label": "NIS2 Directive Controls"},
    {"id": "gdpr", "label": "GDPR Data Protection"},
    {"id": "soc2", "label": "SOC 2 Type II"},
    {"id": "pci_4.0", "label": "PCI-DSS v4.0"},
    {"id": "nist_800_53", "label": "NIST SP 800-53"},
]

CLOUD_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "aws": {
        "id": "aws",
        "label": "Amazon Web Services (AWS)",
        "short": "AWS",
        "default_region": "eu-west-1",
        "default_services": ["iam", "s3", "ec2", "vpc", "rds", "cloudtrail", "kms"],
        "compliances": ["", "cis_3.0_aws", "iso27001_2022", "nis2", "gdpr", "soc2", "pci_4.0", "nist_800_53"],
        "fields": [
            {"key": "aws_access_key_id", "label": "AWS Access Key ID", "secret": False, "placeholder": "AKIA..."},
            {"key": "aws_secret_access_key", "label": "AWS Secret Access Key", "secret": True, "placeholder": "********"},
            {"key": "aws_session_token", "label": "Session Token (optional STS)", "secret": True, "placeholder": "FwoG..."},
            {"key": "aws_role_arn", "label": "Assume Role ARN (optional)", "secret": False, "placeholder": "arn:aws:iam::123456789012:role/ProwlerAudit"},
        ],
    },
    "azure": {
        "id": "azure",
        "label": "Microsoft Azure",
        "short": "Azure",
        "default_region": "",
        "default_services": ["iam", "entra", "storage", "network", "keyvault", "defender"],
        "compliances": ["", "cis_2.1_azure", "iso27001_2022", "nis2", "gdpr", "soc2", "pci_4.0", "nist_800_53"],
        "fields": [
            {"key": "azure_tenant_id", "label": "Tenant ID", "secret": False, "placeholder": "00000000-0000-0000-0000-000000000000"},
            {"key": "azure_client_id", "label": "Client ID (App Registration)", "secret": False, "placeholder": "00000000-0000-0000-0000-000000000000"},
            {"key": "azure_client_secret", "label": "Client Secret", "secret": True, "placeholder": "********"},
            {"key": "azure_subscription_id", "label": "Subscription ID (optional)", "secret": False, "placeholder": "sub-uuid"},
        ],
    },
    "gcp": {
        "id": "gcp",
        "label": "Google Cloud Platform (GCP)",
        "short": "GCP",
        "default_region": "",
        "default_services": ["iam", "compute", "storage", "cloudsql", "kms", "logging"],
        "compliances": ["", "cis_2.0_gcp", "iso27001_2022", "nis2", "gdpr", "soc2", "pci_4.0", "nist_800_53"],
        "fields": [
            {"key": "gcp_project_id", "label": "Project ID (optional)", "secret": False, "placeholder": "my-gcp-project"},
            {"key": "gcp_service_account_json", "label": "Service Account JSON", "secret": True, "placeholder": "{\"type\": \"service_account\", ...}", "multiline": True},
        ],
    },
    "m365": {
        "id": "m365",
        "label": "Microsoft 365 (M365)",
        "short": "M365",
        "default_region": "",
        "default_services": ["entra", "defender", "exchange", "sharepoint", "teams"],
        "compliances": ["", "iso27001_2022", "nis2", "gdpr", "soc2"],
        "fields": [
            {"key": "azure_tenant_id", "label": "Tenant ID", "secret": False, "placeholder": "tenant-uuid"},
            {"key": "azure_client_id", "label": "Client ID", "secret": False, "placeholder": "app-uuid"},
            {"key": "azure_client_secret", "label": "Client Secret", "secret": True, "placeholder": "********"},
        ],
    },
    "kubernetes": {
        "id": "kubernetes",
        "label": "Kubernetes Cluster",
        "short": "Kubernetes",
        "default_region": "",
        "default_services": ["apiserver", "etcd", "rbac", "core", "networking"],
        "compliances": ["", "iso27001_2022", "nis2", "pci_4.0", "nist_800_53"],
        "fields": [
            {"key": "kubeconfig_yaml", "label": "Kubeconfig YAML Content", "secret": True, "placeholder": "apiVersion: v1\nclusters: ...", "multiline": True},
            {"key": "kube_context", "label": "Context Name (optional)", "secret": False, "placeholder": "prod-cluster"},
        ],
    },
    "github": {
        "id": "github",
        "label": "GitHub Organizations & Repos",
        "short": "GitHub",
        "default_region": "",
        "default_services": ["organization", "repository"],
        "compliances": ["", "iso27001_2022", "soc2"],
        "fields": [
            {"key": "github_token", "label": "Personal Access Token (PAT)", "secret": True, "placeholder": "ghp_... / github_pat_..."},
            {"key": "github_org", "label": "Organization / Owner (optional)", "secret": False, "placeholder": "acme-corp"},
        ],
    },
}

_SEV_CVSS = {
    "critical": 9.5,
    "high": 7.8,
    "medium": 5.3,
    "low": 3.1,
    "info": 0.0,
}

_SAFE_TOKEN_RE = re.compile(r"^[a-zA-Z0-9._:/-]+$")


# ---------------------------------------------------------------------
# Stdlib Authenticated Encryption for Cloud Profile Secrets
# ---------------------------------------------------------------------

def _get_or_create_cloud_key() -> bytes:
    CLOUD_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if CLOUD_KEY_PATH.is_file():
        raw = CLOUD_KEY_PATH.read_bytes()
        if len(raw) == 32:
            return raw
    key = secrets.token_bytes(32)
    CLOUD_KEY_PATH.write_bytes(key)
    try:
        os.chmod(CLOUD_KEY_PATH, 0o600)
    except Exception:
        pass
    return key


def _derive_keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(enc_key + nonce + counter.to_bytes(4, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt_cloud_credentials(creds: Dict[str, Any]) -> str:
    """Encrypt credentials dict with per-message random nonce + SHA-256 CTR + HMAC-SHA256."""
    master = _get_or_create_cloud_key()
    enc_key = hmac.new(master, b"urielscan-cloud-enc-v1", hashlib.sha256).digest()
    mac_key = hmac.new(master, b"urielscan-cloud-mac-v1", hashlib.sha256).digest()

    plaintext = json.dumps(creds or {}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    nonce = secrets.token_bytes(16)
    stream = _derive_keystream(enc_key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    blob = base64.urlsafe_b64encode(nonce + tag + ciphertext).decode("ascii")
    return f"v1:{blob}"


def decrypt_cloud_credentials(token: str) -> Dict[str, Any]:
    """Verify HMAC and decrypt encrypted cloud credentials token."""
    if not token or not str(token).startswith("v1:"):
        return {}
    try:
        raw = base64.urlsafe_b64decode(str(token)[3:].encode("ascii"))
        if len(raw) < 48:
            return {}
        nonce, tag, ciphertext = raw[:16], raw[16:48], raw[48:]
        master = _get_or_create_cloud_key()
        enc_key = hmac.new(master, b"urielscan-cloud-enc-v1", hashlib.sha256).digest()
        mac_key = hmac.new(master, b"urielscan-cloud-mac-v1", hashlib.sha256).digest()
        expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            return {}
        stream = _derive_keystream(enc_key, nonce, len(ciphertext))
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, stream))
        obj = json.loads(plaintext.decode("utf-8"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def mask_cloud_credentials(creds: Dict[str, Any]) -> Dict[str, str]:
    """Return masked previews for API responses; never expose raw secrets."""
    masked: Dict[str, str] = {}
    for k, v in (creds or {}).items():
        val = str(v or "").strip()
        if not val:
            continue
        low_k = k.lower()
        is_secret = any(s in low_k for s in ("secret", "token", "password", "json", "yaml", "key"))
        if not is_secret:
            masked[k] = val
        elif len(val) > 24 or "\n" in val:
            masked[k] = "***configured***"
        elif len(val) > 8:
            masked[k] = f"{val[:4]}****{val[-4:]}"
        else:
            masked[k] = "********"
    return masked


# ---------------------------------------------------------------------
# Detection & Isolated Venv Auto-Installer
# ---------------------------------------------------------------------

def _prowler_venv_bin() -> Optional[Path]:
    candidates = [
        PROWLER_VENV_DIR / "Scripts" / "prowler.exe",
        PROWLER_VENV_DIR / "Scripts" / "prowler",
        PROWLER_VENV_DIR / "bin" / "prowler",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def detect_prowler() -> Dict[str, Any]:
    vbin = _prowler_venv_bin()
    sys_bin = shutil.which("prowler")
    docker_bin = shutil.which("docker")

    mode = "missing"
    bin_path = ""
    if vbin:
        mode = "venv"
        bin_path = str(vbin)
    elif sys_bin:
        mode = "system"
        bin_path = str(sys_bin)
    elif docker_bin:
        mode = "docker"
        bin_path = str(docker_bin)

    installed = mode in ("venv", "system")
    version = ""
    if installed and bin_path:
        try:
            proc = subprocess.run([bin_path, "--version"], capture_output=True, text=True, timeout=8)
            out = (proc.stdout or proc.stderr or "").strip()
            if out:
                version = out.splitlines()[0][:60]
        except Exception:
            version = "Prowler CLI"

    return {
        "installed": installed,
        "mode": mode,
        "path": bin_path,
        "version": version or ("Docker fallback ready" if mode == "docker" else "Not installed"),
    }


async def install_prowler() -> Dict[str, Any]:
    """Install Prowler into isolated bin/prowler_venv without touching core dependencies."""
    det = detect_prowler()
    if det["mode"] in ("venv", "system"):
        return {"success": True, "already_installed": True, **det, "message": f"Prowler già disponibile ({det['path']})."}

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    py_venv = PROWLER_VENV_DIR / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")

    try:
        if not py_venv.is_file():
            p1 = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "venv", str(PROWLER_VENV_DIR),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, err1 = await asyncio.wait_for(p1.communicate(), timeout=120.0)
            if p1.returncode != 0 or not py_venv.is_file():
                msg = err1.decode("utf-8", errors="replace").strip()[:300]
                return {"success": False, "installed": False, "message": f"Errore creazione venv Prowler: {msg}"}

        p2 = await asyncio.create_subprocess_exec(
            str(py_venv), "-m", "pip", "install", "--upgrade", "pip", "prowler",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out2, err2 = await asyncio.wait_for(p2.communicate(), timeout=600.0)
        if p2.returncode != 0:
            msg = (err2 or out2).decode("utf-8", errors="replace").strip()[-350:]
            return {"success": False, "installed": False, "message": f"Installazione Prowler fallita: {msg}"}

        det_after = detect_prowler()
        return {
            "success": det_after["installed"],
            "message": "Prowler installato in ambiente isolato." if det_after["installed"] else "Binario Prowler non trovato dopo installazione.",
            **det_after,
        }
    except asyncio.TimeoutError:
        return {"success": False, "installed": False, "message": "Timeout durante l'installazione di Prowler."}
    except Exception as exc:
        return {"success": False, "installed": False, "message": f"Errore installazione Prowler: {exc}"}


# ---------------------------------------------------------------------
# OCSF JSON Parser
# ---------------------------------------------------------------------

def _norm_sev(raw: Any) -> str:
    s = str(raw or "info").strip().lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    return "info"


def parse_prowler_ocsf_json(
    raw_text: str,
    provider: str,
    compliance: str = "",
    services: Optional[List[str]] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Parse Prowler OCSF JSON (array or JSONL) into posture metrics and UrielScan findings."""
    records: List[Dict[str, Any]] = []
    txt = (raw_text or "").strip()
    if txt:
        try:
            parsed = json.loads(txt)
            if isinstance(parsed, list):
                records = [r for r in parsed if isinstance(r, dict)]
            elif isinstance(parsed, dict):
                records = [parsed]
        except Exception:
            for ln in txt.splitlines():
                s = ln.strip().rstrip(",")
                if not s or not s.startswith("{"):
                    continue
                try:
                    obj = json.loads(s)
                    if isinstance(obj, dict):
                        records.append(obj)
                except Exception:
                    continue

    passed = 0
    failed = 0
    manual = 0
    account_id = ""
    by_service: Dict[str, Dict[str, int]] = {}
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings: List[Dict[str, Any]] = []

    prov_upper = (provider or "cloud").upper()

    for rec in records:
        status = str(rec.get("status_code") or rec.get("status") or "").strip().upper()
        sev = _norm_sev(rec.get("severity"))
        finfo = rec.get("finding_info") or {}
        if not isinstance(finfo, dict):
            finfo = {}
        resources = rec.get("resources") or []
        res0 = resources[0] if isinstance(resources, list) and resources and isinstance(resources[0], dict) else {}
        grp = res0.get("group") or {}
        service_name = str(
            (grp.get("name") if isinstance(grp, dict) else "")
            or rec.get("service_name")
            or "cloud"
        ).strip().lower()
        res_uid = str(res0.get("uid") or res0.get("name") or "").strip()
        res_region = str(res0.get("region") or "").strip()

        cloud_obj = rec.get("cloud") or {}
        acct_obj = cloud_obj.get("account") if isinstance(cloud_obj, dict) else {}
        acct = str((acct_obj.get("uid") if isinstance(acct_obj, dict) else "") or "").strip()
        if acct and not account_id:
            account_id = acct

        svc_stats = by_service.setdefault(service_name, {"passed": 0, "failed": 0, "manual": 0})
        if status == "PASS":
            passed += 1
            svc_stats["passed"] += 1
            continue
        elif status == "MANUAL":
            manual += 1
            svc_stats["manual"] += 1
            continue
        elif status != "FAIL":
            continue

        failed += 1
        svc_stats["failed"] += 1
        by_severity[sev] = by_severity.get(sev, 0) + 1

        check_title = str(finfo.get("title") or rec.get("message") or "Cloud Security Misconfiguration").strip()
        check_desc = str(finfo.get("desc") or rec.get("status_detail") or check_title).strip()
        check_uid = str(finfo.get("uid") or "").strip()

        rem_obj = rec.get("remediation") or {}
        rem_desc = str((rem_obj.get("desc") if isinstance(rem_obj, dict) else "") or "").strip()
        rem_refs = rem_obj.get("references") if isinstance(rem_obj, dict) else []
        if isinstance(rem_refs, list) and rem_refs:
            rem_desc = f"{rem_desc}\nReferences: {', '.join(str(x) for x in rem_refs[:3])}".strip()

        ev_parts = [f"Provider: {prov_upper}", f"Service: {service_name}"]
        if acct:
            ev_parts.append(f"Account: {acct}")
        if res_region:
            ev_parts.append(f"Region: {res_region}")
        if res_uid:
            ev_parts.append(f"Resource: {res_uid}")
        if rec.get("status_detail"):
            ev_parts.append(f"Detail: {rec['status_detail']}")
        if check_uid:
            ev_parts.append(f"Check UID: {check_uid}")

        findings.append({
            "host": acct or res_uid or f"{provider}-cloud",
            "port": 0,
            "protocol": "api",
            "service": service_name,
            "title": f"[Prowler/{prov_upper}] {check_title}",
            "severity": sev,
            "cvss": _SEV_CVSS.get(sev, 5.0),
            "cve_ids": "",
            "cwe_id": "",
            "source_engine": "prowler",
            "description": check_desc[:1000],
            "evidence": "\n".join(ev_parts),
            "remediation": rem_desc or f"Apply security hardening best practices on {prov_upper} {service_name}.",
            "mitre_tactic": "Cloud Posture",
            "mitre_technique": f"CSPM / {compliance or 'Prowler Default'}",
        })

    total_checks = passed + failed + manual
    denom = passed + failed
    pass_rate = round((passed / denom) * 100.0, 1) if denom > 0 else 100.0

    cloud_posture_summary: Dict[str, Any] = {
        "provider": provider,
        "account": account_id or "-",
        "compliance": compliance or "Default Checks",
        "services": services or sorted(by_service.keys()),
        "passed": passed,
        "failed": failed,
        "manual": manual,
        "total_checks": total_checks,
        "pass_rate": pass_rate,
        "by_service": by_service,
        "by_severity": by_severity,
    }
    return cloud_posture_summary, findings


# ---------------------------------------------------------------------
# Async Execution & Background Scan Runner
# ---------------------------------------------------------------------

async def run_prowler_scan(
    provider: str,
    credentials: Dict[str, Any],
    region: str = "",
    compliance: str = "",
    services: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str, str], Any]] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Execute Prowler CLI asynchronously using ephemeral credentials and parse OCSF output."""
    def log(level: str, msg: str) -> None:
        if log_callback:
            try:
                log_callback(level, msg)
            except Exception:
                pass

    prov = (provider or "aws").strip().lower()
    if prov not in CLOUD_PROVIDERS:
        raise ValueError(f"Unsupported cloud provider: {provider}")

    det = detect_prowler()
    if not det["installed"]:
        raise RuntimeError(
            "Prowler CLI non installato. Usa 'Installa Prowler' nella vista Cloud Security prima di avviare l'audit."
        )

    env = os.environ.copy()
    temp_files: List[Path] = []
    out_dir = Path(tempfile.mkdtemp(prefix="uriel_prowler_"))

    try:
        creds = credentials or {}
        if prov == "aws":
            if creds.get("aws_access_key_id"):
                env["AWS_ACCESS_KEY_ID"] = str(creds["aws_access_key_id"]).strip()
            if creds.get("aws_secret_access_key"):
                env["AWS_SECRET_ACCESS_KEY"] = str(creds["aws_secret_access_key"]).strip()
            if creds.get("aws_session_token"):
                env["AWS_SESSION_TOKEN"] = str(creds["aws_session_token"]).strip()
            if region:
                env["AWS_DEFAULT_REGION"] = region.strip()
        elif prov in ("azure", "m365"):
            for src_k, env_k in (
                ("azure_tenant_id", "AZURE_TENANT_ID"),
                ("azure_client_id", "AZURE_CLIENT_ID"),
                ("azure_client_secret", "AZURE_CLIENT_SECRET"),
                ("azure_subscription_id", "AZURE_SUBSCRIPTION_ID"),
            ):
                if creds.get(src_k):
                    env[env_k] = str(creds[src_k]).strip()
        elif prov == "gcp":
            sa_json = str(creds.get("gcp_service_account_json") or "").strip()
            if sa_json:
                tf = out_dir / "gcp_sa.json"
                tf.write_text(sa_json, encoding="utf-8")
                temp_files.append(tf)
                env["GOOGLE_APPLICATION_CREDENTIALS"] = str(tf)
        elif prov == "kubernetes":
            kcfg = str(creds.get("kubeconfig_yaml") or "").strip()
            if kcfg:
                kf = out_dir / "kubeconfig.yaml"
                kf.write_text(kcfg, encoding="utf-8")
                temp_files.append(kf)
                env["KUBECONFIG"] = str(kf)
        elif prov == "github":
            if creds.get("github_token"):
                env["GITHUB_PERSONAL_ACCESS_TOKEN"] = str(creds["github_token"]).strip()

        args = [
            det["path"],
            prov,
            "--output-formats", "json-ocsf",
            "--output-directory", str(out_dir),
            "--no-banner",
        ]

        if prov == "aws" and region and _SAFE_TOKEN_RE.match(region.strip()):
            args.extend(["--region", region.strip()])
        if prov == "aws" and creds.get("aws_role_arn") and _SAFE_TOKEN_RE.match(str(creds["aws_role_arn"]).strip()):
            args.extend(["--role", str(creds["aws_role_arn"]).strip()])
        if prov in ("azure", "m365"):
            args.append("--sp-env-auth")
        if prov == "gcp" and creds.get("gcp_project_id") and _SAFE_TOKEN_RE.match(str(creds["gcp_project_id"]).strip()):
            args.extend(["--project-ids", str(creds["gcp_project_id"]).strip()])
        if prov == "kubernetes" and creds.get("kube_context") and _SAFE_TOKEN_RE.match(str(creds["kube_context"]).strip()):
            args.extend(["--context", str(creds["kube_context"]).strip()])
        if prov == "github" and creds.get("github_org") and _SAFE_TOKEN_RE.match(str(creds["github_org"]).strip()):
            args.extend(["--organizations", str(creds["github_org"]).strip()])

        clean_sevs = [s.strip().lower() for s in (severities or []) if s.strip().lower() in {"critical", "high", "medium", "low", "informational", "info"}]
        if clean_sevs:
            args.extend(["--severity", *[("informational" if s == "info" else s) for s in clean_sevs]])

        if compliance and _SAFE_TOKEN_RE.match(compliance.strip()):
            args.extend(["--compliance", compliance.strip()])

        clean_svcs = [s.strip().lower() for s in (services or []) if s.strip() and _SAFE_TOKEN_RE.match(s.strip())]
        if clean_svcs:
            args.extend(["--service", *clean_svcs])

        log("INFO", f"[Prowler] Avvio audit Cloud Security su provider={prov.upper()}...")
        proc = await asyncio.create_subprocess_exec(
            *args,
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=900.0)
        except asyncio.TimeoutError:
            proc.kill()
            stdout, stderr = await proc.communicate()
            log("WARN", "[Prowler] Timeout dopo 15 minuti: tentativo raccolta output parziale.")

        # Locate OCSF output file generated inside out_dir
        ocsf_files = sorted(out_dir.glob("*.ocsf.json")) + sorted(out_dir.glob("*ocsf*.json"))
        if not ocsf_files:
            err_msg = (stderr or stdout or b"").decode("utf-8", errors="replace").strip()[-400:]
            raise RuntimeError(f"Prowler non ha generato file OCSF (exit {proc.returncode}): {err_msg}")

        raw_ocsf = ocsf_files[0].read_text(encoding="utf-8", errors="replace")
        posture, findings = parse_prowler_ocsf_json(raw_ocsf, prov, compliance=compliance, services=clean_svcs)
        log("INFO", f"[Prowler] Completato: {posture['passed']} PASS, {posture['failed']} FAIL (Pass Rate {posture['pass_rate']}%).")
        return posture, findings
    finally:
        for tf in temp_files:
            try:
                tf.unlink(missing_ok=True)
            except Exception:
                pass
        shutil.rmtree(out_dir, ignore_errors=True)


def start_cloud_scan_in_background(scan_id: int, cloud_payload: Dict[str, Any]) -> None:
    """Launch an async Prowler Cloud Security scan on a daemon thread updating SQLite progress."""
    def _worker() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run_cloud_scan_pipeline(scan_id, cloud_payload))
        finally:
            try:
                loop.close()
            except Exception:
                pass

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


async def _run_cloud_scan_pipeline(scan_id: int, cloud_payload: Dict[str, Any]) -> None:
    conn = get_db_connection()
    logs: List[Dict[str, str]] = []

    def append_log(level: str, msg: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        logs.append({"ts": ts, "level": level, "msg": msg})
        try:
            with conn:
                conn.execute("UPDATE scans SET logs_json = ? WHERE id = ?;", (json.dumps(logs[-250:]), scan_id))
        except Exception:
            pass

    def update_progress(pct: int, task_msg: str) -> None:
        try:
            with conn:
                conn.execute(
                    "UPDATE scans SET progress = ?, current_task = ?, status = 'running' WHERE id = ?;",
                    (pct, task_msg, scan_id),
                )
        except Exception:
            pass

    try:
        scan = get_scan_by_id(scan_id)
        if not scan:
            return

        update_progress(10, "Inizializzazione audit Prowler Cloud Security...")
        provider = str(cloud_payload.get("provider") or "aws").lower()
        creds = cloud_payload.get("credentials") or {}
        region = str(cloud_payload.get("region") or "")
        compliance = str(cloud_payload.get("compliance") or "")
        services = cloud_payload.get("services") or []
        severities = cloud_payload.get("severities") or []

        update_progress(35, f"Scansione CSPM Prowler ({provider.upper()}) in corso...")
        posture, cloud_findings = await run_prowler_scan(
            provider=provider,
            credentials=creds,
            region=region,
            compliance=compliance,
            services=services,
            severities=severities,
            log_callback=append_log,
        )

        update_progress(82, "Salvataggio finding & calcolo Cloud Posture...")
        now_iso = datetime.now(timezone.utc).isoformat()
        with conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?;", (scan_id,))
            for f in cloud_findings:
                conn.execute(
                    """
                    INSERT INTO findings (
                        scan_id, org_id, host, port, protocol, service,
                        title, severity, cvss, cve_ids, cwe_id, source_engine,
                        description, evidence, remediation, mitre_tactic, mitre_technique,
                        ai_insight, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', 'open', ?);
                    """,
                    (
                        scan_id,
                        scan["org_id"],
                        f.get("host", ""),
                        0,
                        f.get("protocol", "api"),
                        f.get("service", ""),
                        f.get("title", ""),
                        f.get("severity", "info"),
                        f.get("cvss", 0.0),
                        "",
                        "",
                        "prowler",
                        f.get("description", ""),
                        f.get("evidence", ""),
                        f.get("remediation", ""),
                        f.get("mitre_tactic", "Cloud Posture"),
                        f.get("mitre_technique", "CSPM"),
                        now_iso,
                    ),
                )

        crit = sum(1 for f in cloud_findings if f["severity"] == "critical")
        high = sum(1 for f in cloud_findings if f["severity"] == "high")
        med = sum(1 for f in cloud_findings if f["severity"] == "medium")
        low = sum(1 for f in cloud_findings if f["severity"] == "low")
        info = sum(1 for f in cloud_findings if f["severity"] == "info")
        risk_score = min(100, int((crit * 25) + (high * 15) + (med * 5) + (low * 2)))
        risk_label = "CRITICO" if risk_score >= 75 else ("ALTO" if risk_score >= 50 else ("MEDIO" if risk_score >= 25 else "BASSO"))

        hosts_list = [{
            "ip": posture["account"] if posture["account"] != "-" else f"{provider}-cloud",
            "hostname": f"{provider.upper()} Cloud ({posture['compliance']})",
            "os": f"Cloud Account / Pass Rate {posture['pass_rate']}%",
            "ports": [],
        }]
        summary = {
            "total_hosts": 1,
            "up_hosts": 1,
            "total_ports": 0,
            "total_findings": len(cloud_findings),
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "info": info,
            "risk_score": risk_score,
            "risk_label": risk_label,
            "engines_used": ["prowler"],
            "cloud_posture": posture,
        }

        update_progress(94, "Generazione analisi Purple Team su posture Cloud...")
        settings = get_settings()
        org = get_organization_by_id(scan["org_id"]) or {}
        ai_res = await analyze_findings(scan=scan, findings=cloud_findings, settings=settings, org=org, mode="purple")

        with conn:
            conn.execute(
                """
                UPDATE scans SET
                    status = 'completed',
                    progress = 100,
                    current_task = 'Audit Cloud Security completato',
                    completed_at = ?,
                    hosts_json = ?,
                    summary_json = ?,
                    ai_analysis_json = ?
                WHERE id = ?;
                """,
                (now_iso, json.dumps(hosts_list), json.dumps(summary), json.dumps(ai_res), scan_id),
            )
    except Exception as exc:
        append_log("ERROR", f"[Prowler] Audit fallito: {exc}")
        with conn:
            conn.execute(
                "UPDATE scans SET status = 'failed', current_task = ?, completed_at = ? WHERE id = ?;",
                (f"Errore: {str(exc)[:180]}", datetime.now(timezone.utc).isoformat(), scan_id),
            )
    finally:
        conn.close()
