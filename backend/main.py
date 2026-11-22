import os
import re
import hashlib
import secrets
import sys
import time
import json
import asyncio
import platform
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, Query, Body, Response, Header, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from backend.database import (
    init_db, seed_demo_data, get_db_connection, get_settings, update_settings,
    get_organizations, get_organization_by_id, create_organization,
    update_organization, delete_organization, get_scans, get_scan_by_id,
    get_findings_for_scan, update_finding_status, get_dashboard_stats,
    get_user_by_username, update_user_password, set_user_pending_totp,
    enable_user_totp, disable_user_totp,
    create_agent, get_agents, get_agent_by_id, get_agent_by_token, delete_agent, update_agent_heartbeat,
    rotate_agent_token, create_ai_report, get_ai_reports, get_ai_report_by_id, delete_ai_report,
    REPORTS_DIR as DB_REPORTS_DIR
)
from backend.auth import (
    hash_password, verify_password,
    generate_totp_secret, get_otpauth_uri, generate_totp_code,
    verify_totp_code, generate_qr_svg_data_uri,
    create_session_token, verify_session_token,
    check_login_rate_limit, record_login_failure, clear_login_failures,
    revoke_session_token,
    verify_totp, generate_qr_svg, create_token, decode_token
)
from backend.scanners.nmap_engine import detect_nmap, get_nse_catalog, install_nmap
from backend.scanners.nuclei_engine import detect_nuclei, install_nuclei
from backend.scanners.zap_engine import detect_zap, install_zap
from backend.scanners.recon_engine import (
    detect_subfinder,
    install_subfinder,
    detect_httpx,
    install_httpx,
    detect_feroxbuster,
    install_feroxbuster,
    detect_subzy,
    install_subzy,
)
from backend.scanners.wordlists import list_wordlists, save_custom_wordlist, delete_custom_wordlist
from backend.scanners.tor_engine import (
    detect_tor,
    install_tor,
    ensure_tor_running,
    stop_tor_daemon,
    rotate_tor_circuit,
    get_proxy_exit_ip,
    validate_proxy_url,
)
from backend.scanners.engine_bootstrap import get_bootstrap_state, start_engine_bootstrap_background
from backend.scanners.deduplicator import consolidate_findings
from backend.scanners.orchestrator import start_scan_in_background, stop_scan
from backend.scanners.nat_guard import check_targets_nat_loopback
from backend.probe_packager import build_windows_msi, build_linux_sh
from backend.ai_engine import test_ai_connection, analyze_findings
from backend.report_engine import generate_html_report
from backend.export_engine import (
    export_scan_results_csv,
    export_scan_results_txt,
    generate_pdf_document,
    generate_docx_report,
)
from backend.scheduler import init_scheduler, shutdown_scheduler, reload_schedules, trigger_schedule_now

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
REPORTS_DIR = BASE_DIR / "reports"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    init_scheduler()
    start_engine_bootstrap_background()
    yield
    # Shutdown
    shutdown_scheduler()
    await stop_tor_daemon()


app = FastAPI(
    title="UrielScan API",
    description="Backend ad alte prestazioni per Vulnerability Scanner di Rete e Web Purple Team",
    version="1.0.0",
    lifespan=lifespan
)

_PUBLIC_API_PATHS = {
    "/api/system/status",
    "/api/auth/login",
    "/api/auth/verify-2fa",
    "/api/auth/logout",
}


@app.middleware("http")
async def enforce_api_auth_and_security_headers(request: Request, call_next):
    path = request.url.path

    # Enforce authentication on all /api/* endpoints except explicit public/agent routes
    if request.method != "OPTIONS" and path.startswith("/api/"):
        if path not in _PUBLIC_API_PATHS and not path.startswith("/api/agent/"):
            auth_hdr = request.headers.get("authorization", "")
            if not auth_hdr.startswith("Bearer "):
                return JSONResponse(status_code=401, content={"detail": "Authentication required."})
            token = auth_hdr[7:].strip()
            decoded = verify_session_token(token, allow_temp=False)
            if not decoded:
                return JSONResponse(status_code=401, content={"detail": "Invalid or expired session token."})
            username = decoded.get("sub") or decoded.get("username")
            if not username or not get_user_by_username(username):
                return JSONResponse(status_code=401, content={"detail": "User account not found."})

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if path.startswith("/api/reports/") and path.endswith("/view") and response.headers.get("content-type", "").startswith("text/html"):
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:;"
    return response


# Enable restricted CORS (registered after http middleware so CORS wraps outer layer cleanly)
_CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "URIELSCAN_CORS_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# PYDANTIC SCHEMAS
# ==========================================

class LoginRequest(BaseModel):
    username: str
    password: str

class Verify2FARequest(BaseModel):
    temp_token: str
    code: str

class Enable2FARequest(BaseModel):
    code: str

class Disable2FARequest(BaseModel):
    password: str
    code: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class SettingsModel(BaseModel):
    scanner_company_name: Optional[str] = None
    scanner_company_logo: Optional[str] = None
    scanner_company_email: Optional[str] = None
    scanner_company_website: Optional[str] = None
    scanner_company_address: Optional[str] = None
    report_footer: Optional[str] = None
    ai_provider: Optional[str] = None
    ai_api_key: Optional[str] = None
    clear_ai_api_key: Optional[bool] = None
    ai_model: Optional[str] = None
    ai_base_url: Optional[str] = None
    # Frontend aliases
    company_name: Optional[str] = None
    contact_email: Optional[str] = None
    website: Optional[str] = None
    logo_url: Optional[str] = None
    provider: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    base_url: Optional[str] = None


class OrganizationCreateModel(BaseModel):
    name: str = Field(..., min_length=1)
    industry: Optional[str] = ""
    contact_name: Optional[str] = ""
    contact_email: Optional[str] = ""
    logo_data: Optional[str] = ""
    logo_url: Optional[str] = ""
    target_scope: Optional[str] = ""
    description: Optional[str] = ""
    notes: Optional[str] = ""


class OrganizationUpdateModel(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    logo_data: Optional[str] = None
    logo_url: Optional[str] = None
    target_scope: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None


class ScanCreateModel(BaseModel):
    org_id: int | str
    name: str = Field(..., min_length=1)
    targets: str = Field(..., min_length=1)
    scan_profile: Optional[str] = "standard"
    scan_type: Optional[str] = None
    engines: Optional[List[str]] = ["native"]
    config: Optional[Dict[str, Any]] = {}
    nmap_args: Optional[str] = None
    nse_scripts: Optional[List[str]] = None
    nuclei_tags: Optional[List[str]] = None
    nuclei_severity: Optional[List[str]] = None
    web_checks: Optional[List[str]] = None
    zap_mode: Optional[str] = "baseline"
    agent_id: Optional[int | str] = None
    onion_mode: Optional[bool] = False
    proxy_url: Optional[str] = None
    enable_subdomain_enum: Optional[bool] = False
    subdomain_wordlist: Optional[str] = "n0kovo"
    subdomain_checks: Optional[List[str]] = None
    cascade_subdomains: Optional[bool] = True
    cascade_limit: Optional[int] = 20
    enable_dir_enum: Optional[bool] = False
    dir_wordlist: Optional[str] = "dirbuster_medium"
    dir_extensions: Optional[str] = ""
    dir_recursion: Optional[bool] = False
    dir_max_depth: Optional[int] = 2
    dir_rate_limit: Optional[int] = 100
    dir_time_limit: Optional[int] = 180
    enable_tech_fingerprint: Optional[bool] = True
    enable_cve_intel: Optional[bool] = True


class ProxyTestRequest(BaseModel):
    proxy_url: str = Field(..., min_length=1)


class AgentCreateModel(BaseModel):
    org_id: int | str
    name: str = Field(..., min_length=1)


class ProbeInstallerRequest(BaseModel):
    platform: str = Field(..., pattern="^(windows_msi|linux_sh)$")
    server_url: Optional[str] = None
    token: Optional[str] = None
    insecure: bool = False
    interval: int = Field(5, ge=2, le=300)


class ProbeHeartbeatModel(BaseModel):
    hostname: Optional[str] = ""
    ip_address: Optional[str] = ""
    os_info: Optional[str] = ""
    engines: Optional[Dict[str, Any]] = {}
    version: Optional[str] = "1.0.0"


class ProbeProgressModel(BaseModel):
    progress: int = Field(0, ge=0, le=100)
    current_task: Optional[str] = ""
    logs: Optional[List[Dict[str, Any]]] = None
    logs_json: Optional[Any] = None


class ProbeResultsModel(BaseModel):
    hosts: Optional[List[Dict[str, Any]]] = []
    logs: Optional[List[Dict[str, Any]]] = []
    findings: Optional[List[Dict[str, Any]]] = []
    hosts_json: Optional[Any] = None
    logs_json: Optional[Any] = None
    summary: Optional[Dict[str, Any]] = None


class FindingStatusUpdateModel(BaseModel):
    status: str = Field(..., pattern="^(open|in_progress|resolved|false_positive)$")


class AIAnalyzeRequest(BaseModel):
    scan_id: Optional[int | str] = None
    finding_ids: Optional[List[int | str]] = None
    mode: Optional[str] = "purple_team"
    prompt: Optional[str] = ""
    extra_prompt: Optional[str] = ""
    lang: Optional[str] = Field("en", pattern="^(en|it)$")


class ReportGenerateRequest(BaseModel):
    scan_id: int | str
    classification: Optional[str] = "CONFIDENTIAL - PURPLE TEAM ASSESSMENT"
    title: Optional[str] = None
    lang: Optional[str] = Field("en", pattern="^(en|it)$")


class ReportExportRequest(BaseModel):
    scan_id: int | str
    format: str = Field("docx", pattern="^(pdf|docx|html)$")
    report_title: Optional[str] = None
    classification: Optional[str] = "CONFIDENTIAL - PURPLE TEAM ASSESSMENT"
    executive_notes: Optional[str] = ""
    include_ai: bool = True
    include_evidence: bool = True
    include_host_topology: bool = True
    lang: Optional[str] = Field("en", pattern="^(en|it)$")


class ScheduleCreateModel(BaseModel):
    org_id: int | str
    name: str = Field(..., min_length=1)
    targets: str = Field(..., min_length=1)
    profile: Optional[str] = None
    frequency: Optional[str] = "weekly"
    cron_expr: Optional[str] = None
    time_of_day: Optional[str] = "02:00"
    day_of_week: Optional[str | int] = "MON"
    scan_config: Optional[Dict[str, Any]] = {}
    enabled: Optional[bool] = True


class ScheduleUpdateModel(BaseModel):
    name: Optional[str] = None
    targets: Optional[str] = None
    profile: Optional[str] = None
    frequency: Optional[str] = None
    cron_expr: Optional[str] = None
    time_of_day: Optional[str] = None
    day_of_week: Optional[str | int] = None
    scan_config: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


def _parse_int_id(val: Any, default: int = 1) -> int:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        digits = "".join(ch for ch in val if ch.isdigit())
        if digits:
            return int(digits)
    return default


# ==========================================
# 1. SYSTEM & TOOL DISCOVERY ENDPOINTS
# ==========================================

@app.get("/api/system/status")
async def get_system_status():
    nmap_info = detect_nmap()
    nuclei_info = detect_nuclei()
    zap_info = detect_zap()
    tor_info = detect_tor()
    subfinder_info = detect_subfinder()
    httpx_info = detect_httpx()
    feroxbuster_info = detect_feroxbuster()
    subzy_info = detect_subzy()

    return {
        "status": "healthy",
        "system": {
            "os": platform.system(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "python_version": sys.version.split()[0]
        },
        "engines": {
            "native": {
                "installed": True,
                "version": "1.0.0",
                "features": ["TCP Port Scan", "Banner Grab", "SSL/TLS Inspection", "Web Security Headers", "CORS Misconfig", "Sensitive Endpoints Discovery"]
            },
            "nmap": nmap_info,
            "nuclei": nuclei_info,
            "zap": zap_info,
            "tor": tor_info,
            "subfinder": subfinder_info,
            "httpx": httpx_info,
            "feroxbuster": feroxbuster_info,
            "subzy": subzy_info,
        },
        "bootstrap": get_bootstrap_state(),
    }


@app.post("/api/system/install-nmap")
async def install_nmap_endpoint():
    return await install_nmap()


@app.post("/api/system/install-nuclei")
async def install_nuclei_endpoint():
    return await install_nuclei()


@app.post("/api/system/install-zap")
async def install_zap_endpoint():
    return await install_zap()


@app.post("/api/system/install-subfinder")
async def install_subfinder_endpoint():
    return await install_subfinder()


@app.post("/api/system/install-httpx")
async def install_httpx_endpoint():
    return await install_httpx()


@app.post("/api/system/install-feroxbuster")
async def install_feroxbuster_endpoint():
    return await install_feroxbuster()


@app.post("/api/system/install-subzy")
async def install_subzy_endpoint():
    return await install_subzy()


@app.get("/api/wordlists")
async def get_wordlists_endpoint():
    return list_wordlists()


@app.post("/api/wordlists/upload")
async def upload_wordlist_endpoint(
    category: str = Form(...),
    file: UploadFile = File(...),
):
    content = await file.read()
    try:
        saved = save_custom_wordlist(category, file.filename or "custom.txt", content)
        return {"success": True, "wordlist": saved}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/wordlists/{category}/{filename}")
async def delete_wordlist_endpoint(category: str, filename: str):
    try:
        removed = delete_custom_wordlist(category, filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not removed:
        raise HTTPException(status_code=404, detail="Wordlist not found.")
    return {"success": True}


@app.post("/api/system/install-tor")
async def install_tor_endpoint():
    return await install_tor()


@app.post("/api/system/tor/start")
async def start_tor_endpoint():
    res = await ensure_tor_running(timeout=90.0)
    if not res.get("ok"):
        raise HTTPException(status_code=500, detail=res.get("error", "Tor startup failed."))
    exit_info = await get_proxy_exit_ip(res["proxy_url"], timeout=15.0)
    return {**res, **exit_info, "tor": detect_tor()}


@app.post("/api/system/tor/stop")
async def stop_tor_endpoint():
    res = await stop_tor_daemon()
    return {**res, "tor": detect_tor()}


@app.post("/api/system/tor/new-identity")
async def tor_new_identity_endpoint():
    res = await ensure_tor_running(timeout=90.0)
    if not res.get("ok"):
        raise HTTPException(status_code=500, detail=res.get("error", "Tor is not running."))
    rot = await rotate_tor_circuit(int(res.get("control_port", 19051)))
    if not rot.get("ok"):
        raise HTTPException(status_code=500, detail=rot.get("error", "Circuit rotation failed."))
    exit_info = await get_proxy_exit_ip(res["proxy_url"], timeout=18.0)
    return {**rot, **exit_info, "tor": detect_tor()}


@app.post("/api/system/proxy/test")
async def test_proxy_endpoint(payload: ProxyTestRequest):
    try:
        validated = validate_proxy_url(payload.proxy_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not validated:
        raise HTTPException(status_code=400, detail="Proxy URL is required.")
    return await get_proxy_exit_ip(validated, timeout=15.0)


@app.post("/api/system/install-all-engines")
async def install_all_engines_endpoint():
    started = start_engine_bootstrap_background(force=False, allow_in_test=True)
    return {"started": started, "bootstrap": get_bootstrap_state()}


@app.post("/api/system/reset-data")
async def reset_all_data(include_organizations: bool = Query(False)):
    from backend.scanners.orchestrator import STOP_FLAGS, stop_scan
    for sid in list(STOP_FLAGS.keys()):
        stop_scan(sid)
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM findings;")
        conn.execute("DELETE FROM reports;")
        conn.execute("DELETE FROM ai_reports;")
        conn.execute("DELETE FROM schedules;")
        conn.execute("DELETE FROM scans;")
        if include_organizations:
            conn.execute("DELETE FROM organizations;")
        # Ensure db_initialized stays marked so restart doesn't reseed
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('db_initialized', '1');")
    conn.close()
    return {"success": True, "message": "Dati eliminati con successo.", "scans": 0, "findings": 0}


@app.post("/api/system/seed-demo")
async def seed_demo_endpoint():
    seed_demo_data()
    return {"success": True, "message": "Dati demo ripristinati con successo."}


# ==========================================
# AUTH & 2FA TOTP ENDPOINTS
# ==========================================

def _get_current_user_from_header(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Autenticazione richiesta.")
    token = authorization[7:].strip()
    decoded = verify_session_token(token, allow_temp=False)
    if not decoded:
        raise HTTPException(status_code=401, detail="Token di sessione non valido o scaduto.")
    username = decoded.get("sub") or decoded.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Token di sessione privo di utente.")
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=401, detail="Utente non autenticato o inesistente.")
    return user


@app.post("/api/auth/login")
async def auth_login(req: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{req.username}"
    allowed, retry_after = check_login_rate_limit(rate_key)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Troppi tentativi falliti. Riprova tra {retry_after} secondi."
        )

    user = get_user_by_username(req.username)
    if not user or not verify_password(req.password, user["salt"], user["password_hash"]):
        record_login_failure(rate_key)
        raise HTTPException(status_code=401, detail="Credenziali non valide.")

    clear_login_failures(rate_key)

    if user["totp_enabled"]:
        temp_token = create_session_token(user["username"], user["role"], expires_in_seconds=600, is_temp=True)
        return {
            "requires_2fa": True,
            "temp_token": temp_token,
            "username": user["username"],
            "message": "Codice 2FA TOTP richiesto."
        }

    token = create_session_token(user["username"], user["role"], expires_in_seconds=86400, is_temp=False)
    return {
        "requires_2fa": False,
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "totp_enabled": False,
            "must_change_password": bool(user.get("must_change_password", 0)),
        }
    }


@app.post("/api/auth/verify-2fa")
async def auth_verify_2fa(req: Verify2FARequest):
    decoded = verify_session_token(req.temp_token, allow_temp=True)
    if not decoded or not decoded.get("temp"):
        raise HTTPException(status_code=401, detail="Token 2FA temporaneo non valido o scaduto.")

    username = decoded.get("sub") or decoded.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Token 2FA non valido.")

    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato.")

    secret = user.get("totp_secret", "")
    if not secret or not verify_totp_code(secret, req.code):
        raise HTTPException(status_code=401, detail="Codice TOTP non valido. Verifica l'ora del dispositivo.")

    revoke_session_token(req.temp_token)
    token = create_session_token(user["username"], user["role"], expires_in_seconds=86400, is_temp=False)
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "totp_enabled": True,
            "must_change_password": bool(user.get("must_change_password", 0)),
        }
    }


@app.post("/api/auth/logout")
async def auth_logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        revoke_session_token(authorization[7:].strip())
    return {"success": True}


@app.get("/api/auth/me")
async def auth_me(authorization: Optional[str] = Header(None)):
    user = _get_current_user_from_header(authorization)
    return {
        "username": user["username"],
        "role": user.get("role", "admin"),
        "totp_enabled": bool(user["totp_enabled"]),
        "must_change_password": bool(user.get("must_change_password", 0)),
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user.get("role", "admin"),
            "totp_enabled": bool(user["totp_enabled"]),
            "must_change_password": bool(user.get("must_change_password", 0)),
        }
    }


@app.post("/api/auth/2fa/setup")
async def auth_2fa_setup(authorization: Optional[str] = Header(None)):
    user = _get_current_user_from_header(authorization)
    secret = generate_totp_secret()
    username = user["username"]
    otpauth_uri = get_otpauth_uri(username, secret, issuer="UrielScan")
    qr_svg = generate_qr_svg_data_uri(otpauth_uri)

    set_user_pending_totp(username, secret)

    return {
        "secret": secret,
        "otpauth_uri": otpauth_uri,
        "qr_svg": qr_svg
    }


@app.post("/api/auth/2fa/enable")
async def auth_2fa_enable(req: Enable2FARequest, authorization: Optional[str] = Header(None)):
    user = _get_current_user_from_header(authorization)
    secret = user.get("totp_pending_secret") or user.get("totp_secret", "")
    if not secret or not verify_totp_code(secret, req.code):
        raise HTTPException(status_code=400, detail="Codice OTP non valido. Verifica l'ora del dispositivo.")

    enable_user_totp(user["username"], secret)

    return {
        "success": True,
        "totp_enabled": True,
        "message": "Autenticazione a due fattori (2FA TOTP) attivata con successo."
    }


@app.post("/api/auth/2fa/disable")
async def auth_2fa_disable(req: Disable2FARequest, authorization: Optional[str] = Header(None)):
    user = _get_current_user_from_header(authorization)
    if not verify_password(req.password, user["salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Password errata.")
    secret = user.get("totp_secret", "")
    if user.get("totp_enabled") and (not secret or not verify_totp_code(secret, req.code)):
        raise HTTPException(status_code=401, detail="Codice TOTP non valido.")

    disable_user_totp(user["username"])

    return {
        "success": True,
        "totp_enabled": False,
        "message": "Autenticazione a due fattori disabilitata."
    }


@app.post("/api/auth/change-password")
async def auth_change_password(req: ChangePasswordRequest, authorization: Optional[str] = Header(None)):
    user = _get_current_user_from_header(authorization)
    if not verify_password(req.current_password, user["salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Password attuale errata.")
    if len(req.new_password.strip()) < 8:
        raise HTTPException(status_code=400, detail="La nuova password deve contenere almeno 8 caratteri.")

    new_hash, new_salt = hash_password(req.new_password.strip())
    update_user_password(user["username"], new_hash, new_salt)

    return {"success": True, "message": "Password aggiornata con successo."}


# ==========================================
# 2. SETTINGS & AI CONFIGURATION ENDPOINTS
# ==========================================

def _mask_settings(s: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(s)
    raw_key = str(out.get("ai_api_key") or "")
    out["ai_api_key"] = ""
    out["ai_api_key_configured"] = bool(raw_key)
    if len(raw_key) >= 8:
        out["ai_api_key_masked"] = f"{raw_key[:4]}...{raw_key[-4:]}"
    elif raw_key:
        out["ai_api_key_masked"] = "****"
    else:
        out["ai_api_key_masked"] = ""
    return {
        **out,
        "company_name": out.get("scanner_company_name", ""),
        "contact_email": out.get("scanner_company_email", ""),
        "website": out.get("scanner_company_website", ""),
        "logo_url": out.get("scanner_company_logo", ""),
    }


@app.get("/api/settings")
async def get_settings_endpoint():
    return _mask_settings(get_settings())


@app.put("/api/settings")
async def update_settings_endpoint(payload: SettingsModel):
    raw = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "company_name" in raw and "scanner_company_name" not in raw:
        raw["scanner_company_name"] = raw.pop("company_name")
    if "contact_email" in raw and "scanner_company_email" not in raw:
        raw["scanner_company_email"] = raw.pop("contact_email")
    if "website" in raw and "scanner_company_website" not in raw:
        raw["scanner_company_website"] = raw.pop("website")
    if "logo_url" in raw and "scanner_company_logo" not in raw:
        raw["scanner_company_logo"] = raw.pop("logo_url")
    if "provider" in raw and "ai_provider" not in raw:
        raw["ai_provider"] = raw.pop("provider")
    if "api_key" in raw and "ai_api_key" not in raw:
        raw["ai_api_key"] = raw.pop("api_key")
    if "model" in raw and "ai_model" not in raw:
        raw["ai_model"] = raw.pop("model")
    if "base_url" in raw and "ai_base_url" not in raw:
        raw["ai_base_url"] = raw.pop("base_url")

    clear_key = bool(raw.pop("clear_ai_api_key", False))
    if clear_key:
        raw["ai_api_key"] = ""
    else:
        # Preserve stored AI key when UI submits blank or masked placeholder
        incoming_key = str(raw.get("ai_api_key", ""))
        if "ai_api_key" in raw and (incoming_key == "" or "..." in incoming_key or incoming_key == "****"):
            raw.pop("ai_api_key", None)

    update_settings(raw)
    masked = _mask_settings(get_settings())
    return {
        "success": True,
        "settings": masked,
        **masked,
    }


@app.delete("/api/settings/ai-api-key")
async def delete_ai_api_key_endpoint():
    update_settings({"ai_api_key": ""})
    masked = _mask_settings(get_settings())
    return {
        "success": True,
        "settings": masked,
        **masked,
    }


@app.post("/api/ai/test")
async def test_ai_endpoint(settings_override: Optional[SettingsModel] = None):
    current = get_settings()
    if settings_override:
        raw = {k: v for k, v in settings_override.model_dump().items() if v is not None}
        if "provider" in raw:
            current["ai_provider"] = raw["provider"]
        if "api_key" in raw and raw["api_key"] and "..." not in str(raw["api_key"]):
            current["ai_api_key"] = raw["api_key"]
        if "model" in raw:
            current["ai_model"] = raw["model"]
        if "base_url" in raw:
            current["ai_base_url"] = raw["base_url"]
        for k, v in raw.items():
            if k in ("ai_api_key", "api_key") and (not v or "..." in str(v)):
                continue
            current[k] = v
    try:
        res = await test_ai_connection(current)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    return res


# ==========================================
# 3. ORGANIZATIONS (MSP / MULTI-TENANCY)
# ==========================================

@app.get("/api/organizations")
async def list_organizations():
    return get_organizations()


@app.post("/api/organizations", status_code=201)
async def add_organization(org: OrganizationCreateModel):
    data = org.model_dump()
    if data.get("logo_url") and not data.get("logo_data"):
        data["logo_data"] = data["logo_url"]
    if data.get("notes") and not data.get("description"):
        data["description"] = data["notes"]
    org_id = create_organization(data)
    new_org = get_organization_by_id(org_id)
    return new_org


@app.get("/api/organizations/{org_id}")
async def get_organization(org_id: str):
    oid = _parse_int_id(org_id)
    org = get_organization_by_id(oid)
    if not org:
        raise HTTPException(status_code=404, detail="Organizzazione non trovata.")
    return org


@app.put("/api/organizations/{org_id}")
async def edit_organization(org_id: str, payload: OrganizationUpdateModel):
    oid = _parse_int_id(org_id)
    data = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "logo_url" in data and "logo_data" not in data:
        data["logo_data"] = data.pop("logo_url")
    if "notes" in data and "description" not in data:
        data["description"] = data.pop("notes")
    updated = update_organization(oid, data)
    if not updated:
        raise HTTPException(status_code=404, detail="Organizzazione non trovata.")
    return get_organization_by_id(oid)


@app.delete("/api/organizations/{org_id}")
async def remove_organization(org_id: str):
    oid = _parse_int_id(org_id)
    deleted = delete_organization(oid)
    if not deleted:
        raise HTTPException(status_code=404, detail="Organizzazione non trovata.")
    return {"success": True, "message": "Organizzazione eliminata con successo."}


# ==========================================
# 4. DASHBOARD STATS
# ==========================================

@app.get("/api/dashboard/stats")
async def dashboard_stats(org_id: Optional[str] = Query(None)):
    oid = _parse_int_id(org_id) if org_id else None
    return get_dashboard_stats(oid)


# ==========================================
# 5. NMAP SCRIPTS CATALOG & PRESETS
# ==========================================

@app.get("/api/nmap/scripts")
async def nmap_scripts(
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None)
):
    return get_nse_catalog(category=category, search=search)


# ==========================================
# 6. SCANS MANAGEMENT & EXECUTION
# ==========================================

@app.get("/api/scans")
async def list_scans(org_id: Optional[str] = Query(None)):
    oid = _parse_int_id(org_id) if org_id else None
    return get_scans(org_id=oid)


@app.post("/api/scans", status_code=201)
async def create_and_start_scan(payload: ScanCreateModel):
    oid = _parse_int_id(payload.org_id)
    org = get_organization_by_id(oid)
    if not org:
        orgs = get_organizations()
        if orgs:
            oid = orgs[0]["id"]
        else:
            raise HTTPException(status_code=400, detail="Organizzazione specificata non valida.")

    cfg = dict(payload.config or {})
    if payload.nmap_args and "nmap_flags" not in cfg:
        cfg["nmap_flags"] = payload.nmap_args
    if payload.nse_scripts:
        cfg["nse_scripts"] = payload.nse_scripts
    if payload.nuclei_tags:
        cfg["nuclei_tags"] = payload.nuclei_tags
    if payload.nuclei_severity:
        cfg["nuclei_severities"] = payload.nuclei_severity
    if payload.web_checks:
        cfg["web_checks"] = payload.web_checks
    if payload.zap_mode and "zap_mode" not in cfg:
        cfg["zap_mode"] = payload.zap_mode
    if payload.onion_mode is not None:
        cfg["onion_mode"] = bool(payload.onion_mode)
    raw_proxy = payload.proxy_url if payload.proxy_url is not None else cfg.get("proxy_url")
    if raw_proxy is not None and str(raw_proxy).strip():
        try:
            cfg["proxy_url"] = validate_proxy_url(str(raw_proxy))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    elif "proxy_url" in cfg:
        cfg.pop("proxy_url", None)

    if payload.enable_subdomain_enum is not None:
        cfg["enable_subdomain_enum"] = bool(payload.enable_subdomain_enum)
    if payload.subdomain_wordlist is not None:
        cfg["subdomain_wordlist"] = payload.subdomain_wordlist
    if payload.subdomain_checks is not None:
        cfg["subdomain_checks"] = payload.subdomain_checks
    if payload.cascade_subdomains is not None:
        cfg["cascade_subdomains"] = bool(payload.cascade_subdomains)
    if payload.cascade_limit is not None:
        cfg["cascade_limit"] = max(1, min(int(payload.cascade_limit), 50))

    if payload.enable_dir_enum is not None:
        cfg["enable_dir_enum"] = bool(payload.enable_dir_enum)
    if payload.dir_wordlist is not None:
        cfg["dir_wordlist"] = payload.dir_wordlist
    if payload.dir_extensions is not None:
        cfg["dir_extensions"] = payload.dir_extensions
    if payload.dir_recursion is not None:
        cfg["dir_recursion"] = bool(payload.dir_recursion)
    if payload.dir_max_depth is not None:
        cfg["dir_max_depth"] = max(1, min(int(payload.dir_max_depth), 10))
    if payload.dir_rate_limit is not None:
        cfg["dir_rate_limit"] = max(10, min(int(payload.dir_rate_limit), 500))
    if payload.dir_time_limit is not None:
        cfg["dir_time_limit"] = max(30, min(int(payload.dir_time_limit), 600))
    if payload.enable_tech_fingerprint is not None:
        cfg["enable_tech_fingerprint"] = bool(payload.enable_tech_fingerprint)
    if payload.enable_cve_intel is not None:
        cfg["enable_cve_intel"] = bool(payload.enable_cve_intel)

    profile = payload.scan_type or payload.scan_profile or "standard"

    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()

    aid: Optional[int] = None
    if payload.agent_id is not None and str(payload.agent_id).strip() != "":
        aid = _parse_int_id(payload.agent_id)
        agent = get_agent_by_id(aid)
        if not agent:
            raise HTTPException(status_code=400, detail="Agente remoto specificato non trovato.")

    is_remote = aid is not None
    initial_status = "queued" if is_remote else "running"
    initial_task = "Queued for remote probe..." if is_remote else "In coda di esecuzione..."

    conn = get_db_connection()
    with conn:
        cur = conn.execute("""
            INSERT INTO scans (org_id, name, targets, scan_profile, engines_json, config_json, status, progress, current_task, started_at, agent_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?);
        """, (
            oid,
            payload.name,
            payload.targets,
            profile,
            json.dumps(payload.engines or ["native"]),
            json.dumps(cfg),
            initial_status,
            initial_task,
            None if is_remote else now_iso,
            aid
        ))
        scan_id = cur.lastrowid
    conn.close()

    if not is_remote:
        # Launch local scan in background
        start_scan_in_background(scan_id)

    return get_scan_by_id(scan_id)


@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    sid = _parse_int_id(scan_id)
    scan = get_scan_by_id(sid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scansione non trovata.")
    return scan


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    sid = _parse_int_id(scan_id)
    stop_scan(sid)
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?;", (sid,))
        conn.execute("DELETE FROM reports WHERE scan_id = ?;", (sid,))
        cur = conn.execute("DELETE FROM scans WHERE id = ?;", (sid,))
        deleted = cur.rowcount > 0
    conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Scansione non trovata.")
    return {"success": True, "deleted_id": sid, "message": "Scansione eliminata con successo."}


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan_endpoint(scan_id: str):
    sid = _parse_int_id(scan_id)
    stopped_local = stop_scan(sid)
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    with conn:
        cur = conn.execute("""
            UPDATE scans
            SET status = 'stopped', current_task = ?, completed_at = ?
            WHERE id = ? AND status IN ('running', 'queued');
        """, ("Scansione interrotta dall'utente.", now_iso, sid))
        stopped_sql = cur.rowcount > 0
    conn.close()
    stopped = stopped_local or stopped_sql
    return {"success": stopped, "message": "Scansione interrotta." if stopped else "La scansione non era in esecuzione o in coda."}


@app.get("/api/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    sid = _parse_int_id(scan_id)
    return get_findings_for_scan(sid)


@app.get("/api/scans/{scan_id}/hosts")
async def get_scan_hosts(scan_id: str):
    sid = _parse_int_id(scan_id)
    scan = get_scan_by_id(sid)
    if not scan:
        return []
    return scan.get("hosts", [])


@app.get("/api/scans/{scan_id}/export")
async def export_scan_results(
    scan_id: str,
    format: str = Query("csv", pattern="^(csv|txt|pdf)$"),
    lang: str = Query("en", pattern="^(en|it)$"),
):
    orgs = get_organizations()
    org_map = {int(o["id"]): o for o in orgs}
    settings = get_settings()
    mssp_profile = {
        "company_name": settings.get("scanner_company_name", "UrielScan Security"),
        "analyst_name": settings.get("scanner_analyst_name", "Purple Team"),
        "contact_email": settings.get("scanner_company_email", ""),
        "logo_url": settings.get("scanner_company_logo", ""),
        "report_footer": settings.get("report_footer", ""),
    }

    is_it = (lang or "en").lower().startswith("it")
    if scan_id.strip().upper() == "ALL":
        scans_meta = get_scans()
        if not scans_meta:
            raise HTTPException(status_code=404, detail="Nessuna scansione disponibile per l'esportazione." if is_it else "No scans available for export.")
        all_findings: List[Dict[str, Any]] = []
        hosts_map: Dict[str, Any] = {}
        targets_list: List[str] = []
        for s in scans_meta:
            all_findings.extend(get_findings_for_scan(int(s["id"])))
            if s.get("targets"):
                targets_list.append(str(s["targets"]))
            for h in s.get("hosts", []):
                ip = h.get("ip")
                if ip:
                    hosts_map[ip] = h
        title = "UrielScan - Esportazione Aggregata MSP (Tutte le Scansioni)" if is_it else "UrielScan - MSP Aggregated Export (All Scans)"
        targets_str = ", ".join(dict.fromkeys(targets_list))
        hosts_list = list(hosts_map.values())
        client_org: Dict[str, Any] = {"name": "Vista Aggregata MSP" if is_it else "MSP Aggregated View"}
        safe_slug = "all_scans"
        findings = all_findings
    else:
        sid = _parse_int_id(scan_id)
        scan = get_scan_by_id(sid)
        if not scan:
            raise HTTPException(status_code=404, detail="Scansione non trovata." if is_it else "Scan not found.")
        scans_meta = [scan]
        findings = get_findings_for_scan(sid)
        hosts_list = scan.get("hosts", [])
        targets_str = scan.get("targets", "")
        title = f"UrielScan - {scan.get('name', f'Scan #{sid}')}"
        client_org = org_map.get(int(scan.get("org_id") or 0), {"name": "Organizzazione" if is_it else "Organization"})
        safe_slug = f"scan_{sid}"

    fmt = format.lower()
    if fmt == "csv":
        data = export_scan_results_csv(scans_meta, findings, org_map, lang=lang)
        media_type = "text/csv; charset=utf-8"
        filename = f"urielscan_{safe_slug}.csv"
    elif fmt == "txt":
        data = export_scan_results_txt(title, targets_str, hosts_list, findings, org_map, lang=lang)
        media_type = "text/plain; charset=utf-8"
        filename = f"urielscan_{safe_slug}.txt"
    else:
        export_class = "ESPORTAZIONE RISULTATI SCANSIONE" if is_it else "SCAN RESULTS EXPORT"
        single_recon = (scans_meta[0].get("summary") or {}).get("recon") if len(scans_meta) == 1 else None
        data = generate_pdf_document(
            report_title=title,
            classification=export_class,
            mssp_profile=mssp_profile,
            client_org=client_org,
            targets=targets_str,
            hosts=hosts_list,
            findings=findings,
            executive_notes="",
            ai_analysis=scans_meta[0].get("ai_analysis") if len(scans_meta) == 1 else None,
            include_ai=(len(scans_meta) == 1),
            include_evidence=True,
            include_host_topology=True,
            org_map=org_map if len(scans_meta) > 1 else None,
            lang=lang,
            recon_summary=single_recon,
        )
        media_type = "application/pdf"
        filename = f"urielscan_{safe_slug}.pdf"

    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/hosts")
async def get_all_hosts():
    scans = get_scans()
    hosts_map: Dict[str, Any] = {}
    for s in scans:
        for h in s.get("hosts", []):
            ip = h.get("ip")
            if ip:
                hosts_map[ip] = h
    return list(hosts_map.values())


@app.get("/api/findings")
async def list_all_findings(
    scan_id: Optional[str] = Query(None),
    org_id: Optional[str] = Query(None)
):
    if scan_id:
        return get_findings_for_scan(_parse_int_id(scan_id))
    sev_order = """
        CASE LOWER(severity)
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
        END ASC, cvss DESC, id ASC
    """
    conn = get_db_connection()
    if org_id:
        oid = _parse_int_id(org_id)
        rows = conn.execute(f"SELECT * FROM findings WHERE org_id = ? ORDER BY {sev_order};", (oid,)).fetchall()
    else:
        rows = conn.execute(f"SELECT * FROM findings ORDER BY {sev_order};").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ==========================================
# 7. FINDINGS REMEDIATION STATUS
# ==========================================

@app.patch("/api/findings/{finding_id}")
async def update_finding(finding_id: str, payload: FindingStatusUpdateModel):
    fid = _parse_int_id(finding_id)
    updated = update_finding_status(fid, payload.status)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding non trovato.")
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM findings WHERE id = ?;", (fid,)).fetchone()
    conn.close()
    return dict(row) if row else {"success": True, "finding_id": fid, "status": payload.status}


# ==========================================
# 8. AI ANALYSIS ENDPOINTS
# ==========================================

@app.post("/api/ai/analyze")
async def ai_analyze_endpoint(req: AIAnalyzeRequest):
    sid = _parse_int_id(req.scan_id) if req.scan_id else 1
    scan = get_scan_by_id(sid)
    if not scan:
        scans = get_scans()
        if scans:
            scan = get_scan_by_id(scans[0]["id"])
            sid = scan["id"]
        else:
            raise HTTPException(status_code=404, detail="Scansione non trovata.")

    all_findings = get_findings_for_scan(sid)
    if req.finding_ids and len(req.finding_ids) > 0:
        fids = {_parse_int_id(fid) for fid in req.finding_ids}
        findings_to_analyze = [f for f in all_findings if f["id"] in fids]
        if not findings_to_analyze:
            findings_to_analyze = all_findings
    else:
        findings_to_analyze = all_findings

    org = get_organization_by_id(scan["org_id"]) or {}
    settings = get_settings()

    lang = req.lang or "en"
    is_it = lang.lower().startswith("it")

    result = await analyze_findings(
        scan=scan,
        findings=findings_to_analyze,
        org=org,
        scanner_settings=settings,
        mode=req.mode or "purple_team",
        custom_prompt=req.extra_prompt or req.prompt or "",
        lang=lang,
    )

    # Provide frontend-compatible alias keys alongside backend keys
    step_prefix = "Fase" if is_it else "Step"
    result["red_team_paths"] = [
        f"{step_prefix} {ap.get('step', idx+1)} ({ap.get('title', 'Attack Step')}): {ap.get('details', '')}"
        if isinstance(ap, dict) else str(ap)
        for idx, ap in enumerate(result.get("attack_paths", []))
    ]
    result["blue_team_priorities"] = [
        f"[{rp.get('priority', 'P1')}] {rp.get('action', '')}"
        if isinstance(rp, dict) else str(rp)
        for rp in result.get("remediation_plan", [])
    ]
    detected_lbl = "Rilevato su asset" if is_it else "Detected on asset"
    perimeter_lbl = "Perimetro target" if is_it else "Target perimeter"
    result["mitre_techniques"] = [
        {
            "id": ((m.get("technique") or "T1190").split() or ["T1190"])[0],
            "name": m.get("technique") or "Exploit Public-Facing Application",
            "tactic": m.get("tactic") or "Initial Access",
            "description": f"{detected_lbl}: {', '.join(m.get('assets', ['Target']))}" if isinstance(m.get("assets"), list) else str(m.get("assets", perimeter_lbl))
        }
        if isinstance(m, dict) else {"id": "T1190", "name": str(m), "tactic": "Initial Access", "description": ""}
        for m in result.get("mitre_mapping", [])
    ]
    cmds = [rp.get("command") for rp in result.get("remediation_plan", []) if isinstance(rp, dict) and rp.get("command")]
    if cmds:
        result["remediation_script"] = "\n\n".join(cmds)

    # If full scan was analyzed, update DB record
    if not req.finding_ids:
        conn = get_db_connection()
        with conn:
            conn.execute("UPDATE scans SET ai_analysis_json = ? WHERE id = ?;", (json.dumps(result), sid))
        conn.close()

    # Persist AI report in ai_reports table for Report Management / "View all"
    ai_mode = req.mode or "purple_team"
    scope_type = "findings" if (req.finding_ids and len(req.finding_ids) > 0) else "global"
    md_sections = [
        f"# {ai_mode.upper()} — {scan.get('name', f'Scan #{sid}')}",
        f"**Targets:** {scan.get('targets', '')}",
        "",
        "## Executive Summary",
        str(result.get("executive_summary") or ""),
    ]
    if result.get("red_team_paths"):
        md_sections += ["", "## Red Team Attack Paths"] + [f"- {p}" for p in result["red_team_paths"]]
    if result.get("blue_team_priorities"):
        md_sections += ["", "## Blue Team Hardening Priorities"] + [f"- {p}" for p in result["blue_team_priorities"]]
    if result.get("remediation_script"):
        md_sections += ["", "## Remediation Playbook", "```bash", str(result["remediation_script"]), "```"]

    ai_report_id = f"AIRPT-{secrets.token_hex(4).upper()}"
    ai_title = f"[{ai_mode.replace('_', ' ').upper()}] {scan.get('name', f'Scan #{sid}')}"
    saved_ai_report = create_ai_report(
        report_id=ai_report_id,
        org_id=int(scan.get("org_id") or org.get("id") or 1),
        mode=ai_mode,
        scope_type=scope_type,
        title=ai_title,
        model_used=str(result.get("model_used") or settings.get("ai_model") or "local"),
        locale=lang,
        prompt=req.extra_prompt or req.prompt or "",
        content_md="\n".join(md_sections).strip(),
        scan_id=sid,
    )
    result["saved_report"] = saved_ai_report

    return result


@app.get("/api/ai/reports")
async def list_ai_reports_endpoint(org_id: Optional[str] = Query(None)):
    oid = _parse_int_id(org_id) if org_id else None
    return get_ai_reports(org_id=oid)


@app.delete("/api/ai/reports/{report_id}")
async def delete_ai_report_endpoint(report_id: str):
    deleted = delete_ai_report(report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="AI report not found.")
    return {"success": True, "deleted_id": report_id}


# ==========================================
# 9. WHITE-LABEL REPORTING ENDPOINTS
# ==========================================

@app.get("/api/reports")
async def list_reports(org_id: Optional[int] = Query(None)):
    conn = get_db_connection()
    if org_id:
        rows = conn.execute("""
            SELECT r.*, o.name as org_name
            FROM reports r
            JOIN organizations o ON r.org_id = o.id
            WHERE r.org_id = ?
            ORDER BY r.created_at DESC;
        """, (org_id,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT r.*, o.name as org_name
            FROM reports r
            JOIN organizations o ON r.org_id = o.id
            ORDER BY r.created_at DESC;
        """).fetchall()
    conn.close()

    res = []
    for r in rows:
        item = dict(r)
        item["summary"] = json.loads(item.get("summary_json") or "{}")
        res.append(item)
    return res


@app.post("/api/reports/generate", status_code=201)
async def generate_report_endpoint(req: ReportGenerateRequest):
    try:
        lang = req.lang or "en"
        is_it = lang.lower().startswith("it")
        default_class = "CONFIDENZIALE - PURPLE TEAM ASSESSMENT" if is_it else "CONFIDENTIAL - PURPLE TEAM ASSESSMENT"
        classification = req.classification if req.classification and req.classification not in ("CONFIDENZIALE - PURPLE TEAM ASSESSMENT", "CONFIDENTIAL - PURPLE TEAM ASSESSMENT") else default_class
        report_data = generate_html_report(
            scan_id=req.scan_id,
            classification=classification,
            custom_title=req.title,
            lang=lang
        )
        return report_data
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))


@app.post("/api/reports/export")
async def export_custom_report_endpoint(req: ReportExportRequest):
    sid = _parse_int_id(req.scan_id)
    scan = get_scan_by_id(sid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scansione non trovata.")

    lang = req.lang or "en"
    is_it = lang.lower().startswith("it")

    orgs = get_organizations()
    org_map = {int(o["id"]): o for o in orgs}
    default_org_name = "Organizzazione Cliente" if is_it else "Client Organization"
    client_org = org_map.get(int(scan.get("org_id") or 0), {"name": default_org_name})
    settings = get_settings()
    mssp_profile = {
        "company_name": settings.get("scanner_company_name", "UrielScan Security"),
        "analyst_name": settings.get("scanner_analyst_name", "Purple Team"),
        "contact_email": settings.get("scanner_company_email", ""),
        "logo_url": settings.get("scanner_company_logo", ""),
        "report_footer": settings.get("report_footer", ""),
    }

    findings = get_findings_for_scan(sid)
    hosts = scan.get("hosts", [])
    targets = scan.get("targets", "")
    client_name_short = client_org.get('name', 'Cliente' if is_it else 'Client')
    title = req.report_title or f"Security Assessment - {client_name_short} ({scan.get('name', f'Scan #{sid}')})"
    
    default_class = "CONFIDENZIALE - PURPLE TEAM ASSESSMENT" if is_it else "CONFIDENTIAL - PURPLE TEAM ASSESSMENT"
    classification = req.classification if req.classification and req.classification not in ("CONFIDENZIALE - PURPLE TEAM ASSESSMENT", "CONFIDENTIAL - PURPLE TEAM ASSESSMENT") else default_class
    ai_analysis = scan.get("ai_analysis") if req.include_ai else None

    fmt = req.format.lower()
    saved_report_id = ""
    scan_recon_summary = (scan.get("summary") or {}).get("recon")
    if fmt == "pdf":
        data = generate_pdf_document(
            report_title=title,
            classification=classification,
            mssp_profile=mssp_profile,
            client_org=client_org,
            targets=targets,
            hosts=hosts,
            findings=findings,
            executive_notes=req.executive_notes or "",
            ai_analysis=ai_analysis,
            include_ai=req.include_ai,
            include_evidence=req.include_evidence,
            include_host_topology=req.include_host_topology,
            lang=lang,
            recon_summary=scan_recon_summary,
        )
        media_type = "application/pdf"
        filename = f"urielscan_report_scan_{sid}.pdf"
    elif fmt == "docx":
        data = generate_docx_report(
            report_title=title,
            classification=classification,
            mssp_profile=mssp_profile,
            client_org=client_org,
            targets=targets,
            hosts=hosts,
            findings=findings,
            executive_notes=req.executive_notes or "",
            ai_analysis=ai_analysis,
            include_ai=req.include_ai,
            include_evidence=req.include_evidence,
            include_host_topology=req.include_host_topology,
            lang=lang,
            recon_summary=scan_recon_summary,
        )
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        filename = f"urielscan_report_scan_{sid}.docx"
    else:
        report_data = generate_html_report(
            scan_id=sid,
            classification=classification,
            custom_title=title,
            lang=lang,
        )
        saved_report_id = report_data.get("id", "")
        file_path = report_data.get("file_path", "")
        if not file_path or not os.path.isfile(file_path):
            raise HTTPException(status_code=500, detail="Errore nella generazione del report HTML." if is_it else "Error generating HTML report.")
        with open(file_path, "rb") as f:
            data = f.read()
        media_type = "text/html; charset=utf-8"
        filename = f"urielscan_report_scan_{sid}.html"

    # Persist exported PDF / DOCX reports into DB & reports/ folder so Report History tracks all exports
    if fmt in ("pdf", "docx"):
        DB_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        saved_report_id = f"RPT-{sid}-{secrets.token_hex(3).upper()}"
        out_path = DB_REPORTS_DIR / f"{saved_report_id}.{fmt}"
        out_path.write_bytes(data)
        summary_meta = {
            "format": fmt,
            "risk_score": (scan.get("summary") or {}).get("risk_score", 0),
            "total_findings": len(findings),
            "include_ai": bool(req.include_ai),
        }
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection()
        with conn:
            conn.execute("""
                INSERT INTO reports (id, scan_id, org_id, title, classification, created_at, file_path, summary_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                saved_report_id,
                sid,
                int(scan.get("org_id") or 1),
                title,
                classification,
                now_iso,
                str(out_path),
                json.dumps(summary_meta),
            ))
        conn.close()

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Access-Control-Expose-Headers": "X-Report-Id",
    }
    if saved_report_id:
        headers["X-Report-Id"] = saved_report_id

    return Response(
        content=data,
        media_type=media_type,
        headers=headers,
    )


def _resolve_report_media(file_path: str, report_id: str):
    ext = Path(file_path).suffix.lower()
    if ext == ".pdf":
        return "application/pdf", f"{report_id}.pdf"
    if ext == ".docx":
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document", f"{report_id}.docx"
    return "text/html", f"{report_id}.html"


@app.get("/api/reports/{report_id}/view")
async def view_report(report_id: str):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM reports WHERE id = ?;", (report_id,)).fetchone()
    conn.close()
    if not row or not os.path.isfile(row["file_path"]):
        raise HTTPException(status_code=404, detail="File di report non trovato.")

    media_type, filename = _resolve_report_media(row["file_path"], report_id)
    if filename.endswith(".docx"):
        return FileResponse(row["file_path"], media_type=media_type, filename=filename)
    return FileResponse(row["file_path"], media_type=media_type)


@app.get("/api/reports/{report_id}/download")
async def download_report(report_id: str):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM reports WHERE id = ?;", (report_id,)).fetchone()
    conn.close()
    if not row or not os.path.isfile(row["file_path"]):
        raise HTTPException(status_code=404, detail="File di report non trovato.")

    media_type, filename = _resolve_report_media(row["file_path"], report_id)
    return FileResponse(row["file_path"], media_type=media_type, filename=filename)


@app.delete("/api/reports/{report_id}")
async def delete_report(report_id: str):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM reports WHERE id = ?;", (report_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Report non trovato.")

    file_path = row["file_path"]
    if os.path.isfile(file_path):
        try:
            os.remove(file_path)
        except Exception:
            pass

    with conn:
        conn.execute("DELETE FROM reports WHERE id = ?;", (report_id,))
    conn.close()

    return {"success": True, "message": "Report eliminato con successo."}


# ==========================================
# 10. SCAN SCHEDULER ENDPOINTS
# ==========================================

@app.get("/api/schedules")
async def list_schedules(org_id: Optional[str] = Query(None)):
    conn = get_db_connection()
    if org_id:
        oid = _parse_int_id(org_id)
        rows = conn.execute("""
            SELECT s.*, o.name as org_name
            FROM schedules s
            JOIN organizations o ON s.org_id = o.id
            WHERE s.org_id = ?
            ORDER BY s.id DESC;
        """, (oid,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT s.*, o.name as org_name
            FROM schedules s
            JOIN organizations o ON s.org_id = o.id
            ORDER BY s.id DESC;
        """).fetchall()
    conn.close()

    res = []
    for r in rows:
        item = dict(r)
        item["scan_config"] = json.loads(item.get("scan_config_json") or "{}")
        item["enabled"] = bool(item["enabled"])
        res.append(item)
    return res


@app.post("/api/schedules", status_code=201)
async def create_schedule_endpoint(payload: ScheduleCreateModel):
    oid = _parse_int_id(payload.org_id)
    org = get_organization_by_id(oid)
    if not org:
        orgs = get_organizations()
        if orgs:
            oid = orgs[0]["id"]
        else:
            raise HTTPException(status_code=400, detail="Organizzazione specificata non valida.")

    cfg = dict(payload.scan_config or {})
    if payload.profile and "profile" not in cfg:
        cfg["profile"] = payload.profile

    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    with conn:
        cur = conn.execute("""
            INSERT INTO schedules (
                org_id, name, targets, frequency, cron_expr, time_of_day, day_of_week,
                scan_config_json, enabled, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            oid,
            payload.name,
            payload.targets,
            payload.frequency or "weekly",
            payload.cron_expr,
            payload.time_of_day or "02:00",
            str(payload.day_of_week) if payload.day_of_week is not None else "MON",
            json.dumps(cfg),
            1 if payload.enabled else 0,
            now_iso
        ))
        sched_id = cur.lastrowid
        row = conn.execute("SELECT * FROM schedules WHERE id = ?;", (sched_id,)).fetchone()
    conn.close()

    reload_schedules()
    item = dict(row) if row else {"id": sched_id}
    item["scan_config"] = cfg
    item["enabled"] = bool(payload.enabled)
    return {"success": True, "schedule_id": sched_id, **item}


@app.put("/api/schedules/{schedule_id}")
async def update_schedule_endpoint(schedule_id: str, payload: ScheduleUpdateModel):
    sid = _parse_int_id(schedule_id)
    conn = get_db_connection()
    sched = conn.execute("SELECT * FROM schedules WHERE id = ?;", (sid,)).fetchone()
    if not sched:
        conn.close()
        raise HTTPException(status_code=404, detail="Schedulazione non trovata.")

    updates = []
    params = []

    if payload.name is not None:
        updates.append("name = ?")
        params.append(payload.name)
    if payload.targets is not None:
        updates.append("targets = ?")
        params.append(payload.targets)
    if payload.frequency is not None:
        updates.append("frequency = ?")
        params.append(payload.frequency)
    if payload.cron_expr is not None:
        updates.append("cron_expr = ?")
        params.append(payload.cron_expr)
    if payload.time_of_day is not None:
        updates.append("time_of_day = ?")
        params.append(payload.time_of_day)
    if payload.day_of_week is not None:
        updates.append("day_of_week = ?")
        params.append(str(payload.day_of_week))
    if payload.scan_config is not None:
        updates.append("scan_config_json = ?")
        params.append(json.dumps(payload.scan_config))
    if payload.enabled is not None:
        updates.append("enabled = ?")
        params.append(1 if payload.enabled else 0)

    if updates:
        params.append(sid)
        with conn:
            conn.execute(f"UPDATE schedules SET {', '.join(updates)} WHERE id = ?;", params)
    row = conn.execute("SELECT * FROM schedules WHERE id = ?;", (sid,)).fetchone()
    conn.close()

    reload_schedules()
    item = dict(row) if row else {"id": sid}
    item["scan_config"] = json.loads(item.get("scan_config_json") or "{}")
    item["enabled"] = bool(item.get("enabled", True))
    return {"success": True, "schedule_id": sid, **item}


@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule_endpoint(schedule_id: str):
    sid = _parse_int_id(schedule_id)
    conn = get_db_connection()
    with conn:
        cur = conn.execute("DELETE FROM schedules WHERE id = ?;", (sid,))
        deleted = cur.rowcount > 0
    conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedulazione non trovata.")

    reload_schedules()
    return {"success": True, "message": "Schedulazione eliminata con successo."}


@app.post("/api/schedules/{schedule_id}/run-now")
@app.post("/api/schedules/{schedule_id}/run")
async def schedule_run_now_endpoint(schedule_id: str):
    sid = _parse_int_id(schedule_id)
    try:
        new_scan_id = await trigger_schedule_now(sid)
        return {"success": True, "scan_id": new_scan_id, "message": "Scansione avviata immediatamente."}
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))


# ==========================================
# 11. REMOTE PROBE AGENT ENDPOINTS (ADMIN & PROBE)
# ==========================================

def _require_agent(x_agent_token: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not x_agent_token:
        raise HTTPException(status_code=401, detail="Header X-Agent-Token mancante.")
    agent = get_agent_by_token(x_agent_token)
    if not agent:
        raise HTTPException(status_code=401, detail="Token agente non valido o inesistente.")
    return agent


@app.get("/api/network/nat-check")
async def network_nat_check(targets: str = Query("")):
    targets_list = [t.strip() for t in targets.split(",") if t.strip()]
    return await asyncio.to_thread(check_targets_nat_loopback, targets_list)


@app.get("/api/agents")
async def list_agents(org_id: Optional[str] = Query(None)):
    oid = _parse_int_id(org_id) if org_id else None
    return get_agents(org_id=oid)


@app.post("/api/agents", status_code=201)
async def create_agent_endpoint(payload: AgentCreateModel):
    oid = _parse_int_id(payload.org_id)
    org = get_organization_by_id(oid)
    if not org:
        raise HTTPException(status_code=400, detail="Organizzazione specificata non valida.")
    agent = create_agent(oid, payload.name.strip())
    return agent


_INSTALLER_TICKET_TTL_SEC = 86400
_INSTALLER_TICKETS: Dict[str, Dict[str, Any]] = {}


def _prune_installer_tickets() -> None:
    now = time.time()
    expired = [k for k, v in _INSTALLER_TICKETS.items() if v.get("expires_at", 0) <= now]
    for k in expired:
        _INSTALLER_TICKETS.pop(k, None)


def _resolve_server_url_from_request(explicit_url: Optional[str], request: Request) -> str:
    server_url = (explicit_url or "").strip().rstrip("/")
    if server_url:
        return server_url
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")


@app.post("/api/agents/{agent_id}/installer")
async def generate_agent_installer_endpoint(agent_id: str, payload: ProbeInstallerRequest, request: Request):
    aid = _parse_int_id(agent_id)
    agent = get_agent_by_id(aid)
    if not agent:
        raise HTTPException(status_code=404, detail="Agente non trovato.")

    token = (payload.token or "").strip()
    if not token:
        rotated = rotate_agent_token(aid)
        if not rotated or not rotated.get("token"):
            raise HTTPException(status_code=500, detail="Impossibile generare nuova chiave agente.")
        token = rotated["token"]

    server_url = _resolve_server_url_from_request(payload.server_url, request)
    safe_slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", agent.get("name", f"probe-{aid}")).strip("-").lower() or f"probe-{aid}"

    try:
        if payload.platform == "windows_msi":
            content = await asyncio.to_thread(
                build_windows_msi,
                agent["name"],
                token,
                server_url,
                bool(payload.insecure),
                int(payload.interval),
            )
            return Response(
                content=content,
                media_type="application/octet-stream",
                headers={
                    "Content-Disposition": f'attachment; filename="urielscan-probe-{safe_slug}.msi"',
                    "Access-Control-Expose-Headers": "Content-Disposition",
                },
            )
        else:
            content = await asyncio.to_thread(
                build_linux_sh,
                agent["name"],
                token,
                server_url,
                bool(payload.insecure),
                int(payload.interval),
            )
            return Response(
                content=content,
                media_type="text/x-shellscript",
                headers={
                    "Content-Disposition": f'attachment; filename="urielscan-probe-{safe_slug}.sh"',
                    "Access-Control-Expose-Headers": "Content-Disposition",
                },
            )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.post("/api/agents/{agent_id}/installer-link")
async def create_agent_installer_link(agent_id: str, payload: ProbeInstallerRequest, request: Request):
    aid = _parse_int_id(agent_id)
    agent = get_agent_by_id(aid)
    if not agent:
        raise HTTPException(status_code=404, detail="Agente non trovato.")

    token = (payload.token or "").strip()
    if not token:
        rotated = rotate_agent_token(aid)
        if not rotated or not rotated.get("token"):
            raise HTTPException(status_code=500, detail="Impossibile generare nuova chiave agente.")
        token = rotated["token"]

    server_url = _resolve_server_url_from_request(payload.server_url, request)
    safe_slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", agent.get("name", f"probe-{aid}")).strip("-").lower() or f"probe-{aid}"
    ext = "msi" if payload.platform == "windows_msi" else "sh"
    filename = f"urielscan-probe-{safe_slug}.{ext}"

    _prune_installer_tickets()
    ticket = secrets.token_urlsafe(32)
    ticket_hash = hashlib.sha256(ticket.encode("utf-8")).hexdigest()
    _INSTALLER_TICKETS[ticket_hash] = {
        "agent_id": aid,
        "agent_name": agent["name"],
        "platform": payload.platform,
        "server_url": server_url,
        "token": token,
        "insecure": bool(payload.insecure),
        "interval": int(payload.interval),
        "filename": filename,
        "expires_at": time.time() + _INSTALLER_TICKET_TTL_SEC,
    }

    local_download_path = f"/api/agent/installer/{ticket}"
    download_url = f"{server_url}{local_download_path}"

    if payload.platform == "windows_msi":
        insecure_ps = "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; " if payload.insecure else ""
        silent_command = (
            f'[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; '
            f'{insecure_ps}$msi = "$env:TEMP\\{filename}"; '
            f'Invoke-WebRequest -Uri "{download_url}" -OutFile $msi -UseBasicParsing; '
            f'Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -WindowStyle Hidden'
        )
    else:
        curl_flags = "-fsSLk" if payload.insecure else "-fsSL"
        silent_command = f'curl {curl_flags} "{download_url}" -o /tmp/{filename} && sudo bash /tmp/{filename} && rm -f /tmp/{filename}'

    return {
        "agent_id": aid,
        "agent_name": agent["name"],
        "platform": payload.platform,
        "filename": filename,
        "download_url": download_url,
        "local_download_path": local_download_path,
        "silent_command": silent_command,
        "expires_in_seconds": _INSTALLER_TICKET_TTL_SEC,
    }


@app.get("/api/agent/installer/{ticket}")
async def download_agent_installer_by_ticket(ticket: str):
    _prune_installer_tickets()
    ticket_hash = hashlib.sha256((ticket or "").encode("utf-8")).hexdigest()
    entry = _INSTALLER_TICKETS.get(ticket_hash)
    if not entry:
        raise HTTPException(status_code=404, detail="Installer link expired or invalid.")

    agent = get_agent_by_id(entry["agent_id"])
    if not agent:
        _INSTALLER_TICKETS.pop(ticket_hash, None)
        raise HTTPException(status_code=404, detail="Probe agent has been revoked.")

    try:
        if entry["platform"] == "windows_msi":
            content = await asyncio.to_thread(
                build_windows_msi,
                entry["agent_name"],
                entry["token"],
                entry["server_url"],
                bool(entry["insecure"]),
                int(entry["interval"]),
            )
            media_type = "application/octet-stream"
        else:
            content = await asyncio.to_thread(
                build_linux_sh,
                entry["agent_name"],
                entry["token"],
                entry["server_url"],
                bool(entry["insecure"]),
                int(entry["interval"]),
            )
            media_type = "text/x-shellscript"
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{entry["filename"]}"',
            "Cache-Control": "no-store",
        },
    )


@app.delete("/api/agents/{agent_id}")
async def delete_agent_endpoint(agent_id: str):
    aid = _parse_int_id(agent_id)
    deleted = delete_agent(aid)
    if not deleted:
        raise HTTPException(status_code=404, detail="Agente non trovato.")
    for k in [tk for tk, tv in _INSTALLER_TICKETS.items() if tv.get("agent_id") == aid]:
        _INSTALLER_TICKETS.pop(k, None)
    return {"success": True, "message": "Agente eliminato con successo."}


@app.get("/api/agents/probe-script")
async def download_probe_script():
    script_path = BASE_DIR / "agent" / "urielscan_probe.py"
    if not script_path.exists():
        raise HTTPException(status_code=404, detail="Probe script non trovato.")
    return FileResponse(
        path=str(script_path),
        filename="urielscan_probe.py",
        media_type="text/x-python"
    )


@app.post("/api/agent/heartbeat")
async def probe_heartbeat(
    payload: Optional[ProbeHeartbeatModel] = Body(None),
    x_agent_token: Optional[str] = Header(None)
):
    agent = _require_agent(x_agent_token)
    p = payload or ProbeHeartbeatModel()
    update_agent_heartbeat(
        agent_id=agent["id"],
        hostname=p.hostname or "",
        ip_address=p.ip_address or "",
        os_info=p.os_info or "",
        engines=p.engines or {},
        version=p.version or "1.0.0"
    )
    return {"ok": True, "agent_id": agent["id"]}


@app.get("/api/agent/jobs/next")
async def probe_get_next_job(
    x_agent_token: Optional[str] = Header(None)
):
    agent = _require_agent(x_agent_token)
    conn = get_db_connection()
    row = conn.execute("""
        SELECT id FROM scans
        WHERE agent_id = ? AND status = 'queued'
        ORDER BY id ASC LIMIT 1;
    """, (agent["id"],)).fetchone()
    if not row:
        conn.close()
        return {"job": None}

    job_id = row["id"]
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute("""
            UPDATE scans
            SET status = 'running', started_at = ?, current_task = 'Picked up by remote probe...'
            WHERE id = ?;
        """, (now_iso, job_id))
    conn.close()

    job = get_scan_by_id(job_id)
    return {"job": job}


@app.post("/api/agent/jobs/{scan_id}/progress")
async def probe_update_progress(
    scan_id: str,
    payload: ProbeProgressModel,
    x_agent_token: Optional[str] = Header(None)
):
    agent = _require_agent(x_agent_token)
    sid = _parse_int_id(scan_id)
    conn = get_db_connection()
    row = conn.execute("SELECT id, status, logs_json FROM scans WHERE id = ? AND agent_id = ?;", (sid, agent["id"])).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Job non trovato per questo agente.")

    is_stopped = (row["status"] == "stopped")
    if not is_stopped:
        existing_logs = json.loads(row["logs_json"] or "[]")
        new_logs = payload.logs
        if new_logs is None and payload.logs_json is not None:
            if isinstance(payload.logs_json, str):
                try:
                    new_logs = json.loads(payload.logs_json)
                except Exception:
                    new_logs = []
            elif isinstance(payload.logs_json, list):
                new_logs = payload.logs_json

        if new_logs is not None:
            combined_logs = existing_logs + new_logs
            logs_to_save = json.dumps(combined_logs)
        else:
            logs_to_save = row["logs_json"]

        with conn:
            conn.execute("""
                UPDATE scans
                SET progress = ?, current_task = ?, logs_json = ?
                WHERE id = ?;
            """, (payload.progress, payload.current_task or "", logs_to_save, sid))
    conn.close()
    return {"ok": True, "stop": is_stopped}


@app.post("/api/agent/jobs/{scan_id}/results")
async def probe_upload_results(
    scan_id: str,
    payload: ProbeResultsModel,
    x_agent_token: Optional[str] = Header(None)
):
    agent = _require_agent(x_agent_token)
    sid = _parse_int_id(scan_id)
    conn = get_db_connection()
    row = conn.execute("SELECT id, org_id, status, logs_json FROM scans WHERE id = ? AND agent_id = ?;", (sid, agent["id"])).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Job non trovato per questo agente.")

    org_id = row["org_id"]
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()

    # Determine hosts
    hosts_data = payload.hosts or []
    if payload.hosts_json:
        if isinstance(payload.hosts_json, str):
            try:
                hosts_data = json.loads(payload.hosts_json)
            except Exception:
                pass
        elif isinstance(payload.hosts_json, list):
            hosts_data = payload.hosts_json

    # Determine logs
    existing_logs = json.loads(row["logs_json"] or "[]")
    incoming_logs = payload.logs or []
    if payload.logs_json:
        if isinstance(payload.logs_json, str):
            try:
                incoming_logs = json.loads(payload.logs_json)
            except Exception:
                pass
        elif isinstance(payload.logs_json, list):
            incoming_logs = payload.logs_json
    final_logs = existing_logs + incoming_logs if incoming_logs else existing_logs

    # Consolidate, deduplicate across engines, and sort findings by severity
    findings = consolidate_findings(payload.findings or [])
    crit = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
    high = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    med = sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium")
    low = sum(1 for f in findings if str(f.get("severity", "")).lower() == "low")
    info = sum(1 for f in findings if str(f.get("severity", "")).lower() == "info")
    total = len(findings)
    summary = {
        "critical": crit,
        "high": high,
        "medium": med,
        "low": low,
        "info": info,
        "total": total
    }

    with conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?;", (sid,))
        for f in findings:
            conn.execute("""
                INSERT INTO findings (
                    scan_id, org_id, host, port, protocol, service,
                    title, severity, cvss, cve_ids, cwe_id, source_engine,
                    description, evidence, remediation, mitre_tactic, mitre_technique,
                    ai_insight, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                sid,
                org_id,
                str(f.get("host", "")),
                f.get("port"),
                str(f.get("protocol", "tcp")),
                str(f.get("service", "")),
                str(f.get("title", "Finding")),
                str(f.get("severity", "info")).lower(),
                float(f.get("cvss") or 0.0),
                str(f.get("cve_ids", "")),
                str(f.get("cwe_id", "")),
                str(f.get("source_engine", "probe_agent")),
                str(f.get("description", "")),
                str(f.get("evidence", "")),
                str(f.get("remediation", "")),
                str(f.get("mitre_tactic", "")),
                str(f.get("mitre_technique", "")),
                str(f.get("ai_insight", "")),
                str(f.get("status", "open")),
                now_iso
            ))

        conn.execute("""
            UPDATE scans
            SET status = 'completed',
                progress = 100,
                current_task = 'Completed via remote probe',
                completed_at = ?,
                hosts_json = ?,
                logs_json = ?,
                summary_json = ?
            WHERE id = ?;
        """, (
            now_iso,
            json.dumps(hosts_data),
            json.dumps(final_logs),
            json.dumps(summary),
            sid
        ))
    conn.close()

    return {"ok": True, "scan_id": sid, "findings_count": len(findings), "summary": summary}


# ==========================================
# 12. FRONTEND STATIC ASSETS & SPA ROUTING
# ==========================================

if FRONTEND_DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # Don't intercept API routes
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="API endpoint non trovato.")

        dist_root = FRONTEND_DIST.resolve()
        if full_path:
            potential_file = (dist_root / full_path).resolve()
            if not potential_file.is_relative_to(dist_root):
                raise HTTPException(status_code=404, detail="Percorso non valido.")
            if potential_file.is_file():
                return FileResponse(potential_file)

        index_file = dist_root / "index.html"
        if index_file.is_file():
            return FileResponse(index_file)

        return HTMLResponse("<h3>UrielScan: Frontend in fase di sviluppo/compilazione.</h3>")
else:
    @app.get("/", include_in_schema=False)
    async def root_fallback():
        return HTMLResponse("""
        <div style="font-family: sans-serif; padding: 40px; text-align: center;">
            <h1 style="color: #7c3aed;">UrielScan API Server Operativo</h1>
            <p>Il backend FastAPI è attivo e funzionante.</p>
            <p>Accedi alla documentazione interattiva Swagger: <a href="/docs">/docs</a></p>
        </div>
        """)
