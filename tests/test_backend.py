import os
import sys
import time
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure root directory is on PYTHONPATH
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Use an isolated temporary SQLite database for tests so production data/urielscan.db is never modified
_TEST_DB_FILE = Path(tempfile.gettempdir()) / "urielscan_pytest_isolated.db"
if _TEST_DB_FILE.exists():
    try:
        _TEST_DB_FILE.unlink()
    except Exception:
        pass
os.environ["URIELSCAN_DB_PATH"] = str(_TEST_DB_FILE)

from backend.main import app
from backend.database import init_db, seed_demo_data
from backend.auth import generate_totp_code

# Initialize database and load demo data for backend test suite
init_db()
seed_demo_data()
raw_client = TestClient(app)


class _AuthedClient:
    """Test helper that attaches a valid admin Bearer token to authenticated requests."""
    def __init__(self, inner: TestClient):
        self._inner = inner
        self._token: str | None = None

    def _get_headers(self, extra_headers=None):
        if not self._token:
            resp = self._inner.post("/api/auth/login", json={"username": "admin", "password": "admin"})
            assert resp.status_code == 200, resp.text
            self._token = resp.json()["token"]
        merged = {"Authorization": f"Bearer {self._token}"}
        if extra_headers:
            merged.update(extra_headers)
        return merged

    def get(self, url, **kwargs):
        if "headers" in kwargs and "X-Agent-Token" in kwargs["headers"]:
            return self._inner.get(url, **kwargs)
        kwargs["headers"] = self._get_headers(kwargs.get("headers"))
        return self._inner.get(url, **kwargs)

    def post(self, url, **kwargs):
        if "headers" in kwargs and "X-Agent-Token" in kwargs["headers"]:
            return self._inner.post(url, **kwargs)
        kwargs["headers"] = self._get_headers(kwargs.get("headers"))
        return self._inner.post(url, **kwargs)

    def put(self, url, **kwargs):
        kwargs["headers"] = self._get_headers(kwargs.get("headers"))
        return self._inner.put(url, **kwargs)

    def patch(self, url, **kwargs):
        kwargs["headers"] = self._get_headers(kwargs.get("headers"))
        return self._inner.patch(url, **kwargs)

    def delete(self, url, **kwargs):
        kwargs["headers"] = self._get_headers(kwargs.get("headers"))
        return self._inner.delete(url, **kwargs)


client = _AuthedClient(raw_client)


def test_system_status():
    resp = client.get("/api/system/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "system" in data
    assert "engines" in data
    assert data["engines"]["native"]["installed"] is True
    assert "nmap" in data["engines"]
    assert "nuclei" in data["engines"]


def test_settings_get_and_update():
    # 1. Get settings
    resp = client.get("/api/settings")
    assert resp.status_code == 200
    settings = resp.json()
    assert "scanner_company_name" in settings

    # 2. Update settings
    updated_name = "UrielScan Purple Defense MSSP Test"
    resp = client.put("/api/settings", json={
        "scanner_company_name": updated_name,
        "ai_provider": "offline"
    })
    assert resp.status_code == 200
    assert resp.json()["success"] is True

    # 3. Verify
    resp2 = client.get("/api/settings")
    assert resp2.json()["scanner_company_name"] == updated_name


def test_ai_test_connection():
    resp = client.post("/api/ai/test", json={"ai_provider": "offline"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["provider"] == "offline"


def test_organizations_crud():
    # 1. List existing seed orgs
    resp = client.get("/api/organizations")
    assert resp.status_code == 200
    orgs = resp.json()
    assert len(orgs) >= 2  # Seed has Acme FinTech and NovaCloud

    # 2. Create new organization
    new_org_payload = {
        "name": "SecOps Cyber Defense S.r.l.",
        "industry": "Cybersecurity MSSP",
        "contact_name": "Mario Rossi",
        "contact_email": "m.rossi@secops-defense.it",
        "target_scope": "10.10.0.0/16, vpn.secops-defense.it",
        "description": "Perimetro aziendale di test"
    }
    create_resp = client.post("/api/organizations", json=new_org_payload)
    assert create_resp.status_code == 201
    created_org = create_resp.json()
    org_id = created_org["id"]
    assert created_org["name"] == new_org_payload["name"]

    # 3. Update organization
    edit_resp = client.put(f"/api/organizations/{org_id}", json={
        "contact_name": "Mario Rossi (Head of SOC)"
    })
    assert edit_resp.status_code == 200
    assert edit_resp.json()["contact_name"] == "Mario Rossi (Head of SOC)"

    # 4. Get single organization
    get_resp = client.get(f"/api/organizations/{org_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == org_id

    # 5. Delete organization
    del_resp = client.delete(f"/api/organizations/{org_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True


def test_dashboard_stats():
    # Global stats
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_scans" in data
    assert "findings" in data
    assert "recent_scans" in data
    assert data["total_scans"] >= 1

    # Filtered by org_id
    orgs = client.get("/api/organizations").json()
    first_org_id = orgs[0]["id"]
    resp_filtered = client.get(f"/api/dashboard/stats?org_id={first_org_id}")
    assert resp_filtered.status_code == 200
    assert "total_scans" in resp_filtered.json()


def test_nmap_scripts_catalog():
    # All scripts
    resp = client.get("/api/nmap/scripts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] > 0
    assert len(data["presets"]) >= 5

    # Filter category
    resp_vuln = client.get("/api/nmap/scripts?category=vuln")
    assert resp_vuln.status_code == 200
    assert len(resp_vuln.json()["scripts"]) > 0

    # Search
    resp_search = client.get("/api/nmap/scripts?search=http")
    assert resp_search.status_code == 200
    assert len(resp_search.json()["scripts"]) > 0


def test_scan_lifecycle_and_loopback_scan():
    orgs = client.get("/api/organizations").json()
    org_id = orgs[0]["id"]

    # Launch native network scan on 127.0.0.1 (scanning standard common ports without restricting to closed ports)
    scan_payload = {
        "org_id": org_id,
        "name": "Localhost Self-Audit Verification",
        "targets": "127.0.0.1",
        "scan_profile": "quick_discovery",
        "engines": ["native_net"]
    }
    resp = client.post("/api/scans", json=scan_payload)
    assert resp.status_code == 201
    scan_data = resp.json()
    scan_id = scan_data["id"]

    # Wait for completion (fast native check)
    completed = False
    for _ in range(30):
        time.sleep(0.4)
        check_resp = client.get(f"/api/scans/{scan_id}")
        s = check_resp.json()
        if s["status"] in ["completed", "failed", "stopped"]:
            completed = True
            break

    assert completed is True
    details = client.get(f"/api/scans/{scan_id}").json()
    assert details["status"] == "completed"
    assert details["progress"] == 100
    assert "summary" in details
    assert "hosts" in details
    assert len(details["hosts"]) >= 1
    # Check open ports >= 3 on localhost (135, 445, 5040 etc.)
    open_ports = details["hosts"][0].get("ports", [])
    assert len(open_ports) >= 3, f"Expected at least 3 open ports on 127.0.0.1, found {len(open_ports)}: {open_ports}"

    # Check findings >= 3
    findings_resp = client.get(f"/api/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 3, f"Expected at least 3 findings on 127.0.0.1, found {len(findings)}"


def test_findings_management():
    # Use the demo scan findings
    scans = client.get("/api/scans").json()
    assert len(scans) > 0
    demo_scan_id = scans[-1]["id"]  # Scan 1 seeded

    findings_resp = client.get(f"/api/scans/{demo_scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) > 0

    target_finding = findings[0]
    finding_id = target_finding["id"]

    # Patch finding status to 'resolved'
    patch_resp = client.patch(f"/api/findings/{finding_id}", json={"status": "resolved"})
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "resolved"


def test_ai_analysis_endpoint():
    scans = client.get("/api/scans").json()
    scan_id = scans[-1]["id"]

    # Analyze whole scan
    resp = client.post("/api/ai/analyze", json={
        "scan_id": scan_id,
        "mode": "purple_team",
        "prompt": "Focalizzati sugli scenari di movimento laterale"
    })
    assert resp.status_code == 200
    ai_data = resp.json()
    assert "executive_summary" in ai_data
    assert "attack_paths" in ai_data
    assert "remediation_plan" in ai_data
    assert "markdown_report" in ai_data


def test_report_generation_and_view():
    scans = client.get("/api/scans").json()
    scan_id = scans[-1]["id"]

    # Generate white-label HTML report
    gen_resp = client.post("/api/reports/generate", json={
        "scan_id": scan_id,
        "classification": "STRETTAMENTE RISERVATO",
        "title": "Audit di Sicurezza Perimetrale Acme"
    })
    assert gen_resp.status_code == 201
    rep = gen_resp.json()
    rep_id = rep["id"]

    # List reports
    list_resp = client.get("/api/reports")
    assert list_resp.status_code == 200
    assert any(r["id"] == rep_id for r in list_resp.json())

    # View report HTML
    view_resp = client.get(f"/api/reports/{rep_id}/view")
    assert view_resp.status_code == 200
    assert "UrielScan White-Label Security Report" in view_resp.text
    assert "STRETTAMENTE RISERVATO" in view_resp.text

    # Download report
    dl_resp = client.get(f"/api/reports/{rep_id}/download")
    assert dl_resp.status_code == 200
    assert "text/html" in dl_resp.headers["content-type"]

    # Delete report
    del_resp = client.delete(f"/api/reports/{rep_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True


def test_schedules_crud_and_run_now():
    orgs = client.get("/api/organizations").json()
    org_id = orgs[0]["id"]

    # 1. Create schedule
    new_sched = {
        "org_id": org_id,
        "name": "Audit Notturno Automatizzato",
        "targets": "127.0.0.1",
        "frequency": "daily",
        "time_of_day": "03:30",
        "scan_config": {"profile": "quick_discovery", "engines": ["native_net"]},
        "enabled": True
    }
    create_resp = client.post("/api/schedules", json=new_sched)
    assert create_resp.status_code == 201
    sched_id = create_resp.json()["schedule_id"]

    # 2. Update schedule
    upd_resp = client.put(f"/api/schedules/{sched_id}", json={"time_of_day": "04:00"})
    assert upd_resp.status_code == 200

    # 3. Run now
    run_resp = client.post(f"/api/schedules/{sched_id}/run-now")
    assert run_resp.status_code == 200
    assert "scan_id" in run_resp.json()

    # 4. Delete schedule
    del_resp = client.delete(f"/api/schedules/{sched_id}")
    assert del_resp.status_code == 200


def test_auth_flow_and_2fa_totp():
    from backend.auth import clear_login_failures, hash_password
    from backend.database import update_user_password

    clear_login_failures("testclient:admin")

    # 1. Invalid credentials -> 401
    bad_login = raw_client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert bad_login.status_code == 401
    assert "Credenziali non valide" in bad_login.json()["detail"]

    # 2. Valid login without 2FA
    login_resp = raw_client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["requires_2fa"] is False
    assert "token" in login_data
    token = login_data["token"]
    auth_header = {"Authorization": f"Bearer {token}"}

    # 3. GET /api/auth/me
    me_resp = raw_client.get("/api/auth/me", headers=auth_header)
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["username"] == "admin"
    assert me_data["totp_enabled"] is False

    # 4. Setup 2FA
    setup_resp = raw_client.post("/api/auth/2fa/setup", headers=auth_header)
    assert setup_resp.status_code == 200
    setup_data = setup_resp.json()
    assert "secret" in setup_data
    assert "otpauth_uri" in setup_data
    assert setup_data["qr_svg"].startswith("data:image/svg+xml;base64,")
    secret = setup_data["secret"]

    # 5. Try invalid TOTP code
    bad_enable = raw_client.post("/api/auth/2fa/enable", json={"code": "000000"}, headers=auth_header)
    assert bad_enable.status_code == 400

    # 6. Enable with valid TOTP code
    real_code = generate_totp_code(secret)
    enable_resp = raw_client.post("/api/auth/2fa/enable", json={"code": real_code}, headers=auth_header)
    assert enable_resp.status_code == 200
    assert enable_resp.json()["totp_enabled"] is True

    # 7. Login now requires 2FA
    login_2fa_resp = raw_client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert login_2fa_resp.status_code == 200
    l2_data = login_2fa_resp.json()
    assert l2_data["requires_2fa"] is True
    assert "temp_token" in l2_data
    temp_token = l2_data["temp_token"]

    # Temp token MUST NOT work as a full session token (C-03)
    assert raw_client.get("/api/auth/me", headers={"Authorization": f"Bearer {temp_token}"}).status_code == 401
    assert raw_client.get("/api/settings", headers={"Authorization": f"Bearer {temp_token}"}).status_code == 401

    # 8. Verify with invalid code -> 401
    bad_verify = raw_client.post("/api/auth/verify-2fa", json={"temp_token": temp_token, "code": "999999"})
    assert bad_verify.status_code == 401

    # 9. Verify with valid TOTP code
    real_code_2 = generate_totp_code(secret)
    verify_resp = raw_client.post("/api/auth/verify-2fa", json={"temp_token": temp_token, "code": real_code_2})
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert "token" in v_data
    assert v_data["user"]["totp_enabled"] is True
    session_token_2fa = v_data["token"]
    auth_header_2fa = {"Authorization": f"Bearer {session_token_2fa}"}

    # 10. GET /api/auth/me confirms 2FA enabled
    me_resp_2 = raw_client.get("/api/auth/me", headers=auth_header_2fa)
    assert me_resp_2.status_code == 200
    assert me_resp_2.json()["totp_enabled"] is True

    # 11. Disable 2FA requires password AND TOTP code (C-03)
    assert raw_client.post("/api/auth/2fa/disable", json={}, headers=auth_header_2fa).status_code == 422
    assert raw_client.post(
        "/api/auth/2fa/disable",
        json={"password": "wrong", "code": generate_totp_code(secret)},
        headers=auth_header_2fa,
    ).status_code == 401

    disable_resp = raw_client.post(
        "/api/auth/2fa/disable",
        json={"password": "admin", "code": generate_totp_code(secret)},
        headers=auth_header_2fa,
    )
    assert disable_resp.status_code == 200
    assert disable_resp.json()["totp_enabled"] is False

    # 12. Password minimum length >= 8 enforced + change works
    short_pwd = raw_client.post("/api/auth/change-password", json={
        "current_password": "admin",
        "new_password": "short"
    }, headers=auth_header_2fa)
    assert short_pwd.status_code == 400

    pwd_resp = raw_client.post("/api/auth/change-password", json={
        "current_password": "admin",
        "new_password": "new_admin_password_123"
    }, headers=auth_header_2fa)
    assert pwd_resp.status_code == 200

    # Verify new password works
    new_login = raw_client.post("/api/auth/login", json={"username": "admin", "password": "new_admin_password_123"})
    assert new_login.status_code == 200

    # Restore password for remaining tests cleanly via DB helper
    h, s = hash_password("admin")
    update_user_password("admin", h, s)


def test_delete_single_scan():
    orgs = client.get("/api/organizations").json()
    org_id = orgs[0]["id"]

    # 1. Create a dummy scan to delete
    create_resp = client.post("/api/scans", json={
        "org_id": org_id,
        "name": "Scan To Be Deleted",
        "targets": "127.0.0.1",
        "scan_profile": "quick_discovery",
        "engines": ["native_net"]
    })
    assert create_resp.status_code == 201
    scan_id = create_resp.json()["id"]

    # Verify it exists in GET /api/scans
    scans_before = client.get("/api/scans").json()
    assert any(s["id"] == scan_id for s in scans_before)

    # 2. Delete it
    del_resp = client.delete(f"/api/scans/{scan_id}")
    assert del_resp.status_code == 200
    del_data = del_resp.json()
    assert del_data["success"] is True
    assert del_data["deleted_id"] == scan_id

    # 3. Verify it returns 404 and is not in list
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    scans_after = client.get("/api/scans").json()
    assert not any(s["id"] == scan_id for s in scans_after)


def test_system_reset_data_and_seed_demo():
    # 1. Call reset-data
    reset_resp = client.post("/api/system/reset-data?include_organizations=false")
    assert reset_resp.status_code == 200
    reset_data = reset_resp.json()
    assert reset_data["success"] is True

    # 2. Verify scans and findings are empty
    scans = client.get("/api/scans").json()
    assert len(scans) == 0

    findings = client.get("/api/findings").json()
    assert len(findings) == 0

    # 3. Call seed-demo to restore demo data
    seed_resp = client.post("/api/system/seed-demo")
    assert seed_resp.status_code == 200
    assert seed_resp.json()["success"] is True

    # 4. Verify data restored
    restored_scans = client.get("/api/scans").json()
    assert len(restored_scans) >= 1

    restored_findings = client.get("/api/findings").json()
    assert len(restored_findings) >= 1


def test_remote_agent_workflow():
    # 0. Get an organization ID
    orgs_resp = client.get("/api/organizations")
    assert orgs_resp.status_code == 200
    orgs = orgs_resp.json()
    assert len(orgs) > 0
    org_id = orgs[0]["id"]

    # 1. Download probe script endpoint check
    probe_script_resp = client.get("/api/agents/probe-script")
    assert probe_script_resp.status_code == 200
    assert len(probe_script_resp.content) > 0

    # 2. Create remote agent
    agent_name = "Edge-DMZ-Probe-01"
    create_resp = client.post("/api/agents", json={
        "org_id": org_id,
        "name": agent_name
    })
    assert create_resp.status_code == 201
    agent_data = create_resp.json()
    assert agent_data["name"] == agent_name
    assert "token" in agent_data
    assert "token_prefix" in agent_data
    agent_id = agent_data["id"]
    token = agent_data["token"]
    assert len(token) > 20

    # Verify agent listed in GET /api/agents
    agents_list_resp = client.get(f"/api/agents?org_id={org_id}")
    assert agents_list_resp.status_code == 200
    agents_list = agents_list_resp.json()
    assert any(a["id"] == agent_id for a in agents_list)

    headers = {"X-Agent-Token": token}

    # 3. Heartbeat from probe
    hb_payload = {
        "hostname": "probe-dmz-branch-01",
        "ip_address": "10.50.1.200",
        "os_info": "Linux 6.8.0-ubuntu (x86_64)",
        "engines": {
            "native": {"installed": True, "version": "1.0.0"},
            "nmap": {"installed": True, "path": "/usr/bin/nmap"},
            "nuclei": {"installed": False, "path": ""}
        },
        "version": "1.0.0"
    }
    hb_resp = client.post("/api/agent/heartbeat", json=hb_payload, headers=headers)
    assert hb_resp.status_code == 200
    assert hb_resp.json()["ok"] is True
    assert hb_resp.json()["agent_id"] == agent_id

    # Verify agent status updated to online
    agent_status_resp = client.get(f"/api/agents?org_id={org_id}")
    matching_agent = next(a for a in agent_status_resp.json() if a["id"] == agent_id)
    assert matching_agent["status"] == "online"
    assert matching_agent["hostname"] == "probe-dmz-branch-01"
    assert matching_agent["ip_address"] == "10.50.1.200"

    # 4. Check for job when queue is empty
    empty_job_resp = client.get("/api/agent/jobs/next", headers=headers)
    assert empty_job_resp.status_code == 200
    assert empty_job_resp.json()["job"] is None

    # 5. Create queued scan with agent_id
    scan_resp = client.post("/api/scans", json={
        "org_id": org_id,
        "name": "Audit Remoto DMZ Branch",
        "targets": "10.50.1.10, 10.50.1.25",
        "scan_profile": "standard",
        "engines": ["native", "nmap"],
        "agent_id": agent_id
    })
    assert scan_resp.status_code == 201
    created_scan = scan_resp.json()
    scan_id = created_scan["id"]
    assert created_scan["status"] == "queued"
    assert created_scan["agent_id"] == agent_id
    assert created_scan["agent_name"] == agent_name

    # 6. Probe polls for next job
    next_job_resp = client.get("/api/agent/jobs/next", headers=headers)
    assert next_job_resp.status_code == 200
    job = next_job_resp.json()["job"]
    assert job is not None
    assert job["id"] == scan_id
    assert job["status"] == "running"
    assert "Picked up by remote probe" in job["current_task"]

    # 7. Probe streams progress
    prog_payload = {
        "progress": 50,
        "current_task": "Port scan nativo completato, ispezione SSL...",
        "logs": [
            {"time": "12:00:01", "level": "INFO", "msg": "Job assegnato alla probe"},
            {"time": "12:00:15", "level": "INFO", "msg": "Trovate 3 porte aperte su 10.50.1.10"}
        ]
    }
    prog_resp = client.post(f"/api/agent/jobs/{scan_id}/progress", json=prog_payload, headers=headers)
    assert prog_resp.status_code == 200
    assert prog_resp.json()["ok"] is True
    assert prog_resp.json()["stop"] is False

    # Verify scan in DB reflects progress
    scan_check = client.get(f"/api/scans/{scan_id}").json()
    assert scan_check["progress"] == 50
    assert "ispezione SSL" in scan_check["current_task"]

    # 8. Probe uploads results
    results_payload = {
        "hosts": [
            {
                "ip": "10.50.1.10",
                "hostname": "gw-branch.local",
                "os": "Linux Ubuntu",
                "ports": [
                    {"port": 80, "protocol": "tcp", "service": "http", "state": "open"},
                    {"port": 443, "protocol": "tcp", "service": "https", "state": "open"},
                    {"port": 6379, "protocol": "tcp", "service": "redis", "state": "open"}
                ]
            }
        ],
        "logs": [
            {"time": "12:00:30", "level": "INFO", "msg": "Scansione terminata con successo."}
        ],
        "findings": [
            {
                "host": "10.50.1.10",
                "port": 6379,
                "protocol": "tcp",
                "service": "redis",
                "title": "Database Redis Esposto Senza Autenticazione",
                "severity": "critical",
                "cvss": 9.8,
                "cve_ids": "CVE-2018-11235",
                "cwe_id": "CWE-306",
                "source_engine": "native_probe",
                "description": "Accesso Redis non protetto da password",
                "evidence": "PONG redis_version:6.0.9",
                "remediation": "Configurare requirepass in redis.conf",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1552 - Unsecured Credentials",
                "ai_insight": "Accesso immediato alla cache",
                "status": "open"
            },
            {
                "host": "10.50.1.10",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "title": "Header Strict-Transport-Security (HSTS) Assente",
                "severity": "medium",
                "cvss": 5.0,
                "cve_ids": "",
                "cwe_id": "CWE-693",
                "source_engine": "native_probe",
                "description": "Mancanza di HSTS su endpoint HTTPS",
                "evidence": "Strict-Transport-Security mancante",
                "remediation": "Aggiungere header HSTS nel reverse proxy",
                "mitre_tactic": "Impact",
                "mitre_technique": "T1498 - Network Denial of Service",
                "ai_insight": "Possibile downgrade HTTP",
                "status": "open"
            }
        ]
    }
    results_resp = client.post(f"/api/agent/jobs/{scan_id}/results", json=results_payload, headers=headers)
    assert results_resp.status_code == 200
    res_data = results_resp.json()
    assert res_data["ok"] is True
    assert res_data["findings_count"] == 2
    assert res_data["summary"]["critical"] == 1
    assert res_data["summary"]["medium"] == 1
    assert res_data["summary"]["total"] == 2

    # 9. Verify scan completed in DB and findings stored
    final_scan = client.get(f"/api/scans/{scan_id}").json()
    assert final_scan["status"] == "completed"
    assert final_scan["progress"] == 100
    assert final_scan["summary"]["critical"] == 1
    assert len(final_scan["hosts"]) == 1

    findings_resp = client.get(f"/api/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings_list = findings_resp.json()
    assert len(findings_list) == 2
    redis_finding = next(f for f in findings_list if f["port"] == 6379)
    assert redis_finding["severity"] == "critical"
    assert redis_finding["source_engine"] == "native_probe"

    # 10. Test stopping a queued scan
    queued_scan_resp = client.post("/api/scans", json={
        "org_id": org_id,
        "name": "Scan To Be Stopped While Queued",
        "targets": "10.50.1.99",
        "agent_id": agent_id
    })
    assert queued_scan_resp.status_code == 201
    q_scan_id = queued_scan_resp.json()["id"]
    assert queued_scan_resp.json()["status"] == "queued"

    stop_resp = client.post(f"/api/scans/{q_scan_id}/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["success"] is True
    stopped_scan = client.get(f"/api/scans/{q_scan_id}").json()
    assert stopped_scan["status"] == "stopped"

    # 11. Delete agent
    del_agent_resp = client.delete(f"/api/agents/{agent_id}")
    assert del_agent_resp.status_code == 200
    assert del_agent_resp.json()["success"] is True

    # Verify agent no longer exists
    agents_after = client.get(f"/api/agents?org_id={org_id}").json()
    assert not any(a["id"] == agent_id for a in agents_after)


def test_security_audit_regressions():
    from backend.export_engine import export_scan_results_csv, generate_docx_report
    from backend.scanners.nmap_engine import _is_valid_nmap_target
    import zipfile, io

    # C-01: Unauthenticated access strictly rejected on protected routes
    for path in ("/api/settings", "/api/organizations", "/api/scans", "/api/auth/me", "/api/agents"):
        assert raw_client.get(path).status_code == 401

    # C-02: Path traversal via encoded ../ blocked (never 200)
    trav_resp = raw_client.get("/..%2F..%2Fbackend%2Fauth.py")
    assert trav_resp.status_code == 404

    # C-05: Nmap target flag injection rejected
    assert _is_valid_nmap_target("--script=evil.nse") is False
    assert _is_valid_nmap_target("-oN") is False
    assert _is_valid_nmap_target("::1") is True
    assert _is_valid_nmap_target("192.168.1.0/24") is True

    # C-07: HTML Report escapes XSS payloads in findings/banners
    from backend.database import get_db_connection
    scans = client.get("/api/scans").json()
    sid = scans[0]["id"]
    org_id = scans[0]["org_id"]
    conn = get_db_connection()
    with conn:
        conn.execute(
            """
            INSERT INTO findings (scan_id, org_id, host, port, protocol, service, title, severity, cvss, source_engine, description, evidence, created_at)
            VALUES (?, ?, '10.0.0.1', 80, 'tcp', 'http', '<script>alert(1)</script>', 'high', 7.5, 'native', 'Desc', '</code></pre><script>evil()</script>', '2026-01-01T00:00:00Z');
            """,
            (sid, org_id),
        )
    conn.close()
    rep = client.post("/api/reports/generate", json={"scan_id": sid, "title": "<img src=x onerror=alert(1)>"}).json()
    view_html = client.get(f"/api/reports/{rep['id']}/view").text
    assert "<script>alert(1)</script>" not in view_html
    assert "<script>evil()</script>" not in view_html
    assert "&lt;script&gt;evil()&lt;/script&gt;" in view_html
    client.delete(f"/api/reports/{rep['id']}")

    # C-08: Unknown Origin is NOT reflected with Allow-Origin
    cors_resp = raw_client.get("/api/system/status", headers={"Origin": "https://evil.example"})
    assert cors_resp.headers.get("access-control-allow-origin") != "https://evil.example"

    # H-07: ai_api_key is never returned in plaintext from GET /api/settings
    client.put("/api/settings", json={"ai_provider": "openai", "ai_api_key": "sk-secret-test-value-9999"})
    s = client.get("/api/settings").json()
    assert s["ai_api_key"] == ""
    assert s["ai_api_key_configured"] is True
    assert s["ai_api_key_masked"] == "sk-s...9999"

    # H-08 & M-12: CSV formula injection neutralized & DOCX strips control chars
    csv_bytes = export_scan_results_csv(
        [{"id": 1, "org_id": 1, "name": "Test"}],
        [{"id": 1, "org_id": 1, "scan_id": 1, "host": "1.2.3.4", "title": "=HYPERLINK(\"http://evil\",\"click\")", "evidence": "bad\x00\x01banner"}],
        {1: {"name": "Org"}},
    ).decode("utf-8")
    assert "'=HYPERLINK(" in csv_bytes

    docx_bytes = generate_docx_report(
        report_title="Audit",
        classification="CONFIDENTIAL",
        mssp_profile={"company_name": "Sec"},
        client_org={"name": "Org"},
        targets="1.2.3.4",
        hosts=[],
        findings=[{"host": "1.2.3.4", "port": 80, "severity": "low", "cvss": 2.0, "title": "Ctrl\x00Test", "source_engine": "native", "evidence": "abc\x02\x0bdef"}],
    )
    with zipfile.ZipFile(io.BytesIO(docx_bytes)) as zf:
        doc_xml = zf.read("word/document.xml").decode("utf-8")
        assert "\x00" not in doc_xml
        assert "\x02" not in doc_xml

    # H-09: SSRF blocking on /api/ai/test
    ssrf_resp = client.post("/api/ai/test", json={"ai_provider": "ollama", "ai_base_url": "http://169.254.169.254/latest/meta-data/"})
    assert ssrf_resp.status_code == 400

    # M-16: Logout invalidates session token server-side
    temp_login = raw_client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    tok = temp_login.json()["token"]
    assert raw_client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert raw_client.post("/api/auth/logout", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert raw_client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401



