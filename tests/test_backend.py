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

    # Explicit removal via DELETE /api/settings/ai-api-key and PUT clear_ai_api_key
    del_key = client.delete("/api/settings/ai-api-key")
    assert del_key.status_code == 200
    assert del_key.json()["ai_api_key_configured"] is False
    assert client.get("/api/settings").json()["ai_api_key_masked"] == ""

    client.put("/api/settings", json={"ai_api_key": "sk-secret-temp-12345"})
    assert client.get("/api/settings").json()["ai_api_key_configured"] is True
    clr = client.put("/api/settings", json={"clear_ai_api_key": True})
    assert clr.status_code == 200
    assert clr.json()["ai_api_key_configured"] is False

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


def test_zap_engine_and_cross_engine_deduplication():
    from backend.scanners.zap_engine import parse_zap_alerts, parse_zap_xml
    from backend.scanners.deduplicator import consolidate_findings

    # 1. /api/system/status exposes zap engine metadata
    status_data = raw_client.get("/api/system/status").json()
    assert "zap" in status_data["engines"]

    # 2. Parse ZAP API alerts & XML quickout cleanly
    api_alerts = parse_zap_alerts([
        {
            "alert": "SQL Injection",
            "riskcode": "3",
            "confidence": "3",
            "url": "https://app.example.com:443/login",
            "param": "user",
            "cweid": "89",
            "description": "<p>Possible SQL injection</p>",
            "solution": "<p>Use prepared statements</p>",
            "evidence": "SQL syntax error",
        }
    ])
    assert len(api_alerts) == 1
    assert api_alerts[0]["severity"] == "critical"
    assert api_alerts[0]["cwe_id"] == "CWE-89"
    assert api_alerts[0]["source_engine"] == "zap"
    assert "<p>" not in api_alerts[0]["description"]

    sample_xml = """<?xml version="1.0"?>
    <OWASPZAPReport>
      <site name="https://app.example.com" host="app.example.com" port="443">
        <alerts>
          <alertitem>
            <alert>Strict-Transport-Security Header Not Set</alert>
            <riskcode>1</riskcode>
            <confidence>2</confidence>
            <cweid>319</cweid>
            <desc>&lt;p&gt;HSTS header missing&lt;/p&gt;</desc>
            <solution>&lt;p&gt;Enable HSTS&lt;/p&gt;</solution>
            <instances><instance><uri>https://app.example.com/</uri><evidence>No HSTS</evidence></instance></instances>
          </alertitem>
        </alerts>
      </site>
    </OWASPZAPReport>"""
    xml_findings = parse_zap_xml(sample_xml)
    assert len(xml_findings) == 1
    assert xml_findings[0]["host"] == "app.example.com"
    assert xml_findings[0]["port"] == 443

    # 3. Cross-engine deduplication (ZAP + Nuclei + Nmap + Native Web) + Severity Ordering
    raw_findings = [
        {
            "host": "app.example.com", "port": 443, "severity": "info", "cvss": 0.0,
            "title": "Apache HTTP Server Exposed", "source_engine": "nmap", "evidence": "Apache/2.4.49"
        },
        {
            "host": "https://app.example.com:443", "port": 443, "severity": "low", "cvss": 3.1,
            "title": "Header Strict-Transport-Security (HSTS) Assente", "source_engine": "native_web", "evidence": "Missing HSTS header"
        },
        *xml_findings,  # ZAP also detected HSTS missing
        {
            "host": "app.example.com", "port": 443, "severity": "high", "cvss": 7.5,
            "cve_ids": "CVE-2021-41773", "title": "Apache Path Traversal CVE-2021-41773",
            "source_engine": "nuclei", "evidence": "GET /cgi-bin/.%2e/etc/passwd"
        },
        {
            "host": "app.example.com", "port": 443, "severity": "critical", "cvss": 9.8,
            "cve_ids": "CVE-2021-41773", "title": "http-vuln-cve2021-41773",
            "source_engine": "nmap", "evidence": "Nmap NSE vulnerable"
        },
        *api_alerts,  # ZAP SQLi critical
        {
            "host": "app.example.com", "port": 443, "severity": "high", "cvss": 8.0,
            "title": "SQL Injection Probe Detected", "cwe_id": "CWE-89",
            "source_engine": "native_web", "evidence": "Error near syntax"
        },
    ]

    consolidated = consolidate_findings(raw_findings)
    # 7 inputs -> 4 canonical findings (SQLi merged, CVE-2021-41773 merged, HSTS merged, Banner info)
    assert len(consolidated) == 4
    sevs = [f["severity"] for f in consolidated]
    assert sevs == ["critical", "critical", "low", "info"]

    sqli = next(f for f in consolidated if f.get("cwe_id") == "CWE-89")
    assert sqli["source_engine"] == "zap+native_web"
    assert "[ZAP]" in sqli["evidence"] and "[NATIVE_WEB]" in sqli["evidence"]

    hsts = next(f for f in consolidated if "Strict-Transport-Security" in f["title"])
    assert hsts["source_engine"] == "zap+native_web"

    cve = next(f for f in consolidated if "CVE-2021-41773" in f.get("cve_ids", ""))
    assert cve["source_engine"] == "nuclei+nmap"
    assert cve["severity"] == "critical"


def test_reports_logo_and_severity_ordering():
    from backend.export_engine import (
        export_scan_results_csv,
        export_scan_results_txt,
        generate_pdf_document,
        generate_docx_report,
    )
    import zipfile, io, xml.etree.ElementTree as ET

    shuffled_findings = [
        {"id": 1, "org_id": 1, "scan_id": 1, "host": "10.0.0.5", "port": 80, "severity": "info", "cvss": 0.0, "title": "ITEM_INFO", "source_engine": "native_net"},
        {"id": 2, "org_id": 1, "scan_id": 1, "host": "10.0.0.5", "port": 443, "severity": "medium", "cvss": 5.3, "title": "ITEM_MEDIUM", "source_engine": "zap"},
        {"id": 3, "org_id": 1, "scan_id": 1, "host": "10.0.0.5", "port": 8080, "severity": "critical", "cvss": 9.8, "title": "ITEM_CRITICAL", "source_engine": "nuclei"},
        {"id": 4, "org_id": 1, "scan_id": 1, "host": "10.0.0.5", "port": 22, "severity": "low", "cvss": 3.1, "title": "ITEM_LOW", "source_engine": "nmap"},
        {"id": 5, "org_id": 1, "scan_id": 1, "host": "10.0.0.5", "port": 445, "severity": "high", "cvss": 7.8, "title": "ITEM_HIGH", "source_engine": "nmap"},
    ]
    scans_meta = [{"id": 1, "org_id": 1, "name": "Order Test"}]
    org_map = {1: {"name": "Test Org"}}

    def assert_order(txt: str):
        positions = [txt.index(tag) for tag in ("ITEM_CRITICAL", "ITEM_HIGH", "ITEM_MEDIUM", "ITEM_LOW", "ITEM_INFO")]
        assert positions == sorted(positions), f"Incorrect severity order: {positions}"

    csv_txt = export_scan_results_csv(scans_meta, shuffled_findings, org_map).decode("utf-8")
    assert_order(csv_txt)

    txt_out = export_scan_results_txt("Order Test", "10.0.0.5", [], shuffled_findings, org_map).decode("utf-8")
    assert_order(txt_out)

    pdf_bytes = generate_pdf_document(
        report_title="Order PDF", classification="CONFIDENTIAL", mssp_profile={"company_name": "Uriel"},
        client_org={"name": "Test Org"}, targets="10.0.0.5", hosts=[], findings=shuffled_findings, include_ai=False
    )
    assert pdf_bytes.startswith(b"%PDF") and len(pdf_bytes) > 1500

    docx_bytes = generate_docx_report(
        report_title="Order DOCX", classification="CONFIDENTIAL", mssp_profile={"company_name": "Uriel"},
        client_org={"name": "Test Org"}, targets="10.0.0.5", hosts=[], findings=shuffled_findings, include_ai=False
    )
    with zipfile.ZipFile(io.BytesIO(docx_bytes)) as zf:
        names = zf.namelist()
        assert "word/media/urielscan_logo.png" in names
        doc_xml = zf.read("word/document.xml").decode("utf-8")
        assert "rIdLogo" in doc_xml
        assert_order(doc_xml)
        ET.fromstring(doc_xml.encode("utf-8"))  # Valid XML namespaces & structure

    # When organization HAS a custom PNG logo, PDF/DOCX must use org_logo and NOT UrielScan logo
    import base64 as _b64
    from backend.database import get_db_connection
    tiny_png_b64 = "data:image/png;base64," + _b64.b64encode(
        _b64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
    ).decode("ascii")
    org_pdf = generate_pdf_document(
        report_title="Org PDF", classification="CONFIDENTIAL", mssp_profile={"company_name": "Uriel"},
        client_org={"name": "Custom Logo Org", "logo_data": tiny_png_b64}, targets="10.0.0.5", hosts=[], findings=shuffled_findings, include_ai=False
    )
    assert org_pdf.startswith(b"%PDF")
    org_docx = generate_docx_report(
        report_title="Org DOCX", classification="CONFIDENTIAL", mssp_profile={"company_name": "Uriel"},
        client_org={"name": "Custom Logo Org", "logo_data": tiny_png_b64}, targets="10.0.0.5", hosts=[], findings=shuffled_findings, include_ai=False
    )
    with zipfile.ZipFile(io.BytesIO(org_docx)) as zf:
        org_names = zf.namelist()
        assert "word/media/org_logo.png" in org_names
        assert "word/media/urielscan_logo.png" not in org_names
        ET.fromstring(zf.read("word/document.xml"))

    # HTML report via API: uses Org logo when present, falls back to UrielScan PNG ONLY when org has no logo
    scans = client.get("/api/scans").json()
    rep_with_org_logo = client.post("/api/reports/generate", json={"scan_id": scans[0]["id"], "title": "Org Logo Check"}).json()
    html_org = client.get(f"/api/reports/{rep_with_org_logo['id']}/view").text
    assert 'alt="UrielScan"' not in html_org
    client.delete(f"/api/reports/{rep_with_org_logo['id']}")

    no_logo_org = client.post("/api/organizations", json={"name": "NoLogo Corp", "industry": "Tech", "target_scope": "10.0.0.1"}).json()
    conn = get_db_connection()
    with conn:
        cur = conn.execute(
            "INSERT INTO scans (org_id, name, targets, scan_profile, engines_json, status, progress, started_at) VALUES (?, ?, ?, ?, ?, 'completed', 100, '2026-11-19T00:00:00Z');",
            (no_logo_org["id"], "NoLogo Scan", "10.0.0.1", "standard", '["native"]'),
        )
        nologo_scan_id = cur.lastrowid
    conn.close()
    rep_fallback = client.post("/api/reports/generate", json={"scan_id": nologo_scan_id, "title": "Fallback Logo Check"}).json()
    html_fallback = client.get(f"/api/reports/{rep_fallback['id']}/view").text
    assert "data:image/png;base64," in html_fallback
    assert 'alt="UrielScan"' in html_fallback
    client.delete(f"/api/reports/{rep_fallback['id']}")
    client.delete(f"/api/scans/{nologo_scan_id}")
    client.delete(f"/api/organizations/{no_logo_org['id']}")


def test_saved_pdf_docx_reports_and_ai_reports_crud():
    scans = client.get("/api/scans").json()
    assert len(scans) >= 1
    sid = scans[0]["id"]

    # 1. AI analysis persists saved report in ai_reports table
    ai_resp = client.post("/api/ai/analyze", json={"scan_id": sid, "mode": "purple", "lang": "en"})
    assert ai_resp.status_code == 200
    ai_json = ai_resp.json()
    saved_ai = ai_json.get("saved_report")
    assert saved_ai and saved_ai["id"].startswith("AIRPT-")

    ai_list = client.get("/api/ai/reports").json()
    assert any(r["id"] == saved_ai["id"] for r in ai_list)

    del_ai = client.delete(f"/api/ai/reports/{saved_ai['id']}")
    assert del_ai.status_code == 200
    assert not any(r["id"] == saved_ai["id"] for r in client.get("/api/ai/reports").json())

    # 2. Exported PDF and DOCX reports persist into reports archive with proper MIME types
    created_ids = []
    for fmt, expected_mime in [
        ("pdf", "application/pdf"),
        ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ]:
        exp_resp = client.post("/api/reports/export", json={
            "scan_id": sid,
            "format": fmt,
            "report_title": f"Saved {fmt.upper()} Check",
            "classification": "CONFIDENTIAL",
            "executive_notes": "Verification test",
            "include_ai": False,
            "include_evidence": False,
            "include_host_topology": False,
            "lang": "en",
        })
        assert exp_resp.status_code == 200
        rid = exp_resp.headers.get("X-Report-Id")
        assert rid and rid.startswith("RPT-")
        created_ids.append(rid)

        rep_list = client.get("/api/reports").json()
        matched = next((r for r in rep_list if r["id"] == rid), None)
        assert matched is not None
        assert matched["summary"]["format"] == fmt

        view_resp = client.get(f"/api/reports/{rid}/view")
        assert view_resp.status_code == 200
        assert expected_mime in view_resp.headers.get("content-type", "")

        dl_resp = client.get(f"/api/reports/{rid}/download")
        assert dl_resp.status_code == 200
        assert expected_mime in dl_resp.headers.get("content-type", "")

    for rid in created_ids:
        assert client.delete(f"/api/reports/{rid}").status_code == 200


def test_nat_loopback_guard(monkeypatch):
    from backend.scanners import nat_guard

    monkeypatch.setattr(nat_guard, "get_egress_public_ip", lambda *a, **kw: "198.51.100.42")

    check_hit = client.get("/api/network/nat-check?targets=198.51.100.42,10.0.0.10").json()
    assert check_hit["egress_public_ip"] == "198.51.100.42"
    assert check_hit["has_nat_loopback"] is True
    assert "198.51.100.42" in check_hit["loopback_targets"]

    check_miss = client.get("/api/network/nat-check?targets=10.0.0.10").json()
    assert check_miss["has_nat_loopback"] is False

    # Hairpin false-positive suppression against external WAN InternetDB truth ([443] only)
    hosts = [
        {
            "ip": "198.51.100.42",
            "hostname": "198.51.100.42",
            "ports": [
                {"port": 53, "protocol": "tcp", "state": "open", "service": "domain"},
                {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
                {"port": 8080, "protocol": "tcp", "state": "open", "service": "http-proxy"},
            ],
        }
    ]
    raw_findings = [
        {"host": "198.51.100.42", "port": 53, "severity": "medium", "title": "Router Internal DNS Exposed"},
        {"host": "198.51.100.42", "port": 80, "severity": "high", "title": "Router LAN HTTP Admin Panel"},
        {"host": "198.51.100.42", "port": 8080, "severity": "medium", "title": "Router Proxy Hairpin"},
        {"host": "198.51.100.42", "port": 443, "severity": "medium", "title": "Real Public HTTPS Service"},
    ]
    filtered_hosts, filtered_findings, stats = nat_guard.filter_loopback_artifacts(
        loopback_details=check_hit["details"],
        all_hosts=hosts,
        all_findings=raw_findings,
        wan_info={"ok": True, "ip": "198.51.100.42", "ports": [443], "vulns": []},
        egress_ip="198.51.100.42",
        locale="en",
    )
    assert stats["suppressed_ports"] == 3
    assert stats["suppressed_findings"] == 3
    assert [p["port"] for p in filtered_hosts[0]["ports"]] == [443]
    titles = [f["title"] for f in filtered_findings]
    assert "Real Public HTTPS Service" in titles
    assert "Router LAN HTTP Admin Panel" not in titles
    assert any(f.get("source_engine") == "nat_guard" for f in filtered_findings)


def test_probe_self_contained_installers():
    import base64, json, re

    orgs = client.get("/api/organizations").json()
    org_id = orgs[0]["id"]
    created = client.post("/api/agents", json={"org_id": org_id, "name": "Edge Installer Probe"}).json()
    aid = created["id"]
    token = created["token"]

    try:
        # 1. Windows self-contained .msi
        msi_resp = client.post(
            f"/api/agents/{aid}/installer",
            json={
                "platform": "windows_msi",
                "server_url": "https://uriel.example.test:8443",
                "token": token,
            },
        )
        assert msi_resp.status_code == 200
        msi_bytes = msi_resp.content
        assert msi_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), "Invalid OLE2 MSI header"
        s_idx = msi_bytes.index(b"URIELSCAN_PROBE_CFG_START:") + len(b"URIELSCAN_PROBE_CFG_START:")
        e_idx = msi_bytes.index(b":URIELSCAN_PROBE_CFG_END", s_idx)
        embedded_cfg = json.loads(msi_bytes[s_idx:e_idx].decode("utf-8").strip())
        assert embedded_cfg["token"] == token
        assert embedded_cfg["server_url"] == "https://uriel.example.test:8443"
        # Regression check: Type 3090 deferred EXE custom action must evaluate properties directly (never [CustomActionData])
        assert b"[CustomActionData]" not in msi_bytes
        assert b"msi=[OriginalDatabase];db=[DATABASE];dir=[INSTALLDIR];" in msi_bytes

        # 2. Linux self-contained .sh (also testing token rotation when token omitted)
        sh_resp = client.post(
            f"/api/agents/{aid}/installer",
            json={
                "platform": "linux_sh",
                "server_url": "https://uriel.example.test:8443",
            },
        )
        assert sh_resp.status_code == 200
        sh_text = sh_resp.content.decode("utf-8")
        assert sh_text.startswith("#!/usr/bin/env bash")
        assert "python-build-standalone" in sh_text
        m = re.search(r"probe_config\.json.*?\n([A-Za-z0-9+/=\n]+)\n__URIEL_PROBE_CFG__", sh_text, re.DOTALL)
        assert m is not None
        decoded_cfg = json.loads(base64.b64decode(m.group(1).strip()).decode("utf-8"))
        assert decoded_cfg["server_url"] == "https://uriel.example.test:8443"
        assert decoded_cfg["token"] and decoded_cfg["token"] != token  # rotated freshly

        # 3. Signed direct installer URL + Silent RMM PowerShell / Bash commands
        win_link = client.post(
            f"/api/agents/{aid}/installer-link",
            json={
                "platform": "windows_msi",
                "server_url": "https://uriel.example.test:8443",
                "insecure": True,
            },
        ).json()
        assert win_link["filename"].endswith(".msi")
        assert win_link["download_url"].startswith("https://uriel.example.test:8443/api/agent/installer/")
        assert "/qn /norestart" in win_link["silent_command"]
        assert "ServerCertificateValidationCallback" in win_link["silent_command"]

        # Unauthenticated target fetch via signed ticket works without admin Bearer header
        dl_win = raw_client.get(win_link["local_download_path"])
        assert dl_win.status_code == 200
        assert dl_win.content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")

        lin_link = client.post(
            f"/api/agents/{aid}/installer-link",
            json={
                "platform": "linux_sh",
                "server_url": "https://uriel.example.test:8443",
                "insecure": False,
            },
        ).json()
        assert lin_link["filename"].endswith(".sh")
        assert "curl -fsSL " in lin_link["silent_command"]
        assert "sudo bash" in lin_link["silent_command"]
        dl_lin = raw_client.get(lin_link["local_download_path"])
        assert dl_lin.status_code == 200
        assert dl_lin.content.startswith(b"#!/usr/bin/env bash")
    finally:
        client.delete(f"/api/agents/{aid}")

    # Revoking agent immediately invalidates direct installer tickets
    assert raw_client.get(win_link["local_download_path"]).status_code == 404
    assert raw_client.get(lin_link["local_download_path"]).status_code == 404


def test_engine_auto_bootstrap_and_install_endpoints(tmp_path, monkeypatch):
    import io, zipfile, platform
    from backend import main as main_mod
    from backend.scanners import nmap_engine, zap_engine, archive_utils

    # 1. /api/system/status exposes bootstrap structure
    status_data = raw_client.get("/api/system/status").json()
    assert "bootstrap" in status_data
    assert "engines" in status_data["bootstrap"]
    for eng in ("nmap", "nuclei", "zap", "tor"):
        assert eng in status_data["bootstrap"]["engines"]

    # 2. Portable detection for Nmap & OWASP ZAP inside temporary BIN_DIR
    fake_bin = tmp_path / "bin"
    exe_name = "nmap.exe" if platform.system() == "Windows" else "nmap"
    portable_nmap_dir = fake_bin / "nmap" / "nmap-7.95"
    (portable_nmap_dir / "scripts").mkdir(parents=True)
    (portable_nmap_dir / exe_name).write_text("", encoding="utf-8")
    (portable_nmap_dir / "scripts" / "http-title.nse").write_text("", encoding="utf-8")

    monkeypatch.setattr(nmap_engine, "BIN_DIR", fake_bin)
    monkeypatch.setattr(nmap_engine, "KNOWN_NMAP_PATHS", [])
    monkeypatch.setattr(nmap_engine.shutil, "which", lambda *a, **kw: None)
    nmap_det = nmap_engine.detect_nmap()
    assert nmap_det["installed"] is True
    assert nmap_det["nse_count"] == 1
    assert "nmap-7.95" in nmap_det["path"]

    zap_script = "zap.bat" if platform.system() == "Windows" else "zap.sh"
    portable_zap_dir = fake_bin / "zap" / "ZAP_2.17.0"
    (portable_zap_dir / "jre").mkdir(parents=True)
    (portable_zap_dir / zap_script).write_text("", encoding="utf-8")
    (portable_zap_dir / "zap-2.17.0.jar").write_text("", encoding="utf-8")

    monkeypatch.setattr(zap_engine, "BIN_DIR", fake_bin)
    monkeypatch.setattr(zap_engine, "KNOWN_ZAP_PATHS", [])
    monkeypatch.setattr(zap_engine, "_zap_api_request", lambda *a, **kw: None)
    monkeypatch.setattr(zap_engine.shutil, "which", lambda *a, **kw: None)
    zap_det = zap_engine.detect_zap()
    assert zap_det["installed"] is True
    assert zap_det["mode"] == "cli"
    assert "2.17.0" in zap_det["version"]

    # 3. Install endpoints invoke backend installers cleanly
    async def fake_install_nmap():
        return {"success": True, "version": "7.95", "path": "bin/nmap", "nse_count": 600, "message": "ok nmap"}

    async def fake_install_zap():
        return {"success": True, "version": "2.17.0", "path": "bin/zap", "message": "ok zap"}

    monkeypatch.setattr(main_mod, "install_nmap", fake_install_nmap)
    monkeypatch.setattr(main_mod, "install_zap", fake_install_zap)
    monkeypatch.setattr(main_mod, "start_engine_bootstrap_background", lambda **kw: True)

    assert client.post("/api/system/install-nmap").json()["success"] is True
    assert client.post("/api/system/install-zap").json()["success"] is True
    assert client.post("/api/system/install-all-engines").json()["started"] is True

    # 4. Zip-Slip protection in archive_utils
    evil_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil_zip, "w") as zf:
        zf.writestr("../../outside.txt", "pwned")
    try:
        archive_utils.safe_extract_zip(evil_zip, tmp_path / "extract")
        assert False, "Expected ValueError on Zip-Slip path"
    except ValueError as exc:
        assert "Unsafe ZIP path" in str(exc)

    # 5. First-time installers, silent launchers, stop script & LF line endings on shell scripts
    for fname in ("install.bat", "install.ps1", "install.sh", "start.bat", "start.sh", "stop.bat"):
        fpath = ROOT_DIR / fname
        assert fpath.is_file(), f"Missing {fname}"
    for sh_name in ("install.sh", "start.sh"):
        raw_bytes = (ROOT_DIR / sh_name).read_bytes()
        assert b"\r\n" not in raw_bytes, f"{sh_name} must use pure Unix LF line endings"

    # 6. run.py handles windowless pythonw.exe streams (sys.stdout/stderr is None)
    import run as run_mod
    fake_log = tmp_path / "windowless_urielscan.log"
    orig_stdout, orig_stderr = sys.stdout, sys.stderr
    try:
        monkeypatch.setattr(run_mod, "LOG_FILE", fake_log)
        sys.stdout = None
        sys.stderr = None
        run_mod._configure_windowless_streams()
        assert sys.stdout is not None and sys.stderr is not None
        print("windowless stream check ok")
    finally:
        for stream in (sys.stdout, sys.stderr):
            if stream not in (orig_stdout, orig_stderr) and hasattr(stream, "close"):
                try:
                    stream.close()
                except Exception:
                    pass
        sys.stdout = orig_stdout
        sys.stderr = orig_stderr
    assert "windowless stream check ok" in fake_log.read_text(encoding="utf-8")








def test_tor_onion_routing_and_socks5_tunnel(monkeypatch):
    import asyncio
    import struct
    import backend.main as main_mod
    from backend.scanners import tor_engine, native_engine, nmap_engine

    # 1. URL validation & socks5 -> socks5h upgrade (remote DNS resolution)
    assert tor_engine.validate_proxy_url("socks5://127.0.0.1:9050") == "socks5://127.0.0.1:9050"
    assert tor_engine.to_httpx_proxy_url("socks5://127.0.0.1:9050") == "socks5h://127.0.0.1:9050"
    assert tor_engine.validate_proxy_url("socks5h://user:p%40ss@10.0.0.5:1080") == "socks5h://user:p%40ss@10.0.0.5:1080"
    assert tor_engine.validate_proxy_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    for bad in ("ftp://127.0.0.1:21", "socks5://:1080", "http://127.0.0.1:99999", "socks5://127.0.0.1:9050\r\n"):
        with pytest.raises(ValueError):
            tor_engine.validate_proxy_url(bad)

    # 2. Local RFC 1928 SOCKS5 server + fake .onion HTTP target tunnel verification
    recorded_atyp = []
    recorded_hosts = []

    async def _run_socks5_e2e():
        async def handle_target(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                await asyncio.wait_for(reader.read(1024), timeout=2.0)
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Server: OnionTestServer/1.0\r\n"
                    b"Content-Length: 2\r\n\r\nOK"
                )
                await writer.drain()
            finally:
                writer.close()

        target_srv = await asyncio.start_server(handle_target, "127.0.0.1", 0)
        target_port = target_srv.sockets[0].getsockname()[1]

        async def handle_socks5(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            upstream_writer = None
            try:
                ver_n = await reader.readexactly(2)
                assert ver_n[0] == 5
                await reader.readexactly(ver_n[1])
                writer.write(b"\x05\x00")
                await writer.drain()

                req_hdr = await reader.readexactly(4)
                atyp = req_hdr[3]
                recorded_atyp.append(atyp)
                if atyp == 0x03:
                    dlen = (await reader.readexactly(1))[0]
                    host_b = await reader.readexactly(dlen)
                    recorded_hosts.append(host_b.decode("ascii", errors="replace"))
                elif atyp == 0x01:
                    await reader.readexactly(4)
                dst_port = struct.unpack("!H", await reader.readexactly(2))[0]

                up_r, upstream_writer = await asyncio.open_connection("127.0.0.1", dst_port)
                writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", dst_port))
                await writer.drain()

                async def _pipe(src, dst):
                    try:
                        while True:
                            chunk = await src.read(4096)
                            if not chunk:
                                break
                            dst.write(chunk)
                            await dst.drain()
                    except Exception:
                        pass

                await asyncio.gather(_pipe(reader, upstream_writer), _pipe(up_r, writer))
            finally:
                writer.close()
                if upstream_writer:
                    upstream_writer.close()

        socks_srv = await asyncio.start_server(handle_socks5, "127.0.0.1", 0)
        socks_port = socks_srv.sockets[0].getsockname()[1]

        try:
            proxy_url = f"socks5h://127.0.0.1:{socks_port}"
            hosts, findings = await native_engine.run_native_net_scan(
                "fake-hidden-service.onion",
                ports=[target_port],
                proxy_url=proxy_url,
            )
            assert len(hosts) == 1
            assert hosts[0]["ports"][0]["port"] == target_port
            assert 0x03 in recorded_atyp
            assert "fake-hidden-service.onion" in recorded_hosts

            web_findings = await native_engine.run_native_web_scan(
                f"http://127.0.0.1:{target_port}",
                discovered_hosts=hosts,
                proxy_url=proxy_url,
            )
            assert len(web_findings) > 0
        finally:
            socks_srv.close()
            target_srv.close()
            await socks_srv.wait_closed()
            await target_srv.wait_closed()

    asyncio.run(_run_socks5_e2e())

    # 3. Nmap leak guard in onion/proxy mode when torsocks unavailable
    monkeypatch.setattr(nmap_engine, "detect_nmap", lambda: {"installed": True, "version": "7.95", "path": "nmap"})
    monkeypatch.setattr(nmap_engine.shutil, "which", lambda *a, **kw: None)
    nmap_skipped = asyncio.run(
        nmap_engine.run_nmap_scan("example.com", onion_mode=True, proxy_url="socks5h://127.0.0.1:19050")
    )
    assert nmap_skipped.get("skipped_for_proxy") is True
    assert nmap_skipped["hosts"] == []

    # 4. System status, proxy test validation, and /api/scans onion_mode persistence
    status_data = client.get("/api/system/status").json()
    assert "tor" in status_data["engines"]

    bad_test = client.post("/api/system/proxy/test", json={"proxy_url": "ftp://invalid:21"})
    assert bad_test.status_code == 400

    bad_scan = client.post("/api/scans", json={
        "org_id": 1,
        "name": "Bad Proxy Scan",
        "targets": "example.com",
        "engines": ["native_net"],
        "proxy_url": "ftp://invalid:21",
    })
    assert bad_scan.status_code == 400

    monkeypatch.setattr(main_mod, "start_scan_in_background", lambda scan_id: None)
    ok_scan = client.post("/api/scans", json={
        "org_id": 1,
        "name": "Onion Scan Config Test",
        "targets": "example.com",
        "engines": ["native_web"],
        "onion_mode": True,
    })
    assert ok_scan.status_code == 201
    created = ok_scan.json()
    assert created["config"].get("onion_mode") is True


def test_web_recon_subraptor_takeover_feroxbuster_and_wordlists(tmp_path, monkeypatch):
    import asyncio
    import io
    import json
    import zipfile
    import backend.main as main_mod
    from backend.database import get_db_connection
    from backend.export_engine import generate_docx_report, generate_pdf_document
    from backend.report_engine import generate_html_report
    from backend.scanners import recon_engine, wordlists

    # 1. Wordlists catalog & custom upload/delete security
    monkeypatch.setattr(wordlists, "PRESET_WORDLISTS_DIR", tmp_path / "bin_wl")
    monkeypatch.setattr(wordlists, "CUSTOM_WORDLISTS_DIR", tmp_path / "custom_wl")

    wl_resp = client.get("/api/wordlists")
    assert wl_resp.status_code == 200
    wl_data = wl_resp.json()
    assert [w["id"] for w in wl_data["dns"][:3]] == ["n0kovo", "top1m_110k", "italian"]
    assert [w["id"] for w in wl_data["web"][:2]] == ["dirbuster_medium", "dirbuster_big"]

    # Reject binary NUL payload
    bad_up = client.post(
        "/api/wordlists/upload",
        data={"category": "web"},
        files={"file": ("evil.txt", b"\x00\x01binary", "text/plain")},
    )
    assert bad_up.status_code == 400

    # Upload valid custom wordlist
    good_up = client.post(
        "/api/wordlists/upload",
        data={"category": "dns"},
        files={"file": ("../my_custom.txt", b"api\nstaging\n# comment\nadmin\n", "text/plain")},
    )
    assert good_up.status_code == 200
    wl_item = good_up.json()["wordlist"]
    assert wl_item["filename"] == "my_custom.txt"
    assert wl_item["lines"] == 3
    assert any(w["id"] == "custom:my_custom.txt" for w in client.get("/api/wordlists").json()["dns"])

    del_up = client.delete("/api/wordlists/dns/my_custom.txt")
    assert del_up.status_code == 200
    assert not any(w["id"] == "custom:my_custom.txt" for w in client.get("/api/wordlists").json()["dns"])

    # 2. SubRaptor domain extraction, normalization & Found/Unique stats
    assert recon_engine.extract_domain_targets("https://App.Example.COM:8443/login, 192.168.1.1, 10.0.0.0/24") == [
        "app.example.com"
    ]
    norm = recon_engine.normalize_subdomains(
        ["*.API.Example.COM.", "dev.example.com", "not_valid$", "evil.com"],
        "example.com",
    )
    assert norm == ["api.example.com", "dev.example.com"]

    stats = recon_engine.compute_subraptor_source_stats({
        "subfinder": ("ok", {"a.example.com", "b.example.com"}),
        "crtsh": ("ok", {"b.example.com", "c.example.com"}),
    })
    assert stats["subfinder"] == {"status": "ok", "found": 2, "unique": 1}
    assert stats["crtsh"] == {"status": "ok", "found": 2, "unique": 1}

    # 3. Native Subzy / can-i-take-over-xyz takeover check
    fp_file = tmp_path / "fingerprints.json"
    fp_file.write_text(json.dumps([{
        "service": "GitHub Pages",
        "cname": ["github.io"],
        "fingerprint": "There isn't a GitHub Pages site here.",
        "vulnerable": True,
        "status": "Vulnerable",
        "nxdomain": False,
    }]), encoding="utf-8")
    monkeypatch.setattr(recon_engine, "SUBZY_FP_PATH", fp_file)

    class _FakeResp:
        def __init__(self, code: int, text: str):
            self.status_code = code
            self.text = text

    class _FakeAsyncClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, **kw):
            return _FakeResp(404, "<html>There isn't a GitHub Pages site here.</html>")

    monkeypatch.setattr(recon_engine.httpx, "AsyncClient", _FakeAsyncClient)
    tk_hits, tk_findings = asyncio.run(
        recon_engine.run_subzy_takeover_check(
            ["orphan.example.com"],
            [{"subdomain": "orphan.example.com", "url": "https://orphan.example.com", "status_code": 404, "cname": ["user.github.io"]}],
            onion_mode=True,
        )
    )
    assert len(tk_hits) == 1
    assert tk_hits[0]["service"] == "GitHub Pages"
    assert tk_findings[0]["severity"] == "high"
    assert tk_findings[0]["source_engine"] == "subzy"

    # 4. Feroxbuster JSONL parsing & classification
    sample_jsonl = "\n".join([
        json.dumps({"type": "statistics", "requests": 100}),
        json.dumps({"type": "response", "url": "https://example.com/.env", "path": "/.env", "status": 200, "content_length": 512}),
        json.dumps({"type": "response", "url": "https://example.com/admin", "path": "/admin", "status": 403, "content_length": 120}),
        json.dumps({"type": "response", "url": "https://example.com/assets", "path": "/assets", "status": 301, "content_length": 0}),
    ])
    parsed_dirs = recon_engine.parse_feroxbuster_jsonl(sample_jsonl)
    assert len(parsed_dirs) == 3
    dir_findings = recon_engine.classify_feroxbuster_results(parsed_dirs, "https://example.com")
    sevs = sorted(f["severity"] for f in dir_findings)
    assert sevs == ["high", "info", "medium"]

    # 5. System status includes all 4 recon engines & opt-in defaults on POST /api/scans
    sys_engines = client.get("/api/system/status").json()["engines"]
    for k in ("subfinder", "httpx", "feroxbuster", "subzy"):
        assert k in sys_engines

    monkeypatch.setattr(main_mod, "start_scan_in_background", lambda scan_id: None)
    default_scan = client.post("/api/scans", json={
        "org_id": 1,
        "name": "Default Opt-In Check",
        "targets": "example.com",
        "engines": ["native_web"],
    }).json()
    assert not default_scan["config"].get("enable_subdomain_enum")
    assert not default_scan["config"].get("enable_dir_enum")

    recon_scan = client.post("/api/scans", json={
        "org_id": 1,
        "name": "Full Recon Opt-In",
        "targets": "example.com",
        "engines": ["native_web"],
        "enable_subdomain_enum": True,
        "subdomain_wordlist": "italian",
        "subdomain_checks": ["httpx", "takeover"],
        "enable_dir_enum": True,
        "dir_wordlist": "dirbuster_big",
        "dir_recursion": True,
        "dir_max_depth": 5,
    }).json()
    assert recon_scan["config"]["enable_subdomain_enum"] is True
    assert recon_scan["config"]["subdomain_wordlist"] == "italian"
    assert recon_scan["config"]["enable_dir_enum"] is True
    assert recon_scan["config"]["dir_wordlist"] == "dirbuster_big"
    assert recon_scan["config"]["dir_recursion"] is True
    assert recon_scan["config"]["dir_max_depth"] == 5

    clamped_scan = client.post("/api/scans", json={
        "org_id": 1,
        "name": "Clamped Depth Check",
        "targets": "example.com",
        "engines": ["native_web"],
        "enable_dir_enum": True,
        "dir_max_depth": 99,
    }).json()
    assert clamped_scan["config"]["dir_max_depth"] == 10

    # 6. HTML / PDF / DOCX reports render Attack Surface & Recon summary cleanly
    recon_payload = {
        "total_subdomains": 2,
        "sources": {"example.com": {"subfinder": {"status": "ok", "found": 2, "unique": 1}}},
        "live_subdomains": [{"subdomain": "sub.example.com", "url": "https://sub.example.com", "status_code": 200, "title": "Portal", "tech": ["Nginx"]}],
        "takeovers": [],
        "dns_zones": [{"domain": "example.com", "nameservers": ["ns1.example.com"], "axfr_vulnerable": False, "wildcard_dns": False, "has_spf": True, "has_dmarc": True}],
        "directories": parsed_dirs,
    }
    conn = get_db_connection()
    with conn:
        conn.execute(
            "UPDATE scans SET status='completed', summary_json=? WHERE id=?;",
            (json.dumps({"total_hosts": 1, "total_findings": 1, "risk_score": 40, "recon": recon_payload}), int(recon_scan["id"])),
        )
    conn.close()

    html_rep = generate_html_report(int(recon_scan["id"]), lang="en")
    assert "sub.example.com" in open(html_rep["file_path"], encoding="utf-8").read()
    pdf_bytes = generate_pdf_document("Recon PDF", "CONFIDENTIAL", {}, {"name": "Client"}, "example.com", [], dir_findings, recon_summary=recon_payload)
    assert pdf_bytes.startswith(b"%PDF")
    docx_bytes = generate_docx_report("Recon DOCX", "CONFIDENTIAL", {}, {"name": "Client"}, "example.com", [], dir_findings, recon_summary=recon_payload)
    with zipfile.ZipFile(io.BytesIO(docx_bytes), "r") as zf:
        assert "sub.example.com" in zf.read("word/document.xml").decode("utf-8")


def test_tech_stack_fingerprinting_and_cve_poc_intel(monkeypatch):
    import asyncio
    import io
    import json
    import zipfile
    import backend.main as main_mod
    from backend.database import get_db_connection
    from backend.scanners import tech_cve_engine
    from backend.scanners.deduplicator import consolidate_findings
    from backend.report_engine import generate_html_report
    from backend.export_engine import generate_pdf_document, generate_docx_report

    # 1. Mock httpx probe + HTML/header fetch + Nmap CPE fusion
    async def _fake_httpx_probe(urls, proxy_url=None, log_callback=None):
        return [{
            "subdomain": "portal.example.org",
            "url": "https://portal.example.org",
            "status_code": 200,
            "title": "Portal",
            "tech": ["WordPress:6.4.2", "Nginx:1.24.0"],
            "webserver": "nginx/1.24.0",
            "ip": "93.184.216.34",
            "cname": [],
            "content_length": 1024,
        }]

    monkeypatch.setattr(tech_cve_engine, "run_httpx_probe", _fake_httpx_probe)

    class _FakeResp:
        def __init__(self, status_code, headers=None, text="", json_data=None, url="https://portal.example.org"):
            self.status_code = status_code
            self.headers = headers or {}
            self.text = text
            self._json = json_data
            self.url = url

        def json(self):
            return self._json

    class _FakeTechClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, **kw):
            return _FakeResp(
                200,
                headers={
                    "Server": "nginx/1.24.0",
                    "X-Powered-By": "PHP/8.1.2",
                    "Set-Cookie": "laravel_session=abc; HttpOnly",
                },
                text='<html><head><meta name="generator" content="WordPress 6.4.2">'
                     '<script src="/assets/jquery-3.5.1.min.js"></script></head></html>',
                url=url,
            )

    monkeypatch.setattr(tech_cve_engine.httpx, "AsyncClient", _FakeTechClient)

    hosts_dict = {
        "93.184.216.34": {
            "ip": "93.184.216.34",
            "hostname": "portal.example.org",
            "ports": [{
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "product": "OpenSSH 8.9p1",
                "product_name": "OpenSSH",
                "version": "8.9p1",
                "cpe": ["cpe:/a:openbsd:openssh:8.9p1"],
                "state": "open",
            }],
        }
    }

    stack = asyncio.run(tech_cve_engine.run_tech_fingerprint(
        urls=["https://portal.example.org"],
        hosts_dict=hosts_dict,
    ))
    by_name = {s["name"].lower(): s for s in stack}
    assert "wordpress" in by_name and by_name["wordpress"]["version"] == "6.4.2"
    assert "nginx" in by_name and by_name["nginx"]["version"] == "1.24.0"
    assert "php" in by_name and by_name["php"]["version"] == "8.1.2"
    assert "jquery" in by_name and by_name["jquery"]["version"] == "3.5.1"
    assert "laravel" in by_name
    assert "openssh" in by_name and by_name["openssh"]["cpe"].startswith("cpe:2.3:a:openbsd:openssh:8.9p1:")

    # 2. CVE + CISA KEV + EPSS + PoC-in-GitHub correlation & SQLite caching
    http_calls = []

    class _FakeIntelClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, **kw):
            http_calls.append(url)
            if "known_exploited_vulnerabilities.json" in url:
                return _FakeResp(200, json_data={
                    "vulnerabilities": [{
                        "cveID": "CVE-2024-99999",
                        "dueDate": "2026-05-01",
                        "knownRansomwareCampaignUse": "Known",
                        "vulnerabilityName": "Example Critical RCE",
                    }]
                })
            if "services.nvd.nist.gov" in url:
                return _FakeResp(200, json_data={
                    "vulnerabilities": [{
                        "cve": {
                            "id": "CVE-2024-99999",
                            "published": "2026-01-15T10:00:00.000",
                            "descriptions": [{"lang": "en", "value": "Critical RCE in component"}],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                        }
                    }]
                })
            if "api.first.org" in url:
                return _FakeResp(200, json_data={"data": [{"cve": "CVE-2024-99999", "epss": "0.8732"}]})
            if "PoC-in-GitHub" in url:
                return _FakeResp(200, json_data=[{"html_url": "https://github.com/example/CVE-2024-99999-poc"}])
            return _FakeResp(404)

    monkeypatch.setattr(tech_cve_engine.httpx, "AsyncClient", _FakeIntelClient)

    # Clear test cache keys beforehand to exercise network path then cache path
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM cve_intel_cache;")
    conn.close()

    matches, intel_findings = asyncio.run(tech_cve_engine.run_cve_intel_correlation(stack[:1]))
    assert len(matches) >= 1
    assert matches[0]["cve_id"] == "CVE-2024-99999"
    assert matches[0]["is_kev"] is True
    assert matches[0]["epss"] == 0.8732
    assert "https://github.com/example/CVE-2024-99999-poc" in matches[0]["poc_urls"]
    assert any(
        f["source_engine"] == "cve_intel"
        and "[CISA KEV]" in f["title"]
        and "VERSION-BASED" in f["evidence"]
        for f in intel_findings
    )
    first_call_count = len(http_calls)
    assert first_call_count >= 4

    # Second run must hit SQLite cve_intel_cache without external HTTP requests
    matches2, _ = asyncio.run(tech_cve_engine.run_cve_intel_correlation(stack[:1]))
    assert len(matches2) == len(matches)
    assert len(http_calls) == first_call_count

    # 3. Cross-engine deduplication: active Nuclei beats version-based cve_intel for same host & CVE
    nuclei_finding = {
        "host": intel_findings[0]["host"],
        "port": intel_findings[0]["port"],
        "protocol": "tcp",
        "service": "https",
        "title": "Confirmed Nuclei RCE",
        "severity": "critical",
        "cvss": 9.8,
        "cve_ids": "CVE-2024-99999",
        "cwe_id": "CWE-94",
        "source_engine": "nuclei",
        "description": "Verified via active template",
        "evidence": "HTTP 200 poc match",
        "remediation": "Upgrade now",
    }
    consolidated = consolidate_findings([nuclei_finding, intel_findings[0]])
    matching_99999 = [f for f in consolidated if "CVE-2024-99999" in (f.get("cve_ids") or "")]
    assert len(matching_99999) == 1
    assert matching_99999[0]["source_engine"] == "nuclei+cve_intel"
    assert matching_99999[0]["title"] == "Confirmed Nuclei RCE"

    # 4. POST /api/scans persists enable_tech_fingerprint & enable_cve_intel
    monkeypatch.setattr(main_mod, "start_scan_in_background", lambda scan_id: None)
    tech_scan = client.post("/api/scans", json={
        "org_id": 1,
        "name": "Tech & CVE Intel Scan",
        "targets": "https://portal.example.org",
        "engines": ["native_web"],
        "enable_tech_fingerprint": True,
        "enable_cve_intel": False,
    }).json()
    assert tech_scan["config"]["enable_tech_fingerprint"] is True
    assert tech_scan["config"]["enable_cve_intel"] is False

    # 5. HTML, PDF & DOCX render tech_stack and cve_intel tables (including CISA KEV & PoC URL)
    recon_payload = {"tech_stack": stack, "cve_intel": matches}
    conn = get_db_connection()
    with conn:
        conn.execute(
            "UPDATE scans SET status='completed', summary_json=? WHERE id=?;",
            (json.dumps({"total_hosts": 1, "total_findings": len(intel_findings), "risk_score": 75, "recon": recon_payload}), int(tech_scan["id"])),
        )
    conn.close()

    html_rep = generate_html_report(int(tech_scan["id"]), lang="en")
    html_body = open(html_rep["file_path"], encoding="utf-8").read()
    assert "WordPress" in html_body and "CISA KEV" in html_body and "CVE-2024-99999-poc" in html_body

    pdf_bytes = generate_pdf_document("Tech PDF", "CONFIDENTIAL", {}, {"name": "Client"}, "portal.example.org", [], intel_findings, recon_summary=recon_payload)
    assert pdf_bytes.startswith(b"%PDF") and len(pdf_bytes) > 5000

    docx_bytes = generate_docx_report("Tech DOCX", "CONFIDENTIAL", {}, {"name": "Client"}, "portal.example.org", [], intel_findings, recon_summary=recon_payload)
    with zipfile.ZipFile(io.BytesIO(docx_bytes), "r") as zf:
        doc_xml = zf.read("word/document.xml").decode("utf-8")
        assert "WordPress" in doc_xml and "CISA KEV" in doc_xml and "CVE-2024-99999-poc" in doc_xml


def test_cloud_security_prowler_profiles_ocsf_and_reports(monkeypatch):
    import io
    import json
    import zipfile
    import backend.main as main_mod
    from backend.database import get_db_connection
    from backend.export_engine import generate_docx_report, generate_pdf_document
    from backend.report_engine import generate_html_report
    from backend.scanners import prowler_engine

    # 1. Encrypted cloud credentials round-trip & masking (zero plaintext leakage)
    secret_creds = {
        "aws_access_key_id": "AKIATESTKEY123456789",
        "aws_secret_access_key": "super-secret-aws-key-value",
    }
    enc = prowler_engine.encrypt_cloud_credentials(secret_creds)
    assert enc.startswith("v1:") and "super-secret-aws-key-value" not in enc
    dec = prowler_engine.decrypt_cloud_credentials(enc)
    assert dec == secret_creds
    masked = prowler_engine.mask_cloud_credentials(secret_creds)
    assert masked["aws_secret_access_key"] == "***configured***"
    assert "super-secret-aws-key-value" not in json.dumps(masked)

    # 2. Cloud catalog & profile CRUD endpoints
    cat_resp = client.get("/api/cloud/catalog")
    assert cat_resp.status_code == 200
    cat_data = cat_resp.json()
    assert "aws" in cat_data["providers"] and "azure" in cat_data["providers"] and "gcp" in cat_data["providers"]
    assert "prowler" in client.get("/api/system/status").json()["engines"]

    prof_resp = client.post("/api/cloud/profiles", json={
        "org_id": 1,
        "name": "AWS Prod Audit",
        "provider": "aws",
        "region": "eu-west-1",
        "credentials": secret_creds,
    })
    assert prof_resp.status_code == 201
    prof = prof_resp.json()
    assert prof["provider"] == "aws"
    assert "super-secret-aws-key-value" not in json.dumps(prof)

    list_resp = client.get("/api/cloud/profiles", params={"org_id": 1})
    assert list_resp.status_code == 200
    profs = list_resp.json()
    assert any(p["id"] == prof["id"] and "super-secret-aws-key-value" not in json.dumps(p) for p in profs)

    # 3. OCSF JSON parsing into cloud_posture + prowler findings
    sample_ocsf = json.dumps([
        {
            "status_code": "PASS",
            "severity": "low",
            "cloud": {"account": {"uid": "123456789012"}},
            "resources": [{"uid": "arn:aws:s3:::ok-bucket", "region": "eu-west-1", "group": {"name": "s3"}}],
            "finding_info": {"title": "S3 bucket encryption enabled", "desc": "OK"},
        },
        {
            "status_code": "FAIL",
            "severity": "critical",
            "status_detail": "Bucket ACL allows AllUsers read",
            "cloud": {"account": {"uid": "123456789012"}},
            "resources": [{"uid": "arn:aws:s3:::public-bucket", "region": "eu-west-1", "group": {"name": "s3"}}],
            "finding_info": {"uid": "s3_bucket_public_read", "title": "S3 Bucket Public Read Access", "desc": "Public bucket exposed"},
            "remediation": {"desc": "Enable S3 Block Public Access", "references": ["https://docs.aws.amazon.com/s3"]},
        },
    ])
    posture, cloud_findings = prowler_engine.parse_prowler_ocsf_json(sample_ocsf, "aws", compliance="cis_3.0_aws")
    assert posture["provider"] == "aws"
    assert posture["account"] == "123456789012"
    assert posture["passed"] == 1 and posture["failed"] == 1 and posture["pass_rate"] == 50.0
    assert posture["by_service"]["s3"]["failed"] == 1
    assert len(cloud_findings) == 1
    assert cloud_findings[0]["source_engine"] == "prowler"
    assert "[Prowler/AWS]" in cloud_findings[0]["title"]

    # 4. Launch cloud scan endpoint (mocked background execution) & render HTML/PDF/DOCX
    captured = {}
    def _fake_bg(sid, payload):
        captured["scan_id"] = sid
        captured["payload"] = payload

    monkeypatch.setattr(main_mod, "start_cloud_scan_in_background", _fake_bg)
    cscan_resp = client.post("/api/cloud/scans", json={
        "org_id": 1,
        "name": "AWS CIS Audit",
        "provider": "aws",
        "profile_id": prof["id"],
        "compliance": "cis_3.0_aws",
        "services": ["s3", "iam"],
        "severities": ["critical", "high"],
    })
    assert cscan_resp.status_code == 201
    cscan = cscan_resp.json()
    assert captured["payload"]["credentials"] == secret_creds

    conn = get_db_connection()
    with conn:
        conn.execute(
            "UPDATE scans SET status='completed', summary_json=? WHERE id=?;",
            (json.dumps({"total_hosts": 1, "total_findings": 1, "risk_score": 25, "cloud_posture": posture}), int(cscan["id"])),
        )
    conn.close()

    html_rep = generate_html_report(int(cscan["id"]), lang="en")
    html_body = open(html_rep["file_path"], encoding="utf-8").read()
    assert "Cloud Security Posture (Prowler CSPM)" in html_body and "123456789012" in html_body

    pdf_bytes = generate_pdf_document("Cloud PDF", "CONFIDENTIAL", {}, {"name": "Client"}, "AWS", [], cloud_findings, cloud_posture=posture)
    assert pdf_bytes.startswith(b"%PDF") and len(pdf_bytes) > 5000

    docx_bytes = generate_docx_report("Cloud DOCX", "CONFIDENTIAL", {}, {"name": "Client"}, "AWS", [], cloud_findings, cloud_posture=posture)
    with zipfile.ZipFile(io.BytesIO(docx_bytes), "r") as zf:
        doc_xml = zf.read("word/document.xml").decode("utf-8")
        assert "Cloud Security Posture (Prowler CSPM)" in doc_xml and "123456789012" in doc_xml

    # 5. Cleanup profile
    del_resp = client.delete(f"/api/cloud/profiles/{prof['id']}")
    assert del_resp.status_code == 200
