import os
import json
import sqlite3
import base64
import secrets
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
DB_PATH = Path(os.environ["URIELSCAN_DB_PATH"]) if os.environ.get("URIELSCAN_DB_PATH") else (DATA_DIR / "urielscan.db")

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def _make_svg_base64(svg_str: str) -> str:
    b64 = base64.b64encode(svg_str.strip().encode("utf-8")).decode("utf-8")
    return f"data:image/svg+xml;base64,{b64}"


DEFAULT_MSSP_LOGO = _make_svg_base64("""
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 60" width="200" height="60">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#8b5cf6" />
      <stop offset="100%" stop-color="#3b82f6" />
    </linearGradient>
    <linearGradient id="textGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#ffffff" />
      <stop offset="100%" stop-color="#cbd5e1" />
    </linearGradient>
  </defs>
  <g transform="translate(10, 8)">
    <polygon points="22,2 40,9 40,26 22,42 4,26 4,9" fill="url(#shieldGrad)" stroke="#a855f7" stroke-width="1.5" />
    <path d="M14,20 L20,26 L30,14" fill="none" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />
  </g>
  <text x="60" y="32" font-family="system-ui, -apple-system, sans-serif" font-weight="800" font-size="20" fill="url(#textGrad)" letter-spacing="1">URIEL<tspan fill="#a855f7">SCAN</tspan></text>
  <text x="61" y="46" font-family="system-ui, -apple-system, sans-serif" font-weight="600" font-size="9" fill="#94a3b8" letter-spacing="2">PURPLE TEAM MSSP</text>
</svg>
""")

ACME_LOGO = _make_svg_base64("""
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 48" width="160" height="48">
  <defs>
    <linearGradient id="acmeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0284c7" />
      <stop offset="100%" stop-color="#0369a1" />
    </linearGradient>
  </defs>
  <rect x="6" y="6" width="36" height="36" rx="8" fill="url(#acmeGrad)"/>
  <path d="M16 32 L24 16 L32 32 Z M20 28 L28 28" stroke="#ffffff" stroke-width="2.5" fill="none" stroke-linecap="round"/>
  <text x="50" y="26" font-family="system-ui, sans-serif" font-weight="700" font-size="14" fill="#0f172a">Acme FinTech</text>
  <text x="50" y="38" font-family="system-ui, sans-serif" font-size="9" fill="#64748b">Banking &amp; Securities S.p.A.</text>
</svg>
""")

NOVACLOUD_LOGO = _make_svg_base64("""
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 170 48" width="170" height="48">
  <defs>
    <linearGradient id="novaGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#059669" />
      <stop offset="100%" stop-color="#10b981" />
    </linearGradient>
  </defs>
  <circle cx="24" cy="24" r="18" fill="url(#novaGrad)"/>
  <path d="M24 14 V34 M14 24 H34" stroke="#ffffff" stroke-width="3" stroke-linecap="round"/>
  <text x="50" y="26" font-family="system-ui, sans-serif" font-weight="700" font-size="14" fill="#0f172a">NovaCloud</text>
  <text x="50" y="38" font-family="system-ui, sans-serif" font-size="9" fill="#059669">Healthcare Solutions</text>
</svg>
""")


def init_db() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        totp_secret TEXT DEFAULT '',
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        totp_pending_secret TEXT DEFAULT '',
        must_change_password INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS organizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        industry TEXT,
        contact_name TEXT,
        contact_email TEXT,
        logo_data TEXT,
        target_scope TEXT,
        description TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS agents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        token_prefix TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'offline',
        last_seen TEXT,
        hostname TEXT DEFAULT '',
        ip_address TEXT DEFAULT '',
        os_info TEXT DEFAULT '',
        engines_json TEXT DEFAULT '{}',
        version TEXT DEFAULT '1.0.0',
        created_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        targets TEXT NOT NULL,
        scan_profile TEXT NOT NULL DEFAULT 'standard',
        engines_json TEXT NOT NULL DEFAULT '["native"]',
        config_json TEXT NOT NULL DEFAULT '{}',
        status TEXT NOT NULL DEFAULT 'pending',
        progress INTEGER NOT NULL DEFAULT 0,
        current_task TEXT NOT NULL DEFAULT 'Inizializzazione...',
        started_at TEXT,
        completed_at TEXT,
        hosts_json TEXT NOT NULL DEFAULT '[]',
        summary_json TEXT NOT NULL DEFAULT '{}',
        logs_json TEXT NOT NULL DEFAULT '[]',
        ai_analysis_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        org_id INTEGER NOT NULL,
        host TEXT NOT NULL,
        port INTEGER,
        protocol TEXT DEFAULT 'tcp',
        service TEXT,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss REAL DEFAULT 0.0,
        cve_ids TEXT,
        cwe_id TEXT,
        source_engine TEXT NOT NULL,
        description TEXT,
        evidence TEXT,
        remediation TEXT,
        mitre_tactic TEXT,
        mitre_technique TEXT,
        ai_insight TEXT,
        status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        targets TEXT NOT NULL,
        frequency TEXT NOT NULL DEFAULT 'weekly',
        cron_expr TEXT,
        time_of_day TEXT DEFAULT '02:00',
        day_of_week TEXT DEFAULT 'MON',
        scan_config_json TEXT NOT NULL DEFAULT '{}',
        enabled INTEGER NOT NULL DEFAULT 1,
        last_run TEXT,
        next_run TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        scan_id INTEGER NOT NULL,
        org_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        classification TEXT DEFAULT 'CONFIDENZIALE - USO INTERNO',
        created_at TEXT NOT NULL,
        file_path TEXT NOT NULL,
        summary_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
    );
    """)

    conn.commit()

    # Safe migration for agent_id on scans table
    cursor.execute("PRAGMA table_info(scans);")
    columns = [col[1] for col in cursor.fetchall()]
    if "agent_id" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN agent_id INTEGER;")
        conn.commit()

    # Safe migration for must_change_password on users table
    cursor.execute("PRAGMA table_info(users);")
    user_cols = [col[1] for col in cursor.fetchall()]
    if "must_change_password" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;")
        conn.commit()

    # Mark DB initialized on first launch with default MSSP settings only
    # (demo organizations/scans are NOT auto-seeded; loadable manually from Settings)
    cursor.execute("SELECT value FROM settings WHERE key = 'db_initialized';")
    init_flag = cursor.fetchone()

    if not init_flag:
        default_settings = {
            "scanner_company_name": "UrielScan Purple Team MSSP",
            "scanner_company_logo": DEFAULT_MSSP_LOGO,
            "scanner_company_email": "security-ops@urielscan.io",
            "scanner_company_website": "https://urielscan.io",
            "scanner_company_address": "Cyber Defense Operations Center - Torre A, Milano, Italia",
            "report_footer": "UrielScan v1.0 - Documento Confidenziale di Valutazione Vulnerabilità e Sicurezza Purple Team",
            "ai_provider": "offline",
            "ai_api_key": "",
            "ai_model": "gpt-4o",
            "ai_base_url": "https://api.openai.com/v1",
            "db_initialized": "1",
        }
        for k, v in default_settings.items():
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?);", (k, v))
        conn.commit()

    # Seed default admin user if users table is empty
    cursor.execute("SELECT COUNT(*) as count FROM users;")
    user_count = cursor.fetchone()["count"]
    if user_count == 0:
        from backend.auth import hash_password
        env_admin_pw = os.getenv("URIELSCAN_ADMIN_PASSWORD", "").strip()
        initial_pw = env_admin_pw if env_admin_pw else "admin"
        must_change = 0 if env_admin_pw else 1
        p_hash, p_salt = hash_password(initial_pw)
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor.execute("""
            INSERT INTO users (username, password_hash, salt, role, totp_secret, totp_enabled, totp_pending_secret, must_change_password, created_at)
            VALUES (?, ?, ?, 'admin', '', 0, '', ?, ?);
        """, ("admin", p_hash, p_salt, must_change, now_iso))
        conn.commit()

    conn.close()


def seed_demo_data() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    _seed_demo_data(cursor)
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('db_initialized', '1');")
    conn.commit()
    conn.close()


def _seed_demo_data(cursor: sqlite3.Cursor) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Settings (MSSP Default White-label)
    default_settings = {
        "scanner_company_name": "UrielScan Purple Team MSSP",
        "scanner_company_logo": DEFAULT_MSSP_LOGO,
        "scanner_company_email": "security-ops@urielscan.io",
        "scanner_company_website": "https://urielscan.io",
        "scanner_company_address": "Cyber Defense Operations Center - Torre A, Milano, Italia",
        "report_footer": "UrielScan v1.0 - Documento Confidenziale di Valutazione Vulnerabilità e Sicurezza Purple Team",
        "ai_provider": "offline",
        "ai_api_key": "",
        "ai_model": "gpt-4o",
        "ai_base_url": "https://api.openai.com/v1"
    }
    for k, v in default_settings.items():
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?);", (k, v))

    # 2. Organizations
    cursor.execute("""
        INSERT INTO organizations (name, industry, contact_name, contact_email, logo_data, target_scope, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        "Acme FinTech S.p.A.",
        "Financial Services & Banking",
        "Marco Rossi (CISO)",
        "m.rossi@acmefintech.it",
        ACME_LOGO,
        "192.168.1.10, 192.168.1.15, 192.168.1.25, api.acmefintech.it, portal.acmefintech.it",
        "Infrastruttura di core banking, API gateway per pagamenti PSD2 e portale online banking.",
        now_iso
    ))
    org1_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO organizations (name, industry, contact_name, contact_email, logo_data, target_scope, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        "NovaCloud Healthcare",
        "Sanità Digitale & Ricerca Clinica",
        "Dott.ssa Elena Bianchi",
        "e.bianchi@novacloud-health.com",
        NOVACLOUD_LOGO,
        "ehr.novacloud-health.com, hl7-broker.novacloud-health.com, 10.200.4.0/24",
        "Piattaforma Fascicolo Sanitario Elettronico e nodi di scambio dati sanitari HL7/FHIR.",
        now_iso
    ))
    org2_id = cursor.lastrowid

    # 3. Demo Scan for Org 1
    hosts = [
        {
            "ip": "192.168.1.10",
            "hostname": "api.acmefintech.it",
            "os": "Linux 5.15 (Ubuntu 22.04 LTS)",
            "ports": [
                {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.18.0", "state": "open"},
                {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx (OpenSSL 1.1.1f)", "version": "1.18.0", "state": "open"},
                {"port": 8080, "protocol": "tcp", "service": "http-proxy", "product": "Apache Tomcat / Spring Boot", "version": "9.0.41", "state": "open"}
            ]
        },
        {
            "ip": "192.168.1.15",
            "hostname": "portal.acmefintech.it",
            "os": "Linux (Debian 11)",
            "ports": [
                {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.49", "state": "open"},
                {"port": 443, "protocol": "tcp", "service": "ssl/https", "product": "Apache httpd", "version": "2.4.49", "state": "open"},
                {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.4p1", "state": "open"}
            ]
        },
        {
            "ip": "192.168.1.25",
            "hostname": "db-internal.acmefintech.local",
            "os": "Windows Server 2019 Standard",
            "ports": [
                {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "product": "Windows SMB", "version": "SMBv2/v3", "state": "open"},
                {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "product": "Microsoft Terminal Services RDP", "version": "10.0", "state": "open"},
                {"port": 6379, "protocol": "tcp", "service": "redis", "product": "Redis Key-Value Store", "version": "6.0.9", "state": "open"}
            ]
        }
    ]

    summary = {
        "total_hosts": 3,
        "up_hosts": 3,
        "total_ports": 9,
        "total_findings": 10,
        "critical": 2,
        "high": 3,
        "medium": 3,
        "low": 1,
        "info": 1,
        "risk_score": 88,
        "risk_label": "CRITICO",
        "engines_used": ["native_net", "native_web", "nmap", "nuclei"]
    }

    logs = [
        {"time": "10:00:01", "level": "INFO", "msg": "Inizializzazione scansione Purple Team per Acme FinTech S.p.A."},
        {"time": "10:00:03", "level": "INFO", "msg": "Risoluzione target e verifica raggiungibilità host: 3 host rilevati attivi"},
        {"time": "10:00:15", "level": "INFO", "msg": "Esecuzione Nmap Port & Service Discovery completata con 9 porte aperte"},
        {"time": "10:00:30", "level": "WARN", "msg": "[NMAP NSE] Rilevata vulnerabilità Apache Path Traversal su 192.168.1.15:80 (CVE-2021-41773)"},
        {"time": "10:00:45", "level": "WARN", "msg": "[NUCLEI] Individuata vulnerabilità Remote Code Execution Spring4Shell su api.acmefintech.it (CVE-2022-22965)"},
        {"time": "10:01:00", "level": "WARN", "msg": "[NATIVE NET] Servizio Redis non autenticato rilevato su 192.168.1.25:6379"},
        {"time": "10:01:15", "level": "WARN", "msg": "[NATIVE WEB] Repository Git esposto pubblicamente: /.git/HEAD accessibile su portal.acmefintech.it"},
        {"time": "10:01:25", "level": "INFO", "msg": "Analisi Purple Team AI generata con successo. Scansione completata."}
    ]

    ai_analysis = {
        "provider_used": "Purple Team Smart Heuristic Engine (Offline / Standalone)",
        "risk_rating": "CRITICO (88/100)",
        "executive_summary": "La valutazione di sicurezza condotta sull'infrastruttura di Acme FinTech ha evidenziato vulnerabilità di estrema gravità che consentono l'esecuzione di codice arbitrario da remoto (RCE) e l'accesso diretto alla memoria dati. Due vettori critici (Apache CVE-2021-41773 e Spring4Shell CVE-2022-22965) permettono a un attaccante non autenticato di ottenere il controllo iniziale della DMZ, con conseguente movimento laterale facilitato dall'assenza di autenticazione su Redis e debolezza nelle firme SMB.",
        "attack_paths": [
            {
                "step": 1,
                "title": "Accesso Iniziale & Esecuzione Codice Remoto",
                "details": "L'attaccante sfrutta la vulnerabilità di Path Traversal su Apache 2.4.49 (CVE-2021-41773) o la deserializzazione in Spring Framework (CVE-2022-22965) per eseguire codice con privilegi www-data sull'API Gateway.",
                "mitre": "T1190 - Exploit Public-Facing Application"
            },
            {
                "step": 2,
                "title": "Credential Dumping & Information Disclosure",
                "details": "Tramite l'esposizione della directory /.git/ sul portale web e l'interrogazione diretta di Redis esposto senza password, l'attaccante estrae token di sessione, chiavi JWT e credenziali del database bancario.",
                "mitre": "T1552 - Unsecured Credentials"
            },
            {
                "step": 3,
                "title": "Movimento Laterale & Compromissione Database",
                "details": "Utilizzando le credenziali sottratte e la sessione SMB non firmata su 192.168.1.25, l'avversario esegue dump dei dati finanziari e stabilisce persistenza tramite RDP.",
                "mitre": "T1021.002 - SMB/Windows Admin Shares"
            }
        ],
        "remediation_plan": [
            {
                "priority": "P0 - Immediata (Entro 4 ore)",
                "action": "Aggiornare immediatamente Apache HTTP Server a versione >= 2.4.51 e Spring Boot Framework a versione supportata patchata.",
                "command": "apt-get update && apt-get install --only-upgrade apache2"
            },
            {
                "priority": "P0 - Immediata (Entro 8 ore)",
                "action": "Abilitare l'autenticazione obbligatoria (requirepass) su Redis ed effettuare il bind esclusivo su localhost (127.0.0.1) o interfaccia isolata di backend.",
                "command": "redis-cli CONFIG SET requirepass <StrongPassword>; bind 127.0.0.1 in redis.conf"
            },
            {
                "priority": "P1 - Alta (Entro 24 ore)",
                "action": "Rimuovere la cartella .git dai deployment di produzione e configurare Nginx per bloccare tassativamente l'accesso a file nascosti dotfile.",
                "command": "location ~ /\\.(?!well-known) { deny all; return 404; }"
            },
            {
                "priority": "P2 - Media (Entro 72 ore)",
                "action": "Attivare SMB Signing obbligatorio sui domain controller e server Windows tramite Group Policy (GPO).",
                "command": "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"
            }
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application", "count": 2},
            {"tactic": "Credential Access", "technique": "T1552 - Unsecured Credentials", "count": 2},
            {"tactic": "Lateral Movement", "technique": "T1021.002 - SMB/Windows Admin Shares", "count": 1},
            {"tactic": "Discovery", "technique": "T1046 - Network Service Discovery", "count": 3}
        ]
    }

    cursor.execute("""
        INSERT INTO scans (org_id, name, targets, scan_profile, engines_json, config_json, status, progress, current_task, started_at, completed_at, hosts_json, summary_json, logs_json, ai_analysis_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        org1_id,
        "Audit Perimetrale e Applicativo Q4 - Acme FinTech",
        "192.168.1.10, 192.168.1.15, 192.168.1.25",
        "full_purple",
        json.dumps(["native_net", "native_web", "nmap", "nuclei"]),
        json.dumps({"ports": "top-100", "nse_category": "vuln,safe,discovery"}),
        "completed",
        100,
        "Analisi completata con successo",
        now_iso,
        now_iso,
        json.dumps(hosts),
        json.dumps(summary),
        json.dumps(logs),
        json.dumps(ai_analysis)
    ))
    scan1_id = cursor.lastrowid

    # 4. Findings for Scan 1
    demo_findings = [
        (
            scan1_id, org1_id, "192.168.1.15", 80, "tcp", "http",
            "Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution",
            "critical", 9.8, "CVE-2021-41773, CVE-2021-42013", "CWE-22", "nmap",
            "È stata riscontrata una vulnerabilità critica di path traversal e potenziale esecuzione di codice arbitrario in Apache HTTP Server 2.4.49 tramite payload URL codificati.",
            "curl -s --path-as-is 'http://192.168.1.15/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'\nRisposta: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "Aggiornare tempestivamente Apache HTTP Server alla release 2.4.51 o successiva. Verificare che l'opzione 'Require all denied' sia applicata alla directory root nella configurazione httpd.conf.",
            "Initial Access", "T1190 - Exploit Public-Facing Application",
            "Vulnerabilità critica ampiamente sfruttata da ransomware e botnet per ottenere shell iniziale nel perimetro esposto."
        ),
        (
            scan1_id, org1_id, "192.168.1.10", 8080, "tcp", "http-proxy",
            "Spring Framework RCE (Spring4Shell)",
            "critical", 9.8, "CVE-2022-22965", "CWE-94", "nuclei",
            "Applicazione Spring MVC o Spring WebFlux vulnerabile a Remote Code Execution tramite Data Binding su JDK 9+.",
            "Nuclei Template [CVE-2022-22965] MATCHED:\nPOST /api/v1/customer/profile HTTP/1.1\nclass.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di",
            "Aggiornare Spring Framework alle versioni 5.3.18+, 5.2.20+ o aggiornare Spring Boot a 2.6.6+ / 2.5.12+.",
            "Execution", "T1203 - Exploitation for Client Execution",
            "Permette la creazione di webshell persistente nella directory radice di Tomcat."
        ),
        (
            scan1_id, org1_id, "192.168.1.25", 6379, "tcp", "redis",
            "Istanza Redis Esposta Senza Autenticazione",
            "high", 8.2, "CVE-2018-11235", "CWE-306", "native_net",
            "Il server Redis accetta comandi non autenticati sulla porta pubblica, esponendo l'intera cache in memoria e consentendo potenzialmente la scrittura di file arbitrari.",
            "Native Banner Grab: Comandi INFO e PING accettati senza password.\nredis_version:6.0.9\nos:Linux 5.4.0\nconnected_clients:12\nused_memory_human:450.2M",
            "Configurare la direttiva 'requirepass' con una password robusta in redis.conf e limitare l'ascolto alla sola interfaccia di loopback ('bind 127.0.0.1').",
            "Credential Access", "T1552 - Unsecured Credentials",
            "Un attaccante può eseguire flushall, leggere chiavi API o sovrascrivere authorized_keys via Redis."
        ),
        (
            scan1_id, org1_id, "192.168.1.15", 80, "tcp", "http",
            "Esposizione Pubblica del Repository Git (/.git/)",
            "high", 7.5, "", "CWE-538", "native_web",
            "La directory di versionamento /.git/ è accessibile via HTTP, permettendo l'estrazione integrale del codice sorgente e delle configurazioni storiche.",
            "GET /.git/HEAD -> HTTP 200 OK\nref: refs/heads/production\nGET /.git/config -> HTTP 200 OK (contiene remote origin GitHub con token aziendale)",
            "Bloccare immediatamente l'accesso alla directory /.git nella configurazione del web server e rigenerare tutti i token/secret contenuti nei commit.",
            "Information Disclosure", "T1552.001 - Credentials in Files",
            "Rischio di leakage totale di algoritmi di business logic, database credentials e webhook segreti."
        ),
        (
            scan1_id, org1_id, "192.168.1.25", 445, "tcp", "microsoft-ds",
            "SMB Signing Non Obbligatorio (Rischio NTLM Relay)",
            "high", 7.4, "", "CWE-311", "nmap",
            "Il server SMB supporta la firma digitale ma non ne richiede l'uso obbligatorio, esponendo la rete a violazioni di integrity e NTLM Relay.",
            "Nmap NSE script [smb2-security-mode]:\nMessage signing enabled but not required\nAuthentication level: NTLMv2 supported",
            "Abilitare la richiesta obbligatoria di firma SMB impostando 'Digitally sign communications (always)' via Criteri di Gruppo di Windows.",
            "Lateral Movement", "T1557.001 - LLMNR/NBT-NS Poisoning and Relay",
            "Facilita attacchi di tipo Man-In-The-Middle e relay delle sessioni per guadagnare privilegi di Domain Admin."
        ),
        (
            scan1_id, org1_id, "192.168.1.10", 443, "tcp", "https",
            "Configurazione CORS Insicura (Origin Wildcard con Credentials)",
            "medium", 6.5, "", "CWE-942", "native_web",
            "L'applicazione riflette header Origin arbitrari con Access-Control-Allow-Credentials: true, consentendo attacchi di Cross-Origin Data Theft.",
            "Request Header: Origin: https://evil.urielscan.test\nResponse: Access-Control-Allow-Origin: https://evil.urielscan.test\nAccess-Control-Allow-Credentials: true",
            "Restringere gli host consentiti negli header CORS a una whitelist rigorosa di domini affidabili aziendali.",
            "Initial Access", "T1189 - Drive-by Compromise",
            "Un sito terzo può eseguire chiamate autenticate per conto dell'utente bancario loggato."
        ),
        (
            scan1_id, org1_id, "192.168.1.10", 443, "tcp", "https",
            "Cifratura SSL/TLS Deprecata (Supporto TLS 1.0 e TLS 1.1)",
            "medium", 5.9, "", "CWE-326", "native_net",
            "Il server negozia connessioni utilizzando protocolli TLS obsoleti soggetti a debolezze note (BEAST, POODLE).",
            "Native SSL Probe: Negoziazione riuscita con TLSv1.0 (Cipher: TLS_RSA_WITH_AES_128_CBC_SHA)",
            "Disabilitare TLS 1.0 e TLS 1.1 nel server web. Supportare esclusivamente TLS 1.2 e TLS 1.3 con cipher suite moderne (ECDHE+AES-GCM).",
            "Defense Evasion", "T1573 - Encrypted Channel",
            "Non conforme agli standard PCI-DSS 4.0 e normative bancarie."
        ),
        (
            scan1_id, org1_id, "192.168.1.15", 443, "tcp", "https",
            "Mancanza degli Header di Sicurezza HTTP Fondamentali",
            "medium", 5.0, "", "CWE-693", "native_web",
            "Gli header HSTS, Content-Security-Policy (CSP) e X-Frame-Options non sono implementati.",
            "Missing Security Headers:\n- Strict-Transport-Security\n- Content-Security-Policy\n- X-Frame-Options\n- X-Content-Type-Options",
            "Configurare il web server per inviare header HSTS (max-age=31536000), X-Frame-Options: DENY e una policy CSP restrittiva.",
            "Impact", "T1498 - Network Denial of Service",
            "Espone gli utenti a man-in-the-middle di downgrade HTTP e clickjacking su form riservati."
        ),
        (
            scan1_id, org1_id, "192.168.1.10", 80, "tcp", "http",
            "Information Disclosure: Header Server & X-Powered-By Esposti",
            "low", 3.7, "", "CWE-200", "native_web",
            "Le risposte HTTP rivelano l'esatta versione dei software utilizzati.",
            "Server: nginx/1.18.0\nX-Powered-By: PHP/7.4.33",
            "Disattivare server_tokens in Nginx ('server_tokens off;') e rimuovere l'header expose_php in php.ini.",
            "Reconnaissance", "T1592 - Gather Victim Host Information",
            "Semplifica la selezione di exploit specifici da parte di attaccanti esterni."
        ),
        (
            scan1_id, org1_id, "192.168.1.25", 3389, "tcp", "ms-wbt-server",
            "Servizio Microsoft Remote Desktop (RDP) Attivo",
            "info", 0.0, "", "CWE-200", "native_net",
            "Porta RDP 3389 aperta e in ascolto. Richiede Network Level Authentication (NLA).",
            "RDP NLA abilitato. Certificato SSL emesso per db-internal.acmefintech.local",
            "Isolare l'accesso RDP tramite VPN aziendale con autenticazione multifattore (MFA). Non esporre direttamente su Internet.",
            "Discovery", "T1046 - Network Service Discovery",
            "Best practice di monitoraggio e segmentazione perimetrale."
        )
    ]

    for f in demo_findings:
        cursor.execute("""
            INSERT INTO findings (
                scan_id, org_id, host, port, protocol, service,
                title, severity, cvss, cve_ids, cwe_id, source_engine,
                description, evidence, remediation, mitre_tactic, mitre_technique,
                ai_insight, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?);
        """, (*f, now_iso))

    # 5. Demo Schedules
    cursor.execute("""
        INSERT INTO schedules (org_id, name, targets, frequency, time_of_day, day_of_week, scan_config_json, enabled, last_run, next_run, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        org1_id,
        "Scansione Settimanale Purple Team FinTech",
        "192.168.1.10, 192.168.1.15, 192.168.1.25",
        "weekly",
        "02:00",
        "MON",
        json.dumps({"profile": "full_purple", "engines": ["native_net", "native_web", "nmap", "nuclei"]}),
        1,
        now_iso,
        "2026-11-17T02:00:00Z",
        now_iso
    ))

    cursor.execute("""
        INSERT INTO schedules (org_id, name, targets, frequency, time_of_day, day_of_week, scan_config_json, enabled, last_run, next_run, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        org2_id,
        "Audit Quotidiano Vulnerabilità Web & HL7 Healthcare",
        "ehr.novacloud-health.com, hl7-broker.novacloud-health.com",
        "daily",
        "04:30",
        "*",
        json.dumps({"profile": "web_ssl_audit", "engines": ["native_web", "native_net"]}),
        1,
        None,
        "2026-11-15T04:30:00Z",
        now_iso
    ))


# Helper DB queries
def get_settings() -> Dict[str, str]:
    conn = get_db_connection()
    rows = conn.execute("SELECT key, value FROM settings;").fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}


def update_settings(settings_dict: Dict[str, str]) -> None:
    conn = get_db_connection()
    with conn:
        for k, v in settings_dict.items():
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?);", (k, str(v) if v is not None else ""))
    conn.close()


def get_organizations() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT o.*,
               (SELECT COUNT(*) FROM scans s WHERE s.org_id = o.id) as scans_count,
               (SELECT COUNT(*) FROM findings f WHERE f.org_id = o.id AND f.status = 'open') as open_vulns_count
        FROM organizations o
        ORDER BY o.name ASC;
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_organization_by_id(org_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("""
        SELECT o.*,
               (SELECT COUNT(*) FROM scans s WHERE s.org_id = o.id) as scans_count,
               (SELECT COUNT(*) FROM findings f WHERE f.org_id = o.id AND f.status = 'open') as open_vulns_count
        FROM organizations o
        WHERE o.id = ?;
    """, (org_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_organization(data: Dict[str, Any]) -> int:
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        cur = conn.execute("""
            INSERT INTO organizations (name, industry, contact_name, contact_email, logo_data, target_scope, description, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            data.get("name"),
            data.get("industry", ""),
            data.get("contact_name", ""),
            data.get("contact_email", ""),
            data.get("logo_data", ""),
            data.get("target_scope", ""),
            data.get("description", ""),
            now_iso
        ))
        org_id = cur.lastrowid
    conn.close()
    return org_id


def update_organization(org_id: int, data: Dict[str, Any]) -> bool:
    conn = get_db_connection()
    with conn:
        cur = conn.execute("""
            UPDATE organizations SET
                name = COALESCE(?, name),
                industry = COALESCE(?, industry),
                contact_name = COALESCE(?, contact_name),
                contact_email = COALESCE(?, contact_email),
                logo_data = COALESCE(?, logo_data),
                target_scope = COALESCE(?, target_scope),
                description = COALESCE(?, description)
            WHERE id = ?;
        """, (
            data.get("name"),
            data.get("industry"),
            data.get("contact_name"),
            data.get("contact_email"),
            data.get("logo_data"),
            data.get("target_scope"),
            data.get("description"),
            org_id
        ))
        updated = cur.rowcount > 0
    conn.close()
    return updated


def delete_organization(org_id: int) -> bool:
    conn = get_db_connection()
    with conn:
        cur = conn.execute("DELETE FROM organizations WHERE id = ?;", (org_id,))
        deleted = cur.rowcount > 0
    conn.close()
    return deleted


def get_scans(org_id: Optional[int] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    if org_id:
        rows = conn.execute("""
            SELECT s.*, o.name as org_name, a.name as agent_name
            FROM scans s
            JOIN organizations o ON s.org_id = o.id
            LEFT JOIN agents a ON s.agent_id = a.id
            WHERE s.org_id = ?
            ORDER BY s.id DESC;
        """, (org_id,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT s.*, o.name as org_name, a.name as agent_name
            FROM scans s
            JOIN organizations o ON s.org_id = o.id
            LEFT JOIN agents a ON s.agent_id = a.id
            ORDER BY s.id DESC;
        """).fetchall()
    conn.close()

    res = []
    for r in rows:
        item = dict(r)
        item["engines"] = json.loads(item.get("engines_json") or "[]")
        item["config"] = json.loads(item.get("config_json") or "{}")
        item["summary"] = json.loads(item.get("summary_json") or "{}")
        item["hosts"] = json.loads(item.get("hosts_json") or "[]")
        item["logs"] = json.loads(item.get("logs_json") or "[]")
        item["ai_analysis"] = json.loads(item.get("ai_analysis_json") or "{}")
        res.append(item)
    return res


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("""
        SELECT s.*, o.name as org_name, o.logo_data as org_logo, o.target_scope as org_scope, a.name as agent_name
        FROM scans s
        JOIN organizations o ON s.org_id = o.id
        LEFT JOIN agents a ON s.agent_id = a.id
        WHERE s.id = ?;
    """, (scan_id,)).fetchone()
    conn.close()
    if not row:
        return None

    item = dict(row)
    item["engines"] = json.loads(item.get("engines_json") or "[]")
    item["config"] = json.loads(item.get("config_json") or "{}")
    item["hosts"] = json.loads(item.get("hosts_json") or "[]")
    item["summary"] = json.loads(item.get("summary_json") or "{}")
    item["logs"] = json.loads(item.get("logs_json") or "[]")
    item["ai_analysis"] = json.loads(item.get("ai_analysis_json") or "{}")
    return item


def get_findings_for_scan(scan_id: int) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM findings WHERE scan_id = ? ORDER BY
        CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
        END ASC, cvss DESC;
    """, (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_finding_status(finding_id: int, status: str) -> bool:
    conn = get_db_connection()
    with conn:
        cur = conn.execute("UPDATE findings SET status = ? WHERE id = ?;", (status, finding_id))
        updated = cur.rowcount > 0
    conn.close()
    return updated


def get_dashboard_stats(org_id: Optional[int] = None) -> Dict[str, Any]:
    conn = get_db_connection()
    params = (org_id,) if org_id else ()
    org_filter = "WHERE org_id = ?" if org_id else ""

    total_scans = conn.execute(f"SELECT COUNT(*) FROM scans {org_filter};", params).fetchone()[0]
    active_scans = conn.execute(f"SELECT COUNT(*) FROM scans {'WHERE org_id = ? AND' if org_id else 'WHERE'} status = 'running';", params).fetchone()[0]
    total_orgs = 1 if org_id else conn.execute("SELECT COUNT(*) FROM organizations;").fetchone()[0]

    # Findings counts by severity
    f_filter = "WHERE org_id = ?" if org_id else ""
    findings_stats = conn.execute(f"""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) as info
        FROM findings {f_filter};
    """, params).fetchone()

    # Recent scans
    recent_scans = conn.execute(f"""
        SELECT s.id, s.name, s.status, s.progress, s.started_at, s.completed_at, s.summary_json, o.name as org_name
        FROM scans s
        JOIN organizations o ON s.org_id = o.id
        {org_filter}
        ORDER BY s.id DESC LIMIT 5;
    """, params).fetchall()

    conn.close()

    recent_list = []
    for s in recent_scans:
        item = dict(s)
        item["summary"] = json.loads(item.get("summary_json") or "{}")
        recent_list.append(item)

    crit = findings_stats["critical"] or 0
    high = findings_stats["high"] or 0
    med = findings_stats["medium"] or 0
    # Global posture risk score calculation (0 - 100)
    risk_score = min(100, int((crit * 25) + (high * 15) + (med * 5))) if (crit + high + med) > 0 else 0

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "total_orgs": total_orgs,
        "risk_score": risk_score,
        "findings": {
            "total": findings_stats["total"] or 0,
            "critical": crit,
            "high": high,
            "medium": med,
            "low": findings_stats["low"] or 0,
            "info": findings_stats["info"] or 0
        },
        "recent_scans": recent_list
    }


# ==========================================
# USER & AUTH DATABASE HELPERS
# ==========================================

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?;", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_user_password(username: str, password_hash: str, salt: str) -> bool:
    conn = get_db_connection()
    with conn:
        cur = conn.execute(
            "UPDATE users SET password_hash = ?, salt = ?, must_change_password = 0 WHERE username = ?;",
            (password_hash, salt, username)
        )
        updated = cur.rowcount > 0
    conn.close()
    return updated


def set_user_pending_totp(username: str, pending_secret: str) -> bool:
    conn = get_db_connection()
    with conn:
        cur = conn.execute(
            "UPDATE users SET totp_pending_secret = ? WHERE username = ?;",
            (pending_secret, username)
        )
        updated = cur.rowcount > 0
    conn.close()
    return updated


def enable_user_totp(username: str, totp_secret: str) -> bool:
    conn = get_db_connection()
    with conn:
        cur = conn.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_pending_secret = '' WHERE username = ?;",
            (totp_secret, username)
        )
        updated = cur.rowcount > 0
    conn.close()
    return updated


def disable_user_totp(username: str) -> bool:
    conn = get_db_connection()
    with conn:
        cur = conn.execute(
            "UPDATE users SET totp_secret = '', totp_enabled = 0, totp_pending_secret = '' WHERE username = ?;",
            (username,)
        )
        updated = cur.rowcount > 0
    conn.close()
    return updated


# ==========================================
# REMOTE PROBE AGENT HELPERS
# ==========================================

def _is_agent_online(last_seen_iso: Optional[str]) -> bool:
    if not last_seen_iso:
        return False
    try:
        dt_str = last_seen_iso.replace("Z", "+00:00")
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        diff = (datetime.now(timezone.utc) - dt).total_seconds()
        return 0 <= diff <= 45
    except Exception:
        return False


def create_agent(org_id: int, name: str) -> Dict[str, Any]:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    token_prefix = token[:8]
    now_iso = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    with conn:
        cur = conn.execute("""
            INSERT INTO agents (org_id, name, token_hash, token_prefix, status, created_at, engines_json)
            VALUES (?, ?, ?, ?, 'offline', ?, '{}');
        """, (org_id, name, token_hash, token_prefix, now_iso))
        agent_id = cur.lastrowid
    conn.close()

    return {
        "id": agent_id,
        "org_id": org_id,
        "name": name,
        "token": token,
        "token_prefix": token_prefix,
        "status": "offline",
        "last_seen": None,
        "hostname": "",
        "ip_address": "",
        "os_info": "",
        "engines": {},
        "version": "1.0.0",
        "created_at": now_iso
    }


def get_agents(org_id: Optional[int] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    if org_id:
        rows = conn.execute("""
            SELECT a.*, o.name as org_name
            FROM agents a
            JOIN organizations o ON a.org_id = o.id
            WHERE a.org_id = ?
            ORDER BY a.id DESC;
        """, (org_id,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT a.*, o.name as org_name
            FROM agents a
            JOIN organizations o ON a.org_id = o.id
            ORDER BY a.id DESC;
        """).fetchall()
    conn.close()

    res = []
    for r in rows:
        item = dict(r)
        item.pop("token_hash", None)
        item["engines"] = json.loads(item.get("engines_json") or "{}")
        online = _is_agent_online(item.get("last_seen"))
        item["status"] = "online" if online else "offline"
        item["is_online"] = online
        res.append(item)
    return res


def get_agent_by_id(agent_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("""
        SELECT a.*, o.name as org_name
        FROM agents a
        JOIN organizations o ON a.org_id = o.id
        WHERE a.id = ?;
    """, (agent_id,)).fetchone()
    conn.close()
    if not row:
        return None

    item = dict(row)
    item.pop("token_hash", None)
    item["engines"] = json.loads(item.get("engines_json") or "{}")
    online = _is_agent_online(item.get("last_seen"))
    item["status"] = "online" if online else "offline"
    item["is_online"] = online
    return item


def get_agent_by_token(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = get_db_connection()
    row = conn.execute("""
        SELECT a.*, o.name as org_name
        FROM agents a
        JOIN organizations o ON a.org_id = o.id
        WHERE a.token_hash = ?;
    """, (token_hash,)).fetchone()
    conn.close()
    if not row:
        return None

    item = dict(row)
    item.pop("token_hash", None)
    item["engines"] = json.loads(item.get("engines_json") or "{}")
    online = _is_agent_online(item.get("last_seen"))
    item["status"] = "online" if online else "offline"
    item["is_online"] = online
    return item


def delete_agent(agent_id: int) -> bool:
    conn = get_db_connection()
    with conn:
        cur = conn.execute("DELETE FROM agents WHERE id = ?;", (agent_id,))
        deleted = cur.rowcount > 0
    conn.close()
    return deleted


def update_agent_heartbeat(
    agent_id: int,
    hostname: str = "",
    ip_address: str = "",
    os_info: str = "",
    engines: Optional[Dict[str, Any]] = None,
    version: str = "1.0.0"
) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    with conn:
        conn.execute("""
            UPDATE agents SET
                last_seen = ?,
                status = 'online',
                hostname = COALESCE(NULLIF(?, ''), hostname),
                ip_address = COALESCE(NULLIF(?, ''), ip_address),
                os_info = COALESCE(NULLIF(?, ''), os_info),
                engines_json = ?,
                version = COALESCE(NULLIF(?, ''), version)
            WHERE id = ?;
        """, (
            now_iso,
            hostname or "",
            ip_address or "",
            os_info or "",
            json.dumps(engines or {}),
            version or "1.0.0",
            agent_id
        ))
    conn.close()

