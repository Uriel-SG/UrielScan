import ssl
import socket
import asyncio
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Callable
import httpx

from backend.scanners.tor_engine import open_proxied_connection, to_httpx_proxy_url

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 587, 636, 993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5000,
    5040, 5357, 5432, 5900, 5985, 6379, 7680, 8000, 8080, 8443, 8888, 9000, 9200, 27017
]

PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 3000: "http-dev", 3306: "mysql",
    3389: "ms-wbt-server", 5000: "http-api", 5040: "windows-rpc", 5357: "ws-discovery",
    5432: "postgresql", 5900: "vnc", 5985: "winrm-http", 6379: "redis",
    7680: "p2p-wudf", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9000: "http-service", 9200: "elasticsearch", 27017: "mongodb"
}

SENSITIVE_PATHS = [
    ("/.env", "File di configurazione ambiente (.env) esposto", "critical", 9.1, "CWE-552", ["DB_PASSWORD", "APP_KEY", "AWS_ACCESS", "SECRET_KEY", "DATABASE_URL"]),
    ("/.git/HEAD", "Repository Git esposto pubblicamente (/.git/HEAD)", "high", 7.5, "CWE-538", ["ref: refs/"]),
    ("/actuator/health", "Spring Boot Actuator Health Endpoint esposto", "medium", 5.3, "CWE-200", ['"status":"UP"', '"status":"UNKNOWN"']),
    ("/phpinfo.php", "Script phpinfo() esposto pubblicamente", "high", 7.5, "CWE-200", ["phpinfo()", "PHP Version", "Configuration File"]),
    ("/swagger.json", "Specifiche API Swagger esposte (swagger.json)", "low", 3.7, "CWE-200", ['"swagger":', '"paths":']),
    ("/openapi.json", "Specifiche API OpenAPI esposte (openapi.json)", "low", 3.7, "CWE-200", ['"openapi":', '"paths":']),
    ("/server-status", "Apache Server Status esposto pubblicamente", "medium", 5.3, "CWE-200", ["Apache Server Status", "Server Version:"]),
    ("/robots.txt", "File robots.txt rilevato", "info", 0.0, "CWE-200", ["User-agent:", "Disallow:"]),
    ("/security.txt", "File security.txt rilevato", "info", 0.0, "CWE-200", ["Contact:", "Expires:"]),
    ("/.well-known/security.txt", "File security.txt (.well-known) rilevato", "info", 0.0, "CWE-200", ["Contact:", "Expires:"]),
]


def _generate_native_port_finding(host: str, port: int, banner: str, service: str) -> Dict[str, Any]:
    b_ev = f"\nPorta {port}/TCP aperta su {host}.\nBanner catturato: {banner}" if banner else f"\nPorta {port}/TCP aperta su {host}."

    if port == 23:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "telnet",
            "title": "Protocollo Telnet Esposto Senza Crittografia (Porta 23)",
            "severity": "high", "cvss": 8.5, "cve_ids": "", "cwe_id": "CWE-319",
            "source_engine": "native_net",
            "description": "Il servizio Telnet trasmette credenziali amministrative e sessioni in chiaro sulla rete senza crittografia.",
            "evidence": b_ev,
            "remediation": "Disattivare immediatamente Telnet e sostituirlo con SSH v2 cifrato.",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1078 - Valid Accounts",
            "ai_insight": "Protocollo legacy privo di crittografia end-to-end soggetto a intercettazione passiva."
        }
    elif port == 6379:
        is_unauth = ("PONG" in banner or "redis_version" in banner)
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "redis",
            "title": "Database Redis Esposto Senza Autenticazione" if is_unauth else "Database In-Memory Redis Esposto (Porta 6379)",
            "severity": "critical" if is_unauth else "high",
            "cvss": 9.8 if is_unauth else 8.0,
            "cve_ids": "CVE-2018-11235", "cwe_id": "CWE-306",
            "source_engine": "native_net",
            "description": "L'istanza Redis accetta comandi non autenticati (PING/INFO) consentendo lettura e scrittura completa del database." if is_unauth else "La porta Redis 6379 è accessibile dalla rete. Rischio di accesso non autorizzato alla memoria di cache.",
            "evidence": b_ev,
            "remediation": "Abilitare requirepass nel file redis.conf ed eseguire il bind esclusivamente su 127.0.0.1.",
            "mitre_tactic": "Credential Access", "mitre_technique": "T1552 - Unsecured Credentials",
            "ai_insight": "Consente potenziale RCE via dump di file o accesso immediato alle chiavi di sessione."
        }
    elif port == 21:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "ftp",
            "title": "Servizio FTP (Porta 21) Esposto in Chiaro",
            "severity": "medium", "cvss": 7.0, "cve_ids": "", "cwe_id": "CWE-319",
            "source_engine": "native_net",
            "description": "Il servizio FTP accetta connessioni sulla porta standard 21. Se non configurato con TLS, trasmette credenziali e file in chiaro.",
            "evidence": b_ev,
            "remediation": "Disabilitare FTP non cifrato e migrare a SFTP o FTPS (FTP over TLS/SSL).",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1078 - Valid Accounts",
            "ai_insight": "Suscettibile a sniffing di rete e man-in-the-middle."
        }
    elif port == 445:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "microsoft-ds",
            "title": "Servizio SMB Microsoft-DS (Porta 445) Rilevato",
            "severity": "medium", "cvss": 7.0, "cve_ids": "", "cwe_id": "CWE-200",
            "source_engine": "native_net",
            "description": "Il protocollo SMB è attivo sulla porta 445. Se esposto a segmenti non attendibili o privo di firma obbligatoria, presenta gravi rischi di attacchi NTLM Relay ed exploit remoti.",
            "evidence": b_ev,
            "remediation": "Bloccare la porta 445 sul firewall perimetrale e abilitare SMB Signing obbligatorio sui server Windows.",
            "mitre_tactic": "Lateral Movement", "mitre_technique": "T1021.002 - SMB/Windows Admin Shares",
            "ai_insight": "Vettore primario di propagazione malware e ransomware sulla rete locale."
        }
    elif port == 135:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "msrpc",
            "title": "Esposizione MSRPC (Microsoft Remote Procedure Call - Porta 135)",
            "severity": "medium", "cvss": 6.5, "cwe_id": "CWE-200",
            "source_engine": "native_net",
            "description": "L'endpoint RPC Microsoft è raggiungibile sulla porta 135/TCP. Permette l'enumerazione di interfacce RPC di sistema, endpoint DCOM e dettagli operativi dell'host.",
            "evidence": b_ev,
            "remediation": "Limitare l'ascolto della porta 135 tramite Windows Defender Firewall ed escluderla dai perimetri pubblici.",
            "mitre_tactic": "Discovery", "mitre_technique": "T1046 - Network Service Discovery",
            "ai_insight": "Utilizzato dagli attaccanti per ricognizione iniziale ed enumerazione endpoint RPC."
        }
    elif port == 139:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "netbios-ssn",
            "title": "Servizio NetBIOS Session Service Esposto (Porta 139)",
            "severity": "medium", "cvss": 5.8, "cwe_id": "CWE-200",
            "source_engine": "native_net",
            "description": "Il servizio NetBIOS Session Service è attivo sulla porta 139. Espone informazioni sul workgroup/dominio Windows e facilita l'enumerazione degli host.",
            "evidence": b_ev,
            "remediation": "Disabilitare NetBIOS over TCP/IP nelle impostazioni di rete avanzate delle schede di interfaccia.",
            "mitre_tactic": "Discovery", "mitre_technique": "T1046 - Network Service Discovery",
            "ai_insight": "Protocollo storico legacy spesso sfruttato in combinazione con NTLM Relay."
        }
    elif port in [3306, 5432, 1433, 1521, 27017]:
        db_names = {3306: "MySQL", 5432: "PostgreSQL", 1433: "Microsoft SQL Server", 1521: "Oracle DB", 27017: "MongoDB"}
        db_name = db_names.get(port, "Database")
        return {
            "host": host, "port": port, "protocol": "tcp", "service": service,
            "title": f"Database {db_name} Esposto sul Perimetro di Rete (Porta {port})",
            "severity": "medium", "cvss": 6.5, "cve_ids": "", "cwe_id": "CWE-306",
            "source_engine": "native_net",
            "description": f"Il server di database {db_name} è raggiungibile sulla porta {port}/TCP. L'esposizione diretta incrementa il rischio di accessi non autorizzati e tentativi di password spraying.",
            "evidence": b_ev,
            "remediation": f"Isolare il database {db_name} su interfaccia localhost o segmentare con firewall consentendo l'accesso ai soli server applicativi dedicati.",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1190 - Exploit Public-Facing Application",
            "ai_insight": "I motori di database non devono mai essere accessibili da reti aperte."
        }
    elif port == 5985:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "winrm-http",
            "title": "Interfaccia Windows Remote Management (WinRM HTTP - Porta 5985)",
            "severity": "medium", "cvss": 6.0, "cwe_id": "CWE-200",
            "source_engine": "native_net",
            "description": "Il servizio WinRM HTTP è in ascolto sulla porta 5985/TCP. Consente sessioni di gestione remota PowerShell.",
            "evidence": b_ev,
            "remediation": "Limitare WinRM con regole firewall restrittive ed impiegare esclusivamente WinRM HTTPS cifrato.",
            "mitre_tactic": "Lateral Movement", "mitre_technique": "T1021.006 - Windows Remote Management",
            "ai_insight": "Vettore potenziale di esecuzione remota di comandi PowerShell."
        }
    elif port == 3389:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "ms-wbt-server",
            "title": "Servizio Microsoft Remote Desktop (RDP) Esposto",
            "severity": "low", "cvss": 4.0, "cwe_id": "CWE-200",
            "source_engine": "native_net",
            "description": "Porta RDP 3389 aperta sul sistema. Esposizione suscettibile a tentativi continui di brute-force o password spraying.",
            "evidence": b_ev,
            "remediation": "Isolare RDP dietro un Gateway VPN con autenticazione a due fattori (MFA) e abilitare Network Level Authentication (NLA).",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1078 - Valid Accounts",
            "ai_insight": "Non esporre mai RDP direttamente sul web senza tunneling cifrato."
        }
    elif port == 22:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": "ssh",
            "title": "Servizio Secure Shell (SSH) Attivo sulla Porta 22",
            "severity": "low", "cvss": 3.7, "cwe_id": "CWE-200",
            "source_engine": "native_net",
            "description": "Il demone SSH è in ascolto sulla porta standard 22/TCP.",
            "evidence": b_ev,
            "remediation": "Disabilitare l'autenticazione password per SSH e utilizzare chiavi Ed25519 con protezione fail2ban.",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1078 - Valid Accounts",
            "ai_insight": "Superficie di autenticazione remota da proteggere con limitazioni per IP."
        }
    elif port in [80, 443, 8000, 8080, 8443, 3000, 5000, 8888, 9000]:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": service,
            "title": f"Superficie Applicativa Web: Porta {port}/TCP Attiva ({service})",
            "severity": "low", "cvss": 3.5, "cwe_id": "CWE-200",
            "source_engine": "native_net",
            "description": f"Servizio web attivo sulla porta {port}/TCP. Sottoposto a verifica delle intestazioni di sicurezza OWASP e percorsi critici.",
            "evidence": b_ev,
            "remediation": "Verificare che i certificati TLS siano validi e configurare gli header di sicurezza HTTP raccomandati da OWASP.",
            "mitre_tactic": "Discovery", "mitre_technique": "T1046 - Network Service Discovery",
            "ai_insight": f"Punto di ingresso web perimetrale ({service})."
        }
    else:
        return {
            "host": host, "port": port, "protocol": "tcp", "service": service,
            "title": f"Servizio di Sistema Attivo sulla Porta {port}/TCP ({service})",
            "severity": "low" if banner else "info",
            "cvss": 3.0 if banner else 2.5,
            "cve_ids": "", "cwe_id": "CWE-200",
            "source_engine": "native_net",
            "description": f"La porta TCP {port} ({service}) risulta aperta ed accetta connessioni. Verificare la necessità operativa del servizio nell'ambito dell'inventario perimetrale.",
            "evidence": b_ev,
            "remediation": f"Ispezionare il processo associato alla porta {port} e valutare l'applicazione di filtri firewall restrittivi.",
            "mitre_tactic": "Discovery", "mitre_technique": "T1046 - Network Service Discovery",
            "ai_insight": f"Servizio di sistema identificato ({service}) sulla porta {port}."
        }


# ==========================================
# 1. NETWORK SCAN MODULE
# ==========================================

async def probe_port(
    ip: str,
    port: int,
    timeout: float = 1.5,
    proxy_url: Optional[str] = None,
) -> Tuple[bool, str]:
    try:
        if proxy_url:
            eff_timeout = max(timeout, 6.0)
            reader, writer = await open_proxied_connection(ip, port, proxy_url, timeout=eff_timeout)
        else:
            conn_coro = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn_coro, timeout=timeout)
    except Exception:
        return False, ""

    banner = ""
    try:
        # Probe banner depending on port
        if port in [80, 8080, 8000]:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 6379:
            writer.write(b"PING\r\nINFO\r\n")
        elif port in [21, 22, 25, 110, 143]:
            pass  # wait for initial server greeting
        else:
            writer.write(b"\r\n")

        await writer.drain()

        read_coro = reader.read(1024)
        data = await asyncio.wait_for(read_coro, timeout=2.5 if proxy_url else 1.2)
        banner = data.decode("utf-8", errors="replace").strip()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return True, banner


async def run_native_net_scan(
    targets: str,
    ports: Optional[List[int]] = None,
    log_callback: Optional[Callable[[str, str], Any]] = None,
    proxy_url: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    def log(level: str, msg: str):
        if log_callback:
            try:
                res = log_callback(level, msg)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception:
                pass

    ports_to_scan = ports or COMMON_PORTS
    raw_entries = [t.strip() for t in targets.replace(",", " ").split() if t.strip()]

    # Expand CIDR subnets lazily (prevent memory exhaustion on /8 or IPv6 /64)
    import ipaddress
    import itertools
    raw_targets: List[str] = []
    for entry in raw_entries:
        is_url = entry.lower().startswith(("http://", "https://"))
        if not is_url and "/" in entry:
            base_p, slash_p = entry.split("/", 1)
            if slash_p.isdigit():
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    host_ips = [str(ip) for ip in itertools.islice(net.hosts(), 256)]
                    if not host_ips and net.num_addresses == 1:
                        host_ips = [str(net.network_address)]
                    log("INFO", f"[Native Net] Fast TCP Host Discovery su subnet {entry} ({len(host_ips)} IP)...")
                    sweep_sem = asyncio.Semaphore(128)
                    live_subnet_ips: List[str] = []

                    async def _quick_ping(candidate_ip: str):
                        async with sweep_sem:
                            for qp in (80, 443, 445, 135, 22, 8080, 53, 3389):
                                ok, _ = await probe_port(candidate_ip, qp, timeout=0.25)
                                if ok:
                                    live_subnet_ips.append(candidate_ip)
                                    return

                    await asyncio.gather(*[_quick_ping(cip) for cip in host_ips])
                    log("INFO", f"[Native Net] Host attivi trovati su {entry}: {len(live_subnet_ips)}")
                    raw_targets.extend(sorted(live_subnet_ips))
                    continue
                except Exception:
                    pass
        raw_targets.append(entry)

    hosts = []
    findings = []

    sem = asyncio.Semaphore(12 if proxy_url else 50)

    for target in raw_targets:
        # Clean target if it has URL scheme
        clean_host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        if proxy_url:
            # Skip local DNS resolution to prevent DNS leaks and support .onion targets
            ip_addr = clean_host
            log("INFO", f"[Native Net] Scansione TCP porte proxied su {clean_host} (risoluzione DNS remota)...")
        else:
            log("INFO", f"[Native Net] Risoluzione DNS per {clean_host}...")

            try:
                loop = asyncio.get_running_loop()
                addr_info = await loop.getaddrinfo(clean_host, None)
                ip_addr = addr_info[0][4][0]
            except Exception as e:
                log("WARN", f"[Native Net] Impossibile risolvere host {clean_host}: {str(e)}")
                continue

            log("INFO", f"[Native Net] Scansione TCP porte su {clean_host} ({ip_addr})...")

        open_ports = []

        async def check_p(p: int):
            async with sem:
                is_open, banner = await probe_port(
                    ip_addr,
                    p,
                    timeout=6.0 if proxy_url else 1.5,
                    proxy_url=proxy_url,
                )
                if is_open:
                    service_name = PORT_SERVICE_MAP.get(p, f"port-{p}")
                    open_ports.append({
                        "port": p,
                        "protocol": "tcp",
                        "service": service_name,
                        "product": banner[:60] if banner else service_name,
                        "version": "",
                        "state": "open",
                        "banner": banner
                    })

                    # Generate structured finding for EVERY open port discovered
                    port_finding = _generate_native_port_finding(clean_host, p, banner, service_name)
                    findings.append(port_finding)

        tasks = [check_p(p) for p in ports_to_scan]
        await asyncio.gather(*tasks)

        open_ports.sort(key=lambda x: x["port"])

        hosts.append({
            "ip": ip_addr,
            "hostname": clean_host,
            "os": "Rilevamento euristico: Network Host",
            "ports": open_ports
        })

        log("INFO", f"[Native Net] Scansione {clean_host} completata: {len(open_ports)} porte aperte rilevate.")

    return hosts, findings


# ==========================================
# 2. SSL/TLS INSPECTION MODULE
# ==========================================

async def run_native_ssl_scan(
    targets: str,
    log_callback: Optional[Callable[[str, str], Any]] = None,
    proxy_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    findings = []
    raw_targets = [t.strip() for t in targets.replace(",", " ").split() if t.strip()]

    def log(level: str, msg: str):
        if log_callback:
            try:
                res = log_callback(level, msg)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception:
                pass

    for target in raw_targets:
        clean_host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        port = 443
        log("INFO", f"[Native SSL] Ispezione SSL/TLS per {clean_host}:{port}...")

        if proxy_url:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                _, tls_writer = await open_proxied_connection(
                    clean_host,
                    port,
                    proxy_url,
                    timeout=8.0,
                    use_tls=True,
                    ssl_context=ctx,
                )
                ssl_obj = tls_writer.get_extra_info("ssl_object")
                cert = ssl_obj.getpeercert(binary_form=False) if ssl_obj else None
                cipher = ssl_obj.cipher() if ssl_obj else None
                version = ssl_obj.version() if ssl_obj else None
                success, err = True, None
                tls_writer.close()
                try:
                    await tls_writer.wait_closed()
                except Exception:
                    pass
            except Exception as e:
                success, cert, cipher, version, err = False, None, None, None, str(e)
        else:
            def _sync_ssl_check():
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    with socket.create_connection((clean_host, port), timeout=3.0) as sock:
                        with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                            cert = ssock.getpeercert(binary_form=False)
                            cipher = ssock.cipher()
                            version = ssock.version()
                            return True, cert, cipher, version, None
                except Exception as e:
                    return False, None, None, None, str(e)

            loop = asyncio.get_running_loop()
            success, cert, cipher, version, err = await loop.run_in_executor(None, _sync_ssl_check)

        if not success:
            continue

        log("INFO", f"[Native SSL] {clean_host} TLS Handshake: Versione={version}, Cipher={cipher[0] if cipher else 'N/A'}")

        # Check protocol version
        if version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
            findings.append({
                "host": clean_host,
                "port": port,
                "protocol": "tcp",
                "service": "https",
                "title": f"Protocollo Crittografico Deprecato Abilitato ({version})",
                "severity": "medium",
                "cvss": 5.9,
                "cve_ids": "CVE-2014-3566",
                "cwe_id": "CWE-326",
                "source_engine": "native_ssl",
                "description": f"Il server negozia connessioni utilizzando {version}, un protocollo crittografico dichiarato obsoleto e vulnerabile.",
                "evidence": f"Negoziazione riuscita con {version} e cipher suite {cipher[0] if cipher else 'N/A'}.",
                "remediation": "Disabilitare TLS 1.0 e TLS 1.1 nella configurazione del server web e supportare solo TLS 1.2 e TLS 1.3.",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "T1573 - Encrypted Channel",
                "ai_insight": "Non conforme ai requisiti PCI-DSS v4.0 e alle linee guida AgID/NIST."
            })

    return findings


# ==========================================
# 3. WEB APPLICATION OWASP/ZAP MODULE
# ==========================================

async def run_native_web_scan(
    targets: str,
    discovered_hosts: Optional[List[Dict[str, Any]]] = None,
    log_callback: Optional[Callable[[str, str], Any]] = None,
    proxy_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    findings = []
    raw_targets = [t.strip() for t in targets.replace(",", " ").split() if t.strip()]

    def log(level: str, msg: str):
        if log_callback:
            try:
                res = log_callback(level, msg)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception:
                pass

    urls_to_test = []
    for t in raw_targets:
        if t.startswith("http://") or t.startswith("https://"):
            urls_to_test.append(t)
        else:
            urls_to_test.append(f"http://{t}")
            urls_to_test.append(f"https://{t}")

    # If hosts have been discovered with open web ports, also test those ports!
    if discovered_hosts:
        web_ports = [80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000]
        for dh in discovered_hosts:
            host_candidates = [dh.get("ip"), dh.get("hostname")]
            for p_info in dh.get("ports", []):
                p_num = p_info.get("port")
                if p_num in web_ports:
                    scheme = "https" if p_num in [443, 8443] else "http"
                    for hc in host_candidates:
                        if hc:
                            clean_hc = hc.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
                            url_cand = f"{scheme}://{clean_hc}:{p_num}"
                            if url_cand not in urls_to_test:
                                urls_to_test.append(url_cand)

    httpx_proxy = to_httpx_proxy_url(proxy_url) if proxy_url else None
    client_timeout = httpx.Timeout(18.0, connect=12.0) if httpx_proxy else httpx.Timeout(5.0)
    # Use a resilient httpx client
    async with httpx.AsyncClient(
        proxy=httpx_proxy,
        verify=False,
        timeout=client_timeout,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) UrielScan/1.0 PurpleTeam"}
    ) as client:
        for base_url in urls_to_test:
            try:
                log("INFO", f"[Native Web] Analisi applicativa OWASP per {base_url}...")
                resp = await client.get(base_url)
            except Exception:
                continue

            parsed_u = urllib.parse.urlparse(base_url)
            host = parsed_u.hostname or base_url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
            port = parsed_u.port or (443 if base_url.startswith("https://") else 80)

            headers = {k.lower(): v for k, v in resp.headers.items()}
            if httpx_proxy and resp.status_code in (403, 429, 503):
                body_head = (resp.text[:1500] if resp.text else "").lower()
                if "cf-ray" in headers or "cloudflare" in body_head or "captcha" in body_head or "just a moment" in body_head:
                    log(
                        "WARN",
                        f"[Native Web] Rilevato possibile blocco WAF/Cloudflare/CAPTCHA via Exit Node su {base_url} (HTTP {resp.status_code}). Ruota il circuito Tor o usa un proxy dedicato.",
                    )

            # 1. Security Headers Audit
            missing_headers = []
            if "content-security-policy" not in headers:
                missing_headers.append("Content-Security-Policy")
            if base_url.startswith("https://") and "strict-transport-security" not in headers:
                missing_headers.append("Strict-Transport-Security (HSTS)")
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                missing_headers.append("X-Frame-Options")
            if "x-content-type-options" not in headers:
                missing_headers.append("X-Content-Type-Options")

            if missing_headers:
                findings.append({
                    "host": host,
                    "port": port,
                    "protocol": "tcp",
                    "service": "http/https",
                    "title": f"Mancanza degli Header di Sicurezza HTTP ({len(missing_headers)} assenti)",
                    "severity": "medium",
                    "cvss": 5.0,
                    "cve_ids": "",
                    "cwe_id": "CWE-693",
                    "source_engine": "native_web",
                    "description": "L'applicazione web non include header protettivi standard raccomandati da OWASP.",
                    "evidence": f"URL: {base_url}\nHeader di sicurezza mancanti:\n- " + "\n- ".join(missing_headers),
                    "remediation": "Configurare il web server (Nginx/Apache/Cloudflare) per iniettare HSTS, CSP, X-Frame-Options: SAMEORIGIN e X-Content-Type-Options: nosniff.",
                    "mitre_tactic": "Impact",
                    "mitre_technique": "T1498 - Network Denial of Service",
                    "ai_insight": "Aumenta l'esposizione a Clickjacking, downgrade HTTP e MIME-sniffing."
                })

            # 2. Information Disclosure via Headers
            server_hdr = headers.get("server", "")
            powered_hdr = headers.get("x-powered-by", "")
            aspnet_hdr = headers.get("x-aspnet-version", "")

            disclosed = []
            if server_hdr and any(c.isdigit() for c in server_hdr):
                disclosed.append(f"Server: {server_hdr}")
            if powered_hdr:
                disclosed.append(f"X-Powered-By: {powered_hdr}")
            if aspnet_hdr:
                disclosed.append(f"X-AspNet-Version: {aspnet_hdr}")

            if disclosed:
                findings.append({
                    "host": host,
                    "port": port,
                    "protocol": "tcp",
                    "service": "http/https",
                    "title": "Information Disclosure: Versioni del Software Web Rivelate negli Header",
                    "severity": "low",
                    "cvss": 3.7,
                    "cve_ids": "",
                    "cwe_id": "CWE-200",
                    "source_engine": "native_web",
                    "description": "I banner di risposta HTTP espongono nomi e versioni esatte del software applicativo o del server web.",
                    "evidence": f"URL: {base_url}\nHeader individuati:\n" + "\n".join(disclosed),
                    "remediation": "Disattivare l'emissione dei dettagli software (es. 'server_tokens off' in Nginx, 'ServerTokens Prod' in Apache, 'expose_php = Off' in php.ini).",
                    "mitre_tactic": "Reconnaissance",
                    "mitre_technique": "T1592 - Gather Victim Host Information",
                    "ai_insight": "Fornisce informazioni preziose agli attaccanti per identificare vulnerabilità versione-specifiche."
                })

            # 3. Cookie Security Audit
            set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [headers.get("set-cookie", "")]
            for sc in set_cookies:
                if not sc:
                    continue
                lower_sc = sc.lower()
                cookie_flags_missing = []
                if "httponly" not in lower_sc:
                    cookie_flags_missing.append("HttpOnly")
                if base_url.startswith("https://") and "secure" not in lower_sc:
                    cookie_flags_missing.append("Secure")
                if "samesite" not in lower_sc:
                    cookie_flags_missing.append("SameSite")

                if cookie_flags_missing:
                    cookie_name = sc.split("=")[0]
                    findings.append({
                        "host": host,
                        "port": port,
                        "protocol": "tcp",
                        "service": "http/https",
                        "title": f"Flag di Sicurezza Incompleti per Cookie ({cookie_name})",
                        "severity": "medium",
                        "cvss": 5.3,
                        "cve_ids": "",
                        "cwe_id": "CWE-614",
                        "source_engine": "native_web",
                        "description": f"Il cookie '{cookie_name}' è impostato senza i flag protettivi raccomandati.",
                        "evidence": f"Set-Cookie: {sc[:120]}\nFlag mancanti: {', '.join(cookie_flags_missing)}",
                        "remediation": "Aggiungere sempre i flag 'HttpOnly', 'Secure' (su HTTPS) e 'SameSite=Lax/Strict' su tutti i cookie di sessione.",
                        "mitre_tactic": "Credential Access",
                        "mitre_technique": "T1539 - Steal Web Session Cookie",
                        "ai_insight": "Senza HttpOnly il cookie è accessibile via script malevoli JavaScript (XSS)."
                    })
                    break  # report once per host

            # 4. CORS Misconfiguration Probe
            try:
                cors_resp = await client.get(
                    base_url,
                    headers={"Origin": "https://evil.urielscan.test"}
                )
                acao = cors_resp.headers.get("access-control-allow-origin", "")
                acac = cors_resp.headers.get("access-control-allow-credentials", "")
                if acao == "*" and acac.lower() == "true":
                    findings.append({
                        "host": host,
                        "port": port,
                        "protocol": "tcp",
                        "service": "http/https",
                        "title": "CORS Misconfiguration Critica: Wildcard con Credenziali Abilitate",
                        "severity": "high",
                        "cvss": 7.5,
                        "cve_ids": "",
                        "cwe_id": "CWE-942",
                        "source_engine": "native_web",
                        "description": "L'endpoint abilita Access-Control-Allow-Origin: * combinato con Access-Control-Allow-Credentials: true.",
                        "evidence": f"Request Origin: https://evil.urielscan.test\nResponse ACAO: {acao}\nResponse ACAC: {acac}",
                        "remediation": "Non consentire credenziali con origin wildcard. Configurare una whitelist esplicita di origini attendibili.",
                        "mitre_tactic": "Initial Access",
                        "mitre_technique": "T1189 - Drive-by Compromise",
                        "ai_insight": "Permette il furto cross-origin di sessioni e dati riservati dell'utente."
                    })
                elif "evil.urielscan.test" in acao and acac.lower() == "true":
                    findings.append({
                        "host": host,
                        "port": port,
                        "protocol": "tcp",
                        "service": "http/https",
                        "title": "CORS Arbitrary Origin Reflection con Credenziali",
                        "severity": "high",
                        "cvss": 7.5,
                        "cve_ids": "",
                        "cwe_id": "CWE-942",
                        "source_engine": "native_web",
                        "description": "Il server riflette acriticamente l'header Origin arbitrario inviato dall'attaccante abilitando i cookie di sessione.",
                        "evidence": f"Request Origin: https://evil.urielscan.test\nResponse ACAO: {acao}\nResponse ACAC: {acac}",
                        "remediation": "Validare rigorosamente l'header Origin con un elenco prefissato di domini autorizzati.",
                        "mitre_tactic": "Initial Access",
                        "mitre_technique": "T1189 - Drive-by Compromise",
                        "ai_insight": "Violazione diretta del principio Same-Origin Policy (SOP)."
                    })
            except Exception:
                pass

            # 5. Sensitive Paths Discovery
            base_root = f"{resp.url.scheme}://{resp.url.netloc}"
            for path, title, sev, cvss_val, cwe, patterns in SENSITIVE_PATHS:
                test_url = f"{base_root}{path}"
                try:
                    p_resp = await client.get(test_url)
                    if p_resp.status_code == 200:
                        content_sample = p_resp.text[:500]
                        matched_pattern = any(p in content_sample for p in patterns)
                        if matched_pattern or (path.startswith("/.git") and "ref:" in content_sample):
                            findings.append({
                                "host": host,
                                "port": port,
                                "protocol": "tcp",
                                "service": "http/https",
                                "title": title,
                                "severity": sev,
                                "cvss": cvss_val,
                                "cve_ids": "",
                                "cwe_id": cwe,
                                "source_engine": "native_web",
                                "description": f"Il percorso riservato '{path}' è accessibile pubblicamente con stato HTTP 200 OK.",
                                "evidence": f"URL: {test_url}\nHTTP 200 OK\nAnteprima contenuto:\n{content_sample[:250]}",
                                "remediation": f"Bloccare tempestivamente l'accesso a '{path}' nella configurazione del web server.",
                                "mitre_tactic": "Discovery" if sev in ["info", "low"] else "Credential Access",
                                "mitre_technique": "T1083 - File and Directory Discovery",
                                "ai_insight": f"Esposizione del file {path} che compromette la riservatezza delle credenziali o del codice sorgente."
                            })
                except Exception:
                    continue

    return findings
