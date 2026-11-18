import json
import asyncio
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from backend.database import get_db_connection, get_scan_by_id, get_settings, get_organization_by_id
from backend.scanners.native_engine import run_native_net_scan, run_native_ssl_scan, run_native_web_scan
from backend.scanners.nmap_engine import detect_nmap, run_nmap_scan
from backend.scanners.nuclei_engine import detect_nuclei, run_nuclei_scan
from backend.ai_engine import analyze_findings

STOP_FLAGS: Dict[int, bool] = {}
SCAN_THREADS: Dict[int, threading.Thread] = {}
SCAN_CONCURRENCY_SEM = threading.Semaphore(3)


def start_scan_in_background(scan_id: int) -> None:
    STOP_FLAGS[scan_id] = False

    def _worker():
        with SCAN_CONCURRENCY_SEM:
            if STOP_FLAGS.get(scan_id, False):
                return
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_scan_pipeline(scan_id))
            finally:
                try:
                    loop.close()
                except Exception:
                    pass

    t = threading.Thread(target=_worker, daemon=True)
    SCAN_THREADS[scan_id] = t
    t.start()


def stop_scan(scan_id: int) -> bool:
    STOP_FLAGS[scan_id] = True
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        cur = conn.execute("""
            UPDATE scans
            SET status = 'stopped', current_task = ?, completed_at = ?
            WHERE id = ? AND status = 'running';
        """, ("Scansione interrotta dall'utente.", now_iso, scan_id))
        stopped = cur.rowcount > 0
    conn.close()
    return stopped


async def run_scan_pipeline(scan_id: int) -> None:
    conn = get_db_connection()
    scan = get_scan_by_id(scan_id)
    if not scan:
        conn.close()
        return

    org = get_organization_by_id(scan["org_id"]) or {}
    settings = get_settings()

    targets = scan["targets"]
    engines = scan.get("engines", ["native"])
    config = scan.get("config", {})
    profile = scan.get("scan_profile", "standard")

    logs: List[Dict[str, str]] = []

    def append_log(level: str, msg: str):
        time_str = datetime.now().strftime("%H:%M:%S")
        logs.append({"time": time_str, "level": level, "msg": msg})
        try:
            with conn:
                conn.execute("UPDATE scans SET logs_json = ? WHERE id = ?;", (json.dumps(logs), scan_id))
        except Exception:
            pass

    def update_progress(pct: int, task_name: str):
        try:
            with conn:
                conn.execute(
                    "UPDATE scans SET progress = ?, current_task = ? WHERE id = ?;",
                    (pct, task_name, scan_id)
                )
        except Exception:
            pass

    append_log("INFO", f"Inizializzazione scansione UrielScan per target: {targets}")
    update_progress(5, "Inizializzazione motori...")

    all_hosts: Dict[str, Dict[str, Any]] = {}
    all_findings: List[Dict[str, Any]] = []

    try:
        if STOP_FLAGS.get(scan_id, False):
            return

        # -------------------------------------------------------------
        # 1. Nmap Execution (if requested and installed)
        # -------------------------------------------------------------
        nmap_ran_successfully = False
        if "nmap" in engines:
            nmap_det = detect_nmap()
            if nmap_det["installed"]:
                update_progress(20, "Esecuzione Nmap Host Discovery, Service & NSE Scan...")
                append_log("INFO", f"Esecuzione Nmap ({nmap_det['version']}) con discovery host e porte...")

                ports_cfg = config.get("ports", "top-100")
                if isinstance(ports_cfg, list):
                    ports_cfg = ",".join(map(str, ports_cfg))

                custom_nse = config.get("nse_scripts", [])
                nmap_flags_cfg = config.get("nmap_flags") or config.get("nmap_args") or scan.get("nmap_args")

                if not custom_nse:
                    if profile == "full_purple":
                        custom_nse = ["default", "safe"]
                    elif profile == "nse_vuln_sweep":
                        custom_nse = ["vuln"]
                    elif profile == "web_ssl_audit":
                        custom_nse = ["http-security-headers", "ssl-cert", "ssl-enum-ciphers"]

                try:
                    nmap_res = await run_nmap_scan(
                        targets=targets,
                        ports=ports_cfg,
                        nmap_flags=nmap_flags_cfg,
                        nse_scripts=custom_nse,
                        log_callback=append_log
                    )

                    for nh in nmap_res["hosts"]:
                        ip = nh["ip"]
                        all_hosts[ip] = nh

                    all_findings.extend(nmap_res["findings"])
                    nmap_ran_successfully = len(nmap_res["hosts"]) > 0
                except Exception as ne:
                    append_log("ERROR", f"Errore durante l'esecuzione di Nmap: {str(ne)}")
            else:
                append_log("WARN", "Nmap non trovato: continuazione con gli altri motori.")

        if STOP_FLAGS.get(scan_id, False):
            return

        # -------------------------------------------------------------
        # 2. Native Network & Port Scan (Banner Grabbing & Fallback)
        # -------------------------------------------------------------
        if "native" in engines or "native_net" in engines:
            # If Nmap already discovered a multi-host subnet (> 3 hosts), inspect hosts with open ports;
            # if Nmap returned 0 open ports across all live hosts (e.g. timeout/filtering), fall back to scanning all live hosts!
            if nmap_ran_successfully and len(all_hosts) > 3:
                hosts_with_open_ports = [ip for ip, h in all_hosts.items() if len(h.get("ports", [])) > 0]
                if hosts_with_open_ports:
                    native_target_str = ", ".join(hosts_with_open_ports)
                else:
                    append_log("WARN", "[Orchestrator] Nmap non ha restituito porte aperte sugli host attivi: avvio fallback TCP Native Net su tutti gli host rilevati.")
                    native_target_str = ", ".join(all_hosts.keys())
            else:
                native_target_str = ", ".join(all_hosts.keys()) if nmap_ran_successfully else targets

            if native_target_str:
                update_progress(42, "Scansione TCP & Banner Grabbing nativo in corso...")
                append_log("INFO", "Avvio motore di ispezione TCP e banner grabbing nativo UrielScan...")

                custom_ports = config.get("ports") if isinstance(config.get("ports"), list) else None

                net_hosts, net_findings = await run_native_net_scan(
                    targets=native_target_str,
                    ports=custom_ports,
                    log_callback=append_log
                )
                for h in net_hosts:
                    ip = h["ip"]
                    if ip in all_hosts:
                        existing_ports = {p["port"]: p for p in all_hosts[ip].get("ports", [])}
                        for np in h.get("ports", []):
                            if np["port"] not in existing_ports:
                                existing_ports[np["port"]] = np
                            elif np.get("banner") and not existing_ports[np["port"]].get("version"):
                                existing_ports[np["port"]]["version"] = np["banner"][:80]
                        all_hosts[ip]["ports"] = sorted(existing_ports.values(), key=lambda x: x["port"])
                    else:
                        all_hosts[ip] = h
                all_findings.extend(net_findings)

        if STOP_FLAGS.get(scan_id, False):
            return

        # -------------------------------------------------------------
        # 3. Native SSL & Web Inspection
        # -------------------------------------------------------------
        web_port_numbers = {80, 443, 3000, 5000, 7070, 8000, 8008, 8080, 8443, 8888, 9000}
        web_capable_hosts = [
            h["ip"] for h in all_hosts.values()
            if any(p.get("port") in web_port_numbers for p in h.get("ports", []))
        ]
        discovered_web_ports = len(web_capable_hosts) > 0
        should_run_web = ("native" in engines or "native_web" in engines or "native_ssl" in engines)

        if should_run_web:
            # On multi-host/subnet scans, only run SSL/Web audit on hosts with open web/TLS ports;
            # on domain/URL scans, always preserve original targets for SNI & VirtualHost headers
            has_cidr = any("/" in t and t.split("/", 1)[1].isdigit() for t in targets.replace(",", " ").split())
            if not has_cidr:
                web_targets_str = targets
            elif len(all_hosts) > 1 and web_capable_hosts:
                web_targets_str = ", ".join(web_capable_hosts)
            elif len(all_hosts) <= 1:
                web_targets_str = targets
            else:
                web_targets_str = ""
            if web_targets_str:
                update_progress(58, "Audit Crittografia SSL/TLS in corso...")
                ssl_findings = await run_native_ssl_scan(targets=web_targets_str, log_callback=append_log)
                all_findings.extend(ssl_findings)

                update_progress(68, "Audit Applicativo Web OWASP in corso...")
                web_hosts_objs = [all_hosts[ip] for ip in web_capable_hosts if ip in all_hosts] or list(all_hosts.values())
                web_findings = await run_native_web_scan(
                    targets=web_targets_str,
                    discovered_hosts=web_hosts_objs,
                    log_callback=append_log
                )
                all_findings.extend(web_findings)

        if STOP_FLAGS.get(scan_id, False):
            return

        # -------------------------------------------------------------
        # 4. Nuclei Execution (if requested and installed)
        # -------------------------------------------------------------
        if "nuclei" in engines:
            nuclei_det = detect_nuclei()
            if nuclei_det["installed"]:
                has_cidr = any("/" in t and t.split("/", 1)[1].isdigit() for t in targets.replace(",", " ").split())
                nuclei_targets_str = ""
                if not has_cidr:
                    nuclei_targets_str = targets
                elif web_capable_hosts:
                    # Build actual HTTP/HTTPS URLs from discovered web hosts instead of passing a raw CIDR block
                    web_urls: List[str] = []
                    for ip in web_capable_hosts:
                        h_obj = all_hosts.get(ip, {})
                        for p in h_obj.get("ports", []):
                            port_num = p.get("port")
                            if port_num in {80, 8000, 8008, 8080, 8888, 3000, 5000, 9000}:
                                web_urls.append(f"http://{ip}" if port_num == 80 else f"http://{ip}:{port_num}")
                            elif port_num in {443, 8443}:
                                web_urls.append(f"https://{ip}" if port_num == 443 else f"https://{ip}:{port_num}")
                    nuclei_targets_str = ", ".join(dict.fromkeys(web_urls))

                if nuclei_targets_str:
                    update_progress(78, "Esecuzione Nuclei Template & CVE Scan...")
                    append_log("INFO", f"Esecuzione Nuclei ({nuclei_det['version']}) sui percorsi Web: {nuclei_targets_str}")
                    nuclei_findings = await run_nuclei_scan(
                        targets=nuclei_targets_str,
                        tags=config.get("nuclei_tags"),
                        severities=config.get("nuclei_severities"),
                        log_callback=append_log
                    )
                    all_findings.extend(nuclei_findings)
                else:
                    append_log("INFO", "Nessun servizio Web attivo rilevato sulla subnet CIDR: scansione Nuclei saltata.")
            else:
                append_log("WARN", "Nuclei non installato sul server: template nuclei saltati.")

        if STOP_FLAGS.get(scan_id, False):
            return

        # -------------------------------------------------------------
        # 5. Summary & Risk Score Calculation
        # -------------------------------------------------------------
        update_progress(88, "Consolidamento vulnerabilità e calcolo Risk Posture...")
        append_log("INFO", "Consolidamento evidenze e normalizzazione finding...")

        now_iso = datetime.now(timezone.utc).isoformat()

        unique_findings: List[Dict[str, Any]] = []
        seen_keys = set()
        for f in all_findings:
            key = (f.get("host"), f.get("port"), f.get("title"))
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        crit_count = sum(1 for f in unique_findings if f.get("severity") == "critical")
        high_count = sum(1 for f in unique_findings if f.get("severity") == "high")
        med_count = sum(1 for f in unique_findings if f.get("severity") == "medium")
        low_count = sum(1 for f in unique_findings if f.get("severity") == "low")
        info_count = sum(1 for f in unique_findings if f.get("severity") == "info")

        risk_score = min(100, int((crit_count * 25) + (high_count * 15) + (med_count * 5) + (low_count * 2)))
        risk_label = "BASSO"
        if risk_score >= 75:
            risk_label = "CRITICO"
        elif risk_score >= 50:
            risk_label = "ALTO"
        elif risk_score >= 25:
            risk_label = "MEDIO"

        # Ensure hosts discovered exclusively via Web/SSL/Nuclei engines also appear in hosts_list
        for f in unique_findings:
            f_host = f.get("host")
            f_port = f.get("port", 0)
            if f_host and f_host not in all_hosts:
                all_hosts[f_host] = {
                    "ip": f_host,
                    "hostname": f_host,
                    "os": "Web / Application Server",
                    "ports": []
                }
            if f_host and f_port and f_port > 0:
                existing_p = {p["port"] for p in all_hosts[f_host].get("ports", [])}
                if f_port not in existing_p:
                    all_hosts[f_host].setdefault("ports", []).append({
                        "port": int(f_port),
                        "protocol": f.get("protocol", "tcp"),
                        "state": "open",
                        "service": f.get("service", "http/https"),
                        "version": ""
                    })

        hosts_list = list(all_hosts.values())
        summary = {
            "total_hosts": len(hosts_list),
            "up_hosts": len(hosts_list),
            "total_ports": sum(len(h.get("ports", [])) for h in hosts_list),
            "total_findings": len(unique_findings),
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
            "info": info_count,
            "risk_score": risk_score,
            "risk_label": risk_label,
            "engines_used": engines
        }

        with conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?;", (scan_id,))
            for f in unique_findings:
                conn.execute("""
                    INSERT INTO findings (
                        scan_id, org_id, host, port, protocol, service,
                        title, severity, cvss, cve_ids, cwe_id, source_engine,
                        description, evidence, remediation, mitre_tactic, mitre_technique,
                        ai_insight, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?);
                """, (
                    scan_id,
                    scan["org_id"],
                    f.get("host", ""),
                    f.get("port", 0),
                    f.get("protocol", "tcp"),
                    f.get("service", ""),
                    f.get("title", "Finding senza titolo"),
                    f.get("severity", "info"),
                    f.get("cvss", 0.0),
                    f.get("cve_ids", ""),
                    f.get("cwe_id", ""),
                    f.get("source_engine", "native"),
                    f.get("description", ""),
                    f.get("evidence", ""),
                    f.get("remediation", ""),
                    f.get("mitre_tactic", "Discovery"),
                    f.get("mitre_technique", "T1046 - Network Service Discovery"),
                    f.get("ai_insight", ""),
                    now_iso
                ))

        # -------------------------------------------------------------
        # 6. Purple Team AI Analysis
        # -------------------------------------------------------------
        update_progress(94, "Generazione analisi Purple Team con Motore AI...")
        append_log("INFO", "Elaborazione matrice Purple Team (Attack Paths & Remediation Playbook)...")

        ai_res = await analyze_findings(
            scan=scan,
            findings=unique_findings,
            org=org,
            scanner_settings=settings,
            mode="purple_team"
        )

        append_log("INFO", f"Analisi AI completata con successo tramite: {ai_res.get('provider_used')}")
        update_progress(100, "Scansione e analisi completate!")

        if STOP_FLAGS.get(scan_id, False):
            append_log("WARN", "Scansione interrotta dall'utente prima della finalizzazione.")
            return

        with conn:
            conn.execute("""
                UPDATE scans SET
                    status = 'completed',
                    progress = 100,
                    current_task = 'Scansione completata con successo',
                    completed_at = ?,
                    hosts_json = ?,
                    summary_json = ?,
                    logs_json = ?,
                    ai_analysis_json = ?
                WHERE id = ? AND status != 'stopped';
            """, (
                now_iso,
                json.dumps(hosts_list),
                json.dumps(summary),
                json.dumps(logs),
                json.dumps(ai_res),
                scan_id
            ))

    except asyncio.CancelledError:
        append_log("WARN", "Scansione interrotta dall'utente.")
        now_iso = datetime.now(timezone.utc).isoformat()
        with conn:
            conn.execute("UPDATE scans SET status = 'stopped', current_task = 'Scansione interrotta.', completed_at = ? WHERE id = ?;", (now_iso, scan_id))
    except Exception as e:
        err_msg = f"Eccezione critica durante la scansione: {str(e)}"
        append_log("ERROR", err_msg)
        now_iso = datetime.now(timezone.utc).isoformat()
        with conn:
            conn.execute("""
                UPDATE scans SET
                    status = 'failed',
                    current_task = ?,
                    completed_at = ?,
                    logs_json = ?
                WHERE id = ?;
            """, (err_msg, now_iso, json.dumps(logs), scan_id))
    finally:
        SCAN_THREADS.pop(scan_id, None)
        STOP_FLAGS.pop(scan_id, None)
        conn.close()
