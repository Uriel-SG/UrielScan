import json
import asyncio
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from backend.database import get_db_connection, get_scan_by_id, get_settings, get_organization_by_id
from backend.scanners.native_engine import run_native_net_scan, run_native_ssl_scan, run_native_web_scan
from backend.scanners.nmap_engine import detect_nmap, run_nmap_scan
from backend.scanners.nuclei_engine import detect_nuclei, run_nuclei_scan
from backend.scanners.zap_engine import detect_zap, run_zap_scan, _format_web_urls
from backend.scanners.recon_engine import run_subraptor_pipeline, run_feroxbuster_scan
from backend.scanners.deduplicator import consolidate_findings
from backend.scanners.nat_guard import (
    check_targets_nat_loopback,
    query_external_wan_internetdb,
    filter_loopback_artifacts,
)
from backend.scanners.tor_engine import (
    ensure_tor_running,
    rotate_tor_circuit,
    get_proxy_exit_ip,
    validate_proxy_url,
)
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
    nat_status: Dict[str, Any] = {"has_nat_loopback": False, "details": []}
    wan_info: Dict[str, Any] = {"ok": False, "ports": []}

    onion_mode = bool(config.get("onion_mode"))
    raw_proxy_url = config.get("proxy_url")
    active_proxy_url: Optional[str] = None
    routing_meta: Dict[str, Any] = {
        "mode": "direct",
        "onion_mode": onion_mode,
        "exit_ip": "",
        "is_tor": False,
    }

    try:
        if onion_mode:
            update_progress(8, "Avvio circuito Tor (Onion Routing)...")
            append_log("INFO", "[Onion Routing] Inizializzazione demone Tor e negoziazione circuito anonimo...")
            tor_res = await ensure_tor_running(timeout=90.0, log_callback=append_log)
            if not tor_res.get("ok"):
                raise RuntimeError(
                    f"Modalità Onion attivata ma Tor non è disponibile: {tor_res.get('error', 'avvio fallito')}. Scansione bloccata per prevenire IP leak."
                )
            active_proxy_url = tor_res["proxy_url"]
            await rotate_tor_circuit(int(tor_res.get("control_port", 19051)))
            exit_info = await get_proxy_exit_ip(active_proxy_url, timeout=20.0)
            routing_meta = {
                "mode": "tor",
                "onion_mode": True,
                "proxy_url": active_proxy_url,
                "exit_ip": exit_info.get("ip", ""),
                "is_tor": bool(exit_info.get("is_tor", False)),
            }
            if exit_info.get("ok"):
                append_log(
                    "INFO",
                    f"[Onion Routing] Circuito Tor operativo — Exit IP visibile: {exit_info.get('ip')} (Tor Exit Node={exit_info.get('is_tor')})",
                )
            else:
                append_log(
                    "WARN",
                    f"[Onion Routing] Tunnel SOCKS5 Tor attivo ({active_proxy_url}), verifica exit IP non riuscita: {exit_info.get('error', '')}",
                )
        elif raw_proxy_url:
            active_proxy_url = validate_proxy_url(str(raw_proxy_url))
            if active_proxy_url:
                update_progress(8, "Verifica connettività proxy SOCKS5/HTTP...")
                exit_info = await get_proxy_exit_ip(active_proxy_url, timeout=15.0)
                sanitized_proxy = active_proxy_url.split("@")[-1]
                routing_meta = {
                    "mode": "custom_proxy",
                    "onion_mode": False,
                    "proxy_url": sanitized_proxy,
                    "exit_ip": exit_info.get("ip", ""),
                    "is_tor": bool(exit_info.get("is_tor", False)),
                }
                if exit_info.get("ok"):
                    append_log(
                        "INFO",
                        f"[Proxy Routing] Instradamento tramite {sanitized_proxy} — Exit IP: {exit_info.get('ip')}",
                    )
                else:
                    raise RuntimeError(
                        f"Proxy configurato non raggiungibile ({sanitized_proxy}): {exit_info.get('error', 'errore connessione')}. Scansione bloccata per prevenire IP leak."
                    )

        targets_list = [t.strip() for t in (targets.split(",") if isinstance(targets, str) else targets) if t.strip()]
        if targets_list and not active_proxy_url:
            try:
                nat_status = await asyncio.to_thread(check_targets_nat_loopback, targets_list)
                if nat_status.get("has_nat_loopback") and nat_status.get("egress_public_ip"):
                    egress_ip = nat_status["egress_public_ip"]
                    append_log(
                        "WARN",
                        f"NAT Loopback Guard: target {', '.join(nat_status.get('loopback_targets', []))} corrisponde all'IP pubblico di uscita ({egress_ip}). Verifica WAN esterna e filtro falsi positivi LAN attivo.",
                    )
                    wan_info = await asyncio.to_thread(query_external_wan_internetdb, egress_ip)
            except Exception as nat_exc:
                append_log("WARN", f"NAT Guard pre-check non riuscito: {nat_exc}")
        elif active_proxy_url:
            append_log("INFO", "NAT Loopback Guard disabilitato in modalità Onion/Proxy (traffico instradato verso nodo di uscita esterno).")
        if STOP_FLAGS.get(scan_id, False):
            return

        recon_summary: Dict[str, Any] = {}
        cascaded_web_urls: List[str] = []
        cascaded_hosts: List[str] = []
        if bool(config.get("enable_subdomain_enum")):
            update_progress(12, "SubRaptor Discovery, DNS Zone & Subdomain Takeover...")
            recon_data, sub_findings = await run_subraptor_pipeline(
                targets=targets,
                wordlist_id=config.get("subdomain_wordlist", "passive_only"),
                checks=config.get("subdomain_checks"),
                proxy_url=active_proxy_url,
                onion_mode=onion_mode,
                log_callback=append_log,
            )
            all_findings.extend(sub_findings)
            recon_summary.update(recon_data)

            for lr in recon_data.get("live_subdomains", []):
                sub_host = lr.get("subdomain")
                if sub_host and sub_host not in all_hosts:
                    sub_url = lr.get("url", "")
                    sub_port = 443 if sub_url.startswith("https://") else 80
                    all_hosts[sub_host] = {
                        "ip": lr.get("ip") or sub_host,
                        "hostname": sub_host,
                        "os": f"HTTP/{lr.get('status_code', 200)} {(lr.get('webserver') or '').strip()}".strip(),
                        "ports": [{
                            "port": sub_port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "https" if sub_port == 443 else "http",
                            "version": lr.get("webserver", ""),
                        }],
                    }
                if lr.get("url"):
                    cascaded_web_urls.append(lr["url"])
                if sub_host:
                    cascaded_hosts.append(sub_host)

            if bool(config.get("cascade_subdomains", True)) and cascaded_web_urls:
                lim = max(1, min(int(config.get("cascade_limit", 20) or 20), 50))
                cascaded_web_urls = list(dict.fromkeys(cascaded_web_urls))[:lim]
                cascaded_hosts = list(dict.fromkeys(cascaded_hosts))[:lim]
                append_log(
                    "INFO",
                    f"[Orchestrator] Passaggio di {len(cascaded_web_urls)} sottodomini HTTP/S vivi ai motori Web.",
                )
            else:
                cascaded_web_urls = []
                cascaded_hosts = []

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
                        log_callback=append_log,
                        onion_mode=onion_mode,
                        proxy_url=active_proxy_url,
                    )

                    for nh in nmap_res["hosts"]:
                        ip = nh["ip"]
                        all_hosts[ip] = nh

                    all_findings.extend(nmap_res["findings"])
                    nmap_ran_successfully = (len(nmap_res["hosts"]) > 0) and not nmap_res.get("skipped_for_proxy", False)
                except Exception as ne:
                    append_log("ERROR", f"Errore durante l'esecuzione di Nmap: {str(ne)}")
            else:
                append_log("WARN", "Nmap non trovato: continuazione con gli altri motori.")

        if STOP_FLAGS.get(scan_id, False):
            return

        # -------------------------------------------------------------
        # 2. Native Network & Port Scan (Banner Grabbing & Fallback)
        # -------------------------------------------------------------
        should_run_native_net = (
            "native" in engines
            or "native_net" in engines
            or (bool(active_proxy_url) and "nmap" in engines and not nmap_ran_successfully)
        )
        if should_run_native_net:
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
                    log_callback=append_log,
                    proxy_url=active_proxy_url,
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
                base_web = targets
            elif len(all_hosts) > 1 and web_capable_hosts:
                base_web = ", ".join(web_capable_hosts)
            elif len(all_hosts) <= 1:
                base_web = targets
            else:
                base_web = ""

            if cascaded_hosts:
                existing_toks = [x.strip() for x in base_web.split(",") if x.strip()]
                for ch in cascaded_hosts:
                    if ch not in existing_toks:
                        existing_toks.append(ch)
                web_targets_str = ", ".join(existing_toks)
            else:
                web_targets_str = base_web

            if web_targets_str:
                update_progress(58, "Audit Crittografia SSL/TLS in corso...")
                ssl_findings = await run_native_ssl_scan(
                    targets=web_targets_str,
                    log_callback=append_log,
                    proxy_url=active_proxy_url,
                )
                all_findings.extend(ssl_findings)

                update_progress(68, "Audit Applicativo Web OWASP in corso...")
                web_hosts_objs = [all_hosts[ip] for ip in web_capable_hosts if ip in all_hosts] or list(all_hosts.values())
                web_findings = await run_native_web_scan(
                    targets=web_targets_str,
                    discovered_hosts=web_hosts_objs,
                    log_callback=append_log,
                    proxy_url=active_proxy_url,
                )
                all_findings.extend(web_findings)

        if STOP_FLAGS.get(scan_id, False):
            return

        # -------------------------------------------------------------
        # 4. Nuclei, 4b. OWASP ZAP & 4c. Feroxbuster Directory Enum
        # -------------------------------------------------------------
        def _resolve_web_target_urls() -> str:
            base_urls: List[str] = []
            has_cidr = any("/" in t and t.split("/", 1)[1].isdigit() for t in targets.replace(",", " ").split())
            if not has_cidr:
                base_urls.extend(_format_web_urls(targets) or [t.strip() for t in targets.split(",") if t.strip()])
            elif web_capable_hosts:
                for ip in web_capable_hosts:
                    h_obj = all_hosts.get(ip, {})
                    for p in h_obj.get("ports", []):
                        port_num = p.get("port")
                        if port_num in {80, 8000, 8008, 8080, 8888, 3000, 5000, 9000}:
                            base_urls.append(f"http://{ip}" if port_num == 80 else f"http://{ip}:{port_num}")
                        elif port_num in {443, 8443}:
                            base_urls.append(f"https://{ip}" if port_num == 443 else f"https://{ip}:{port_num}")
            if cascaded_web_urls:
                base_urls.extend(cascaded_web_urls)
            return ", ".join(dict.fromkeys(u for u in base_urls if u))

        web_scan_targets_str = (
            _resolve_web_target_urls()
            if ("nuclei" in engines or "zap" in engines or bool(config.get("enable_dir_enum")))
            else ""
        )

        if "nuclei" in engines:
            nuclei_det = detect_nuclei()
            if nuclei_det["installed"]:
                if web_scan_targets_str:
                    update_progress(75, "Esecuzione Nuclei Template & CVE Scan...")
                    append_log("INFO", f"Esecuzione Nuclei ({nuclei_det['version']}) sui percorsi Web: {web_scan_targets_str}")
                    nuclei_findings = await run_nuclei_scan(
                        targets=web_scan_targets_str,
                        tags=config.get("nuclei_tags"),
                        severities=config.get("nuclei_severities"),
                        log_callback=append_log,
                        proxy_url=active_proxy_url,
                    )
                    all_findings.extend(nuclei_findings)
                else:
                    append_log("INFO", "Nessun servizio Web attivo rilevato sulla subnet CIDR: scansione Nuclei saltata.")
            else:
                append_log("WARN", "Nuclei non installato sul server: template nuclei saltati.")

        if STOP_FLAGS.get(scan_id, False):
            return

        if "zap" in engines:
            zap_det = detect_zap()
            if zap_det["installed"]:
                if web_scan_targets_str:
                    zap_mode = config.get("zap_mode", "baseline")
                    update_progress(82, "Esecuzione OWASP ZAP Web Application Scan...")
                    append_log("INFO", f"Esecuzione {zap_det['version']} ({zap_mode}) su: {web_scan_targets_str}")
                    zap_findings = await run_zap_scan(
                        targets=web_scan_targets_str,
                        zap_mode=zap_mode,
                        log_callback=append_log,
                        proxy_url=active_proxy_url,
                    )
                    all_findings.extend(zap_findings)
                else:
                    append_log("INFO", "Nessun servizio Web attivo rilevato sulla subnet CIDR: scansione OWASP ZAP saltata.")
            else:
                append_log("WARN", "OWASP ZAP non rilevato (daemon API/CLI assente): modulo ZAP saltato.")

        if STOP_FLAGS.get(scan_id, False):
            return

        if bool(config.get("enable_dir_enum")):
            ferox_urls = list(dict.fromkeys(_format_web_urls(targets) + cascaded_web_urls))
            if not ferox_urls and web_capable_hosts:
                ferox_urls = [f"http://{ip}" for ip in web_capable_hosts[:4]]
            if ferox_urls:
                update_progress(86, "Enumerazione directory Web con Feroxbuster...")
                dirs_found, dir_findings = await run_feroxbuster_scan(
                    urls=ferox_urls,
                    wordlist_id=config.get("dir_wordlist", "dirbuster_medium"),
                    extensions=config.get("dir_extensions"),
                    recursion=bool(config.get("dir_recursion", False)),
                    rate_limit=int(config.get("dir_rate_limit", 100) or 100),
                    time_limit=int(config.get("dir_time_limit", 180) or 180),
                    proxy_url=active_proxy_url,
                    log_callback=append_log,
                )
                all_findings.extend(dir_findings)
                recon_summary["directories"] = dirs_found
            else:
                append_log("WARN", "[Feroxbuster] Nessun URL Web valido rilevato per l'enumerazione delle directory.")

        if STOP_FLAGS.get(scan_id, False):
            return

        # -------------------------------------------------------------
        # 5. Summary, Cross-Engine Deduplication & Risk Score Calculation
        # -------------------------------------------------------------
        update_progress(88, "Consolidamento vulnerabilità e calcolo Risk Posture...")
        append_log("INFO", "Deduplicazione cross-motore (ZAP/Nuclei/Nmap/Native) e ordinamento per severità...")

        now_iso = datetime.now(timezone.utc).isoformat()

        unique_findings = consolidate_findings(all_findings)

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
        nat_stats: Dict[str, Any] = {}
        if not active_proxy_url and nat_status.get("has_nat_loopback") and nat_status.get("egress_public_ip"):
            hosts_list, unique_findings, nat_stats = filter_loopback_artifacts(
                nat_status.get("details", []),
                hosts_list,
                unique_findings,
                wan_info,
                nat_status["egress_public_ip"],
                locale=settings.get("locale", "en"),
            )
            append_log(
                "INFO",
                f"NAT Loopback Guard completato: porte esterne={nat_stats.get('confirmed_wan_ports', [])}, soppressi {nat_stats.get('suppressed_findings', 0)} finding hairpin.",
            )

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
            "engines_used": engines,
            "nat_loopback_detected": bool(nat_stats),
            "nat_guard": nat_stats,
            "routing": routing_meta,
            **({"recon": recon_summary} if recon_summary else {}),
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
