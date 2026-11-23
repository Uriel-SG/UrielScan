import os
import html
import json
import uuid
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from backend.database import get_db_connection, get_scan_by_id, get_findings_for_scan, get_organization_by_id, get_settings
from backend.scanners.deduplicator import sort_findings_by_severity
from backend.export_engine import _load_urielscan_logo_bytes

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _esc(val: Any) -> str:
    """Escapes untrusted text for safe HTML interpolation."""
    return html.escape(str(val if val is not None else ""), quote=True)


def _safe_img_data_url(url: Any) -> str:
    """Allows only safe raster/SVG data URIs (filtering out legacy placeholder SVGs)."""
    if not isinstance(url, str):
        return ""
    s = url.strip()
    if s.startswith("data:image/svg+xml;base64,"):
        try:
            decoded = base64.b64decode(s.split("base64,", 1)[1]).decode("utf-8", errors="ignore")
            if "shieldGrad" in decoded or "PURPLE TEAM MSSP" in decoded:
                return ""
        except Exception:
            return ""
        return _esc(s)
    if s.startswith(("data:image/png;base64,", "data:image/jpeg;base64,", "data:image/jpg;base64,", "data:image/webp;base64,", "data:image/gif;base64,")):
        return _esc(s)
    return ""


def _build_recon_html_section(recon: Dict[str, Any], is_it: bool) -> str:
    """Build bilingual HTML section for SubRaptor/httpx/Subzy/DNS Zone/Feroxbuster recon summary."""
    if not isinstance(recon, dict) or not (
        recon.get("total_subdomains")
        or recon.get("dns_zones")
        or recon.get("takeovers")
        or recon.get("directories")
        or recon.get("tech_stack")
        or recon.get("cve_intel")
    ):
        return ""

    sec_title = (
        "Superficie d'Attacco, Stack Tecnologico & CVE/PoC Intel"
        if is_it
        else "Attack Surface, Tech Stack & CVE/PoC Intelligence"
    )
    live_subs = recon.get("live_subdomains") or []
    takeovers = recon.get("takeovers") or []
    dns_zones = recon.get("dns_zones") or []
    dirs = recon.get("directories") or []
    tech_stack = recon.get("tech_stack") or []
    cve_intel = recon.get("cve_intel") or []
    axfr_open = sum(1 for z in dns_zones if z.get("axfr_vulnerable"))
    sources = recon.get("sources") or {}

    src_badges = ""
    for dom, sdict in sources.items():
        if not isinstance(sdict, dict):
            continue
        pills = " ".join(
            f"<span class='badge' style='background:#f1f5f9;color:#1e293b;'>{_esc(src)}: {_esc(info.get('found', 0))} (uniq {_esc(info.get('unique', 0))})</span>"
            for src, info in sdict.items()
            if isinstance(info, dict)
        )
        src_badges += f"<div style='margin:6px 0;font-size:12px;'><strong>{_esc(dom)}:</strong> {pills}</div>"

    sub_rows = ""
    for lr in live_subs[:35]:
        tech_str = ", ".join((lr.get("tech") or [])[:4]) or "-"
        cnames_str = ", ".join(lr.get("cname") or []) or "-"
        sub_rows += (
            f"<tr>"
            f"<td><code>{_esc(lr.get('url') or lr.get('subdomain'))}</code></td>"
            f"<td><strong>{_esc(lr.get('status_code') or '-')}</strong></td>"
            f"<td>{_esc(lr.get('title') or '-')}</td>"
            f"<td>{_esc(tech_str)}</td>"
            f"<td><code>{_esc(cnames_str)}</code></td>"
            f"</tr>"
        )
    sub_table = (
        f"<h4 style='margin:14px 0 6px;font-size:13px;color:#334155;'>"
        + ("Sottodomini HTTP/S Attivi (httpx)" if is_it else "Live HTTP/S Subdomains (httpx)")
        + "</h4><table class='custom-table'><thead><tr>"
        + "<th>URL / Subdomain</th><th>Status</th><th>Title</th><th>Tech</th><th>CNAME</th>"
        + f"</tr></thead><tbody>{sub_rows}</tbody></table>"
        if sub_rows
        else ""
    )

    dns_rows = ""
    for z in dns_zones:
        axfr_lbl = "<span style='color:#dc2626;font-weight:bold;'>OPEN</span>" if z.get("axfr_vulnerable") else "Closed"
        dns_rows += (
            f"<tr>"
            f"<td><strong>{_esc(z.get('domain'))}</strong></td>"
            f"<td>{', '.join(_esc(n) for n in (z.get('nameservers') or [])[:3]) or '-'}</td>"
            f"<td>{axfr_lbl}</td>"
            f"<td>{'Yes' if z.get('wildcard_dns') else 'No'}</td>"
            f"<td>{'OK' if z.get('has_spf') else 'Missing'} / {'OK' if z.get('has_dmarc') else 'Missing'}</td>"
            f"</tr>"
        )
    dns_table = (
        f"<h4 style='margin:14px 0 6px;font-size:13px;color:#334155;'>"
        + ("Audit Zona DNS & AXFR" if is_it else "DNS Zone & AXFR Audit")
        + "</h4><table class='custom-table'><thead><tr>"
        + "<th>Domain</th><th>Nameservers</th><th>AXFR</th><th>Wildcard</th><th>SPF / DMARC</th>"
        + f"</tr></thead><tbody>{dns_rows}</tbody></table>"
        if dns_rows
        else ""
    )

    dir_rows = ""
    for d in dirs[:35]:
        dir_rows += (
            f"<tr>"
            f"<td><strong>{_esc(d.get('status') or '-')}</strong></td>"
            f"<td><code>{_esc(d.get('url') or d.get('path'))}</code></td>"
            f"<td>{_esc(d.get('content_length', 0))} B</td>"
            f"<td>{_esc(d.get('content_type') or '-')}</td>"
            f"</tr>"
        )
    dir_table = (
        f"<h4 style='margin:14px 0 6px;font-size:13px;color:#334155;'>"
        + ("Percorsi Web Enumerati (Feroxbuster)" if is_it else "Discovered Web Paths (Feroxbuster)")
        + "</h4><table class='custom-table'><thead><tr>"
        + "<th>Status</th><th>URL / Path</th><th>Size</th><th>Content-Type</th>"
        + f"</tr></thead><tbody>{dir_rows}</tbody></table>"
        if dir_rows
        else ""
    )

    tech_rows = ""
    for ts in tech_stack[:40]:
        ver_str = _esc(ts.get("version") or "-")
        host_url = _esc(ts.get("url") or ts.get("host") or "-")
        tech_rows += (
            f"<tr>"
            f"<td><strong>{_esc(ts.get('name') or '-')}</strong></td>"
            f"<td><code>{ver_str}</code></td>"
            f"<td>{_esc(ts.get('category') or '-')}</td>"
            f"<td><code>{host_url}</code></td>"
            f"<td>{_esc(ts.get('source') or '-')}</td>"
            f"</tr>"
        )
    tech_table = (
        f"<h4 style='margin:14px 0 6px;font-size:13px;color:#334155;'>"
        + ("Stack Tecnologico Rilevato (Wappalyzer / httpx / Nmap)" if is_it else "Detected Technology Stack (Wappalyzer / httpx / Nmap)")
        + "</h4><table class='custom-table'><thead><tr>"
        + "<th>Product</th><th>Version</th><th>Category</th><th>Host / URL</th><th>Source</th>"
        + f"</tr></thead><tbody>{tech_rows}</tbody></table>"
        if tech_rows
        else ""
    )

    cve_rows = ""
    for ci in cve_intel[:30]:
        kev_badge = "<span style='color:#dc2626;font-weight:bold;'>CISA KEV</span> " if ci.get("is_kev") else ""
        epss_v = f"{float(ci['epss']) * 100:.2f}%" if isinstance(ci.get("epss"), (int, float)) else "-"
        pocs_html = "<br/>".join(
            f"<a href='{_esc(u)}' target='_blank' rel='noopener noreferrer'><code>{_esc(u)}</code></a>"
            for u in (ci.get("poc_urls") or [])[:3]
        ) or "-"
        cve_rows += (
            f"<tr>"
            f"<td><code>{_esc(ci.get('cve_id') or '-')}</code></td>"
            f"<td><strong>{_esc(ci.get('product') or '-')}</strong> {_esc(ci.get('version') or '')}</td>"
            f"<td><strong>{_esc(ci.get('cvss') or '-')}</strong></td>"
            f"<td>{kev_badge}{epss_v}</td>"
            f"<td>{pocs_html}</td>"
            f"</tr>"
        )
    cve_table = (
        f"<h4 style='margin:14px 0 6px;font-size:13px;color:#334155;'>"
        + ("CVE &amp; PoC Intelligence (NVD / CISA KEV / EPSS)" if is_it else "CVE &amp; PoC Intelligence (NVD / CISA KEV / EPSS)")
        + "</h4><table class='custom-table'><thead><tr>"
        + "<th>CVE</th><th>Component</th><th>CVSS</th><th>EPSS / KEV</th><th>Public PoCs</th>"
        + f"</tr></thead><tbody>{cve_rows}</tbody></table>"
        if cve_rows
        else ""
    )

    return f"""
        <h2 class="section-title page-break-before">{_esc(sec_title)}</h2>
        <div class="exec-card" style="margin-bottom:16px;">
            <div style="font-size:13px;display:flex;gap:18px;flex-wrap:wrap;margin-bottom:6px;">
                <span><strong>Subdomains:</strong> {int(recon.get('total_subdomains') or 0)}</span>
                <span><strong>Live HTTP/S:</strong> {len(live_subs)}</span>
                <span><strong>Takeovers (Subzy):</strong> {len(takeovers)}</span>
                <span><strong>AXFR Open:</strong> {axfr_open}</span>
                <span><strong>Directories (Feroxbuster):</strong> {len(dirs)}</span>
                <span><strong>Tech Stack:</strong> {len(tech_stack)}</span>
                <span><strong>CVE Intel:</strong> {len(cve_intel)}</span>
            </div>
            {src_badges}
        </div>
        {dns_table}
        {sub_table}
        {tech_table}
        {cve_table}
        {dir_table}
    """


def _build_cloud_posture_html_section(cloud_posture: Dict[str, Any], is_it: bool) -> str:
    """Build bilingual HTML section for Prowler Cloud Security Posture (CSPM)."""
    if not isinstance(cloud_posture, dict) or not cloud_posture.get("provider"):
        return ""
    sec_title = "Cloud Security Posture (Prowler CSPM)"
    provider = str(cloud_posture.get("provider") or "").upper()
    account = str(cloud_posture.get("account") or "-")
    compliance = str(cloud_posture.get("compliance") or "Default Checks")
    passed = int(cloud_posture.get("passed") or 0)
    failed = int(cloud_posture.get("failed") or 0)
    manual = int(cloud_posture.get("manual") or 0)
    pass_rate = float(cloud_posture.get("pass_rate") or 0.0)
    by_service = cloud_posture.get("by_service") or {}

    svc_rows = ""
    for svc_name, counts in sorted(
        by_service.items(),
        key=lambda kv: int((kv[1] or {}).get("failed", 0)),
        reverse=True,
    )[:25]:
        if not isinstance(counts, dict):
            continue
        svc_rows += (
            f"<tr>"
            f"<td><strong>{_esc(svc_name)}</strong></td>"
            f"<td style='color:#059669;font-weight:bold;'>{int(counts.get('passed', 0))}</td>"
            f"<td style='color:#dc2626;font-weight:bold;'>{int(counts.get('failed', 0))}</td>"
            f"<td>{int(counts.get('manual', 0))}</td>"
            f"</tr>"
        )
    svc_table = (
        f"<h4 style='margin:14px 0 6px;font-size:13px;color:#334155;'>"
        + ("Stato Controlli per Servizio Cloud" if is_it else "Checks Breakdown by Cloud Service")
        + "</h4><table class='custom-table'><thead><tr>"
        + "<th>Service</th><th>Passed</th><th>Failed</th><th>Manual</th>"
        + f"</tr></thead><tbody>{svc_rows}</tbody></table>"
        if svc_rows
        else ""
    )

    return f"""
        <h2 class="section-title page-break-before">{_esc(sec_title)}</h2>
        <div class="exec-card" style="margin-bottom:16px;">
            <div style="font-size:13px;display:flex;gap:18px;flex-wrap:wrap;">
                <span><strong>Provider:</strong> {_esc(provider)}</span>
                <span><strong>Account:</strong> <code>{_esc(account)}</code></span>
                <span><strong>Compliance:</strong> {_esc(compliance)}</span>
                <span><strong>Pass Rate:</strong> {pass_rate:.1f}%</span>
                <span><strong>Passed:</strong> {passed}</span>
                <span><strong>Failed:</strong> {failed}</span>
                <span><strong>Manual:</strong> {manual}</span>
            </div>
        </div>
        {svc_table}
    """


def generate_html_report(
    scan_id: int,
    classification: str = "CONFIDENTIAL - PURPLE TEAM ASSESSMENT",
    custom_title: Optional[str] = None,
    lang: str = "en"
) -> Dict[str, Any]:
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise ValueError(f"Scansione ID {scan_id} non trovata.")

    is_it = (lang or "").lower().startswith("it")
    if is_it and classification == "CONFIDENTIAL - PURPLE TEAM ASSESSMENT":
        classification = "CONFIDENZIALE - PURPLE TEAM ASSESSMENT"
    elif not is_it and classification == "CONFIDENZIALE - PURPLE TEAM ASSESSMENT":
        classification = "CONFIDENTIAL - PURPLE TEAM ASSESSMENT"

    org = get_organization_by_id(scan["org_id"]) or {}
    settings = get_settings()
    findings = sort_findings_by_severity(get_findings_for_scan(scan_id))
    _uriel_raw = _load_urielscan_logo_bytes()
    uriel_logo_uri = f"data:image/png;base64,{base64.b64encode(_uriel_raw).decode('ascii')}" if _uriel_raw else ""

    report_id = f"REP-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    default_client_name = "Cliente" if is_it else "Client"
    report_title = custom_title or (
        f"Rapporto Vulnerability Assessment & Purple Team - {org.get('name', default_client_name)}"
        if is_it else
        f"Vulnerability Assessment & Purple Team Report - {org.get('name', default_client_name)}"
    )
    created_at_iso = datetime.now(timezone.utc).isoformat()
    created_at_human = datetime.now().strftime("%d/%m/%Y %H:%M")

    summary = scan.get("summary", {})
    ai_analysis = scan.get("ai_analysis", {})
    hosts = scan.get("hosts", [])

    # Metrics
    crit_count = summary.get("critical", 0)
    high_count = summary.get("high", 0)
    med_count = summary.get("medium", 0)
    low_count = summary.get("low", 0)
    info_count = summary.get("info", 0)
    risk_score = summary.get("risk_score", 0)

    raw_risk_label = str(summary.get("risk_label", "")).upper()
    if is_it:
        risk_label_map = {"CRITICAL": "CRITICO", "HIGH": "ALTO", "MEDIUM": "MEDIO", "LOW": "BASSO"}
        risk_label = risk_label_map.get(raw_risk_label, raw_risk_label or ("CRITICO" if risk_score >= 75 else ("ALTO" if risk_score >= 50 else ("MEDIO" if risk_score >= 25 else "BASSO"))))
    else:
        risk_label_map = {"CRITICO": "CRITICAL", "ALTO": "HIGH", "MEDIO": "MEDIUM", "BASSO": "LOW"}
        risk_label = risk_label_map.get(raw_risk_label, raw_risk_label or ("CRITICAL" if risk_score >= 75 else ("HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW"))))

    # Colors
    risk_color = "#ef4444" if risk_score >= 75 else ("#f97316" if risk_score >= 50 else ("#eab308" if risk_score >= 25 else "#10b981"))

    # MSP Info
    mssp_name = _esc(settings.get("scanner_company_name", "UrielScan Purple Team MSSP"))
    mssp_logo = _safe_img_data_url(settings.get("scanner_company_logo", ""))
    mssp_email = _esc(settings.get("scanner_company_email", "security@urielscan.io"))
    mssp_web = _esc(settings.get("scanner_company_website", "https://urielscan.io"))
    mssp_addr = _esc(settings.get("scanner_company_address", "Cyber Security Operations Center"))
    default_footer = "Documento Riservato UrielScan Purple Team Assessment" if is_it else "Confidential Document - UrielScan Purple Team Assessment"
    footer_text = _esc(settings.get("report_footer") or default_footer)

    # Client Info
    client_name = _esc(org.get("name") or ("Organizzazione Cliente" if is_it else "Client Organization"))
    client_logo = _safe_img_data_url(org.get("logo_data", ""))
    na_val = "N/D" if is_it else "N/A"
    client_industry = _esc(org.get("industry") or na_val)
    client_contact = _esc(org.get("contact_name") or ("Referente della Sicurezza" if is_it else "Security Contact"))
    client_email = _esc(org.get("contact_email") or na_val)
    client_scope = _esc(org.get("target_scope", scan.get("targets", na_val)))

    if not isinstance(ai_analysis, dict):
        ai_analysis = {}

    # Build HTML sections (all untrusted fields escaped)
    attack_paths_html = ""
    step_prefix = "Fase" if is_it else "Step"
    for ap in (ai_analysis.get("attack_paths") or []):
        if not isinstance(ap, dict):
            continue
        attack_paths_html += f"""
        <div class="card attack-step">
            <div class="step-badge">{step_prefix} {_esc(ap.get('step', 1))}</div>
            <div class="step-content">
                <h4>{_esc(ap.get('title', 'Scenario'))}</h4>
                <p>{_esc(ap.get('details', ''))}</p>
                <span class="mitre-tag">MITRE: {_esc(ap.get('mitre', 'T1046'))}</span>
            </div>
        </div>
        """

    remediation_plan_html = ""
    for rp in (ai_analysis.get("remediation_plan") or []):
        if not isinstance(rp, dict):
            continue
        cmd_box = f"<pre><code>{_esc(rp.get('command'))}</code></pre>" if rp.get("command") else ""
        remediation_plan_html += f"""
        <div class="card remediation-item">
            <span class="prio-tag">{_esc(rp.get('priority', 'P1'))}</span>
            <div class="prio-content">
                <p><strong>{_esc(rp.get('action'))}</strong></p>
                {cmd_box}
            </div>
        </div>
        """

    hosts_table_html = ""
    no_ports_str = "Nessuna porta rilevata" if is_it else "No open ports detected"
    for h in hosts:
        if not isinstance(h, dict):
            continue
        ports_str = ", ".join([
            f"{_esc(p.get('port'))}/{_esc(p.get('protocol', 'tcp'))} ({_esc(p.get('service', ''))})"
            for p in (h.get("ports") or []) if isinstance(p, dict)
        ]) or no_ports_str
        hosts_table_html += f"""
        <tr>
            <td><strong>{_esc(h.get('ip', na_val))}</strong></td>
            <td>{_esc(h.get('hostname', na_val))}</td>
            <td>{_esc(h.get('os', 'Standard Network OS'))}</td>
            <td><small>{ports_str}</small></td>
        </tr>
        """

    findings_dossier_html = ""
    evidence_lbl = "Evidenza Tecnica Raccolta:" if is_it else "Collected Technical Evidence:"
    rem_lbl = "Azioni di Remediation Consigliate:" if is_it else "Recommended Remediation Actions:"
    ai_lbl = "Purple Team AI Insight:"
    service_word = "Servizio:" if is_it else "Service:"
    desc_word = "Descrizione Vulnerabilità:" if is_it else "Vulnerability Description:"
    for idx, f in enumerate(findings, 1):
        sev = str(f.get("severity", "info")).lower()
        sev_color = "#ef4444" if sev == "critical" else ("#f97316" if sev == "high" else ("#eab308" if sev == "medium" else ("#3b82f6" if sev == "low" else "#64748b")))
        cve_badge = f"<span class='badge cve-badge'>{_esc(f.get('cve_ids'))}</span>" if f.get("cve_ids") else ""
        cwe_badge = f"<span class='badge cwe-badge'>{_esc(f.get('cwe_id'))}</span>" if f.get("cwe_id") else ""
        engine_badge = f"<span class='badge engine-badge'>{_esc(str(f.get('source_engine', 'native')).upper())}</span>"

        evidence_html = f"<div class='section-block'><h5>{evidence_lbl}</h5><pre><code>{_esc(f.get('evidence', ''))}</code></pre></div>" if f.get("evidence") else ""
        remediation_html = f"<div class='section-block'><h5>{rem_lbl}</h5><div class='rem-box'>{_esc(f.get('remediation', ''))}</div></div>" if f.get("remediation") else ""
        ai_insight_html = f"<div class='section-block ai-box'><h5>{ai_lbl}</h5><p>{_esc(f.get('ai_insight', ''))}</p></div>" if f.get("ai_insight") else ""

        findings_dossier_html += f"""
        <div class="card finding-card page-break-inside-avoid">
            <div class="finding-header" style="border-left: 6px solid {sev_color};">
                <div class="finding-title-row">
                    <span class="finding-num">#{idx}</span>
                    <h3 class="finding-title">{_esc(f.get('title'))}</h3>
                    <span class="badge sev-badge" style="background-color: {sev_color};">{_esc(sev.upper())}</span>
                </div>
                <div class="finding-meta-row">
                    <span><strong>Asset:</strong> {_esc(f.get('host'))}:{_esc(f.get('port'))}</span>
                    <span><strong>{service_word}</strong> {_esc(f.get('service', na_val))}</span>
                    <span><strong>CVSS:</strong> {_esc(f.get('cvss', 0.0))}</span>
                    {engine_badge}
                    {cve_badge}
                    {cwe_badge}
                </div>
            </div>
            <div class="finding-body">
                <div class="section-block">
                    <h5>{desc_word}</h5>
                    <p>{_esc(f.get('description', ''))}</p>
                </div>
                {evidence_html}
                {remediation_html}
                {ai_insight_html}
                <div class="mitre-footer">
                    <small><strong>MITRE ATT&CK:</strong> {_esc(f.get('mitre_tactic', 'Discovery'))} &bull; {_esc(f.get('mitre_technique', 'T1046 - Network Service Discovery'))}</small>
                </div>
            </div>
        </div>
        """

    print_btn_txt = "Stampa / Salva come PDF" if is_it else "Print / Save as PDF"
    brand_divider_txt = "Eseguito per" if is_it else "Prepared for"
    industry_lbl = "Settore:" if is_it else "Industry:"
    ref_lbl = "Ref:" if is_it else "Contact:"
    date_lbl = "Data Report:" if is_it else "Report Date:"
    scan_lbl = "ID Scansione:" if is_it else "Scan ID:"
    scope_lbl = "Perimetro Target:" if is_it else "Target Scope:"
    risk_score_lbl = "Indice di Rischio Globale" if is_it else "Global Risk Score"
    crit_lbl = "Critiche" if is_it else "Critical"
    high_lbl = "Alte" if is_it else "High"
    med_lbl = "Medie" if is_it else "Medium"
    low_lbl = "Basse" if is_it else "Low"
    info_lbl = "Info"
    sec1_title = "1. Sintesi Esecutiva (Executive Summary)" if is_it else "1. Executive Summary"
    exec_fallback = "Nessuna sintesi disponibile." if is_it else "No executive summary available."
    sec2_title = "2. Matrice Scenari di Attacco & Remediation (Purple Team)" if is_it else "2. Attack Scenarios & Remediation Matrix (Purple Team)"
    red_paths_empty = "<p style='font-size:13px; color:#64748b;'>Nessun percorso di attacco critico evidenziato.</p>" if is_it else "<p style='font-size:13px; color:#64748b;'>No critical attack paths identified.</p>"
    blue_playbook_empty = "<p style='font-size:13px; color:#64748b;'>Nessuna azione urgente richiesta.</p>" if is_it else "<p style='font-size:13px; color:#64748b;'>No urgent remediation actions required.</p>"
    sec3_title = "3. Inventario Asset & Porte Aperte Rilevate" if is_it else "3. Asset Inventory & Detected Open Ports"
    th_ip = "Indirizzo IP" if is_it else "IP Address"
    th_hostname = "Hostname / FQDN"
    th_os = "Sistema Operativo" if is_it else "Operating System"
    th_ports = "Porte e Servizi Attivi" if is_it else "Active Ports & Services"
    hosts_empty = "<tr><td colspan='4'>Nessun host attivo rilevato nel perimetro.</td></tr>" if is_it else "<tr><td colspan='4'>No active hosts detected within the scope.</td></tr>"
    sec4_title = "4. Schede Tecniche Dettagliate delle Vulnerabilità" if is_it else "4. Detailed Technical Vulnerability Dossiers"
    findings_empty = "<p>Nessuna vulnerabilità rilevata durante la scansione.</p>" if is_it else "<p>No vulnerabilities detected during the scan.</p>"
    gen_by = "Generato da UrielScan &bull; Motore:" if is_it else "Generated by UrielScan &bull; Engine:"
    page_txt = "Pagina 1 di 1" if is_it else "Page 1 of 1"
    doc_lang = "it" if is_it else "en"

    html_content = f"""<!DOCTYPE html>
<html lang="{doc_lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title} - {report_id}</title>
    <style>
        :root {{
            --primary: #7c3aed;
            --primary-dark: #6d28d9;
            --text-main: #0f172a;
            --text-muted: #475569;
            --bg-page: #f8fafc;
            --bg-card: #ffffff;
            --border-color: #e2e8f0;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-page);
            color: var(--text-main);
            line-height: 1.5;
            padding: 30px;
        }}
        .container {{
            max-width: 1050px;
            margin: 0 auto;
            background: var(--bg-card);
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.06);
            padding: 40px 50px;
        }}
        .no-print-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #1e293b;
            color: #fff;
            padding: 12px 24px;
            border-radius: 8px;
            margin-bottom: 25px;
        }}
        .btn-print {{
            background: #7c3aed;
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .btn-print:hover {{ background: #6d28d9; }}
        .classification-header {{
            text-align: center;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 2px;
            color: #dc2626;
            border-bottom: 2px solid #fee2e2;
            padding-bottom: 6px;
            margin-bottom: 25px;
        }}
        /* Dual Branding Header */
        .dual-branding {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 25px;
            margin-bottom: 30px;
        }}
        .brand-box {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .brand-logo {{
            max-height: 52px;
            max-width: 180px;
            object-fit: contain;
        }}
        .brand-text h3 {{ font-size: 16px; font-weight: 700; color: #0f172a; }}
        .brand-text p {{ font-size: 11px; color: var(--text-muted); }}
        .brand-divider {{
            font-size: 12px;
            font-weight: 800;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }}

        /* Document Title Area */
        .report-header {{
            text-align: center;
            margin-bottom: 35px;
        }}
        .report-header h1 {{
            font-size: 26px;
            font-weight: 800;
            color: #1e1b4b;
            margin-bottom: 8px;
        }}
        .report-meta {{
            font-size: 13px;
            color: var(--text-muted);
            display: flex;
            justify-content: center;
            gap: 20px;
        }}

        /* Posture Grid */
        .posture-grid {{
            display: grid;
            grid-template-columns: 240px 1fr;
            gap: 20px;
            margin-bottom: 35px;
        }}
        .gauge-card {{
            background: #f8fafc;
            border: 2px solid var(--border-color);
            border-radius: 10px;
            padding: 24px;
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}
        .gauge-value {{
            font-size: 48px;
            font-weight: 900;
            line-height: 1;
            margin: 10px 0 5px 0;
        }}
        .gauge-label {{
            font-size: 12px;
            font-weight: 800;
            letter-spacing: 1px;
            text-transform: uppercase;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 10px;
        }}
        .stat-box {{
            background: #ffffff;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px 8px;
            text-align: center;
        }}
        .stat-box.crit {{ border-top: 4px solid #ef4444; }}
        .stat-box.high {{ border-top: 4px solid #f97316; }}
        .stat-box.med {{ border-top: 4px solid #eab308; }}
        .stat-box.low {{ border-top: 4px solid #3b82f6; }}
        .stat-box.info {{ border-top: 4px solid #64748b; }}
        .stat-val {{ font-size: 24px; font-weight: 800; }}
        .stat-lbl {{ font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-top: 4px; }}

        /* Sections */
        .section-title {{
            font-size: 18px;
            font-weight: 800;
            color: #0f172a;
            border-left: 4px solid var(--primary);
            padding-left: 10px;
            margin: 35px 0 15px 0;
        }}
        .exec-card {{
            background: #f8fafc;
            border-left: 4px solid #7c3aed;
            padding: 20px 24px;
            border-radius: 0 8px 8px 0;
            font-size: 14px;
            color: #1e293b;
            line-height: 1.6;
        }}

        /* Purple Team Attack & Remediation */
        .attack-step {{
            display: flex;
            gap: 16px;
            background: #ffffff;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 18px;
            margin-bottom: 10px;
        }}
        .step-badge {{
            background: #ef4444;
            color: #fff;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 11px;
            height: fit-content;
            white-space: nowrap;
        }}
        .step-content h4 {{ font-size: 14px; margin-bottom: 4px; color: #0f172a; }}
        .step-content p {{ font-size: 13px; color: var(--text-muted); margin-bottom: 6px; }}
        .mitre-tag {{
            font-size: 11px;
            background: #fee2e2;
            color: #991b1b;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-weight: 600;
        }}

        .remediation-item {{
            display: flex;
            gap: 14px;
            background: #ffffff;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 18px;
            margin-bottom: 10px;
        }}
        .prio-tag {{
            background: #10b981;
            color: #fff;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 11px;
            height: fit-content;
            white-space: nowrap;
        }}
        .prio-content p {{ font-size: 13px; margin-bottom: 4px; }}

        /* Tables */
        table.custom-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 13px;
        }}
        table.custom-table th, table.custom-table td {{
            padding: 10px 14px;
            border: 1px solid var(--border-color);
            text-align: left;
        }}
        table.custom-table th {{
            background: #f1f5f9;
            font-weight: 700;
            color: #1e293b;
        }}

        /* Findings Dossier */
        .finding-card {{
            background: #ffffff;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .finding-header {{
            background: #f8fafc;
            padding: 14px 18px;
            border-bottom: 1px solid var(--border-color);
        }}
        .finding-title-row {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
        }}
        .finding-num {{
            font-weight: 800;
            color: #64748b;
            font-size: 13px;
        }}
        .finding-title {{
            font-size: 15px;
            font-weight: 700;
            color: #0f172a;
            flex-grow: 1;
        }}
        .finding-meta-row {{
            font-size: 12px;
            color: var(--text-muted);
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            align-items: center;
        }}
        .badge {{
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 11px;
            color: #fff;
        }}
        .cve-badge {{ background: #dc2626; }}
        .cwe-badge {{ background: #475569; }}
        .engine-badge {{ background: #7c3aed; }}
        .finding-body {{
            padding: 18px;
        }}
        .section-block {{
            margin-bottom: 14px;
        }}
        .section-block h5 {{
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            color: #475569;
            margin-bottom: 5px;
        }}
        .section-block p {{
            font-size: 13px;
            color: #1e293b;
        }}
        pre {{
            background: #0f172a;
            color: #38bdf8;
            padding: 12px;
            border-radius: 6px;
            font-size: 12px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .rem-box {{
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            padding: 10px 14px;
            border-radius: 6px;
            font-size: 13px;
            color: #166534;
        }}
        .ai-box {{
            background: #faf5ff;
            border: 1px solid #e9d5ff;
            padding: 10px 14px;
            border-radius: 6px;
            font-size: 13px;
            color: #6b21a8;
        }}
        .mitre-footer {{
            border-top: 1px dashed var(--border-color);
            padding-top: 8px;
            margin-top: 10px;
            color: #64748b;
        }}

        /* Footer */
        .report-footer {{
            border-top: 2px solid var(--border-color);
            padding-top: 20px;
            margin-top: 40px;
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            color: #94a3b8;
        }}

        @media print {{
            body {{ padding: 0; background: #fff; }}
            .container {{ box-shadow: none; padding: 20px; max-width: 100%; }}
            .no-print-bar {{ display: none; }}
            .page-break-inside-avoid {{ page-break-inside: avoid; }}
            .page-break-before {{ page-break-before: always; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Action Bar (hidden when printing) -->
        <div class="no-print-bar">
            <div>
                <strong>UrielScan White-Label Security Report</strong> &bull; ID: {report_id}
            </div>
            <button class="btn-print" onclick="window.print()">{print_btn_txt}</button>
        </div>

        <!-- Top Bar: Classification (left) + Organization Logo or UrielScan Logo Fallback (top-right) -->
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 0 14px 0; border-bottom: 1px solid var(--border-color); margin-bottom: 16px;">
            <span class="classification-header" style="margin: 0; padding: 4px 10px; border-radius: 4px; text-align: left;">{_esc(classification)}</span>
            {f'<img src="{client_logo or uriel_logo_uri}" alt="{client_name if client_logo else "UrielScan"}" style="max-height: 36px; width: auto; object-fit: contain;" />' if (client_logo or uriel_logo_uri) else '<strong style="font-size:16px; letter-spacing:1px; color:#1e3a5f;">URIELSCAN</strong>'}
        </div>

        <!-- Dual Branding Header -->
        <div class="dual-branding">
            <div class="brand-box">
                {f'<img src="{mssp_logo}" class="brand-logo" alt="MSP Logo"/>' if mssp_logo else ''}
                <div class="brand-text">
                    <h3>{mssp_name}</h3>
                    <p>{mssp_addr}</p>
                    <p>{mssp_email} &bull; {mssp_web}</p>
                </div>
            </div>

            <div class="brand-divider">{brand_divider_txt}</div>

            <div class="brand-box" style="flex-direction: row-reverse; text-align: right;">
                <div class="brand-text">
                    <h3>{client_name}</h3>
                    <p>{industry_lbl} {client_industry}</p>
                    <p>{ref_lbl} {client_contact} ({client_email})</p>
                </div>
            </div>
        </div>

        <!-- Title -->
        <div class="report-header">
            <h1>{_esc(report_title)}</h1>
            <div class="report-meta">
                <span><strong>{date_lbl}</strong> {created_at_human}</span>
                <span><strong>{scan_lbl}</strong> #{scan_id}</span>
                <span><strong>{scope_lbl}</strong> <code>{client_scope}</code></span>
            </div>
        </div>

        <!-- Risk Posture & Stats -->
        <div class="posture-grid">
            <div class="gauge-card">
                <span class="stat-lbl">{risk_score_lbl}</span>
                <div class="gauge-value" style="color: {risk_color};">{risk_score}</div>
                <div class="gauge-label" style="color: {risk_color};">{risk_label}</div>
            </div>
            <div class="stats-grid">
                <div class="stat-box crit">
                    <div class="stat-val" style="color: #ef4444;">{crit_count}</div>
                    <div class="stat-lbl">{crit_lbl}</div>
                </div>
                <div class="stat-box high">
                    <div class="stat-val" style="color: #f97316;">{high_count}</div>
                    <div class="stat-lbl">{high_lbl}</div>
                </div>
                <div class="stat-box med">
                    <div class="stat-val" style="color: #eab308;">{med_count}</div>
                    <div class="stat-lbl">{med_lbl}</div>
                </div>
                <div class="stat-box low">
                    <div class="stat-val" style="color: #3b82f6;">{low_count}</div>
                    <div class="stat-lbl">{low_lbl}</div>
                </div>
                <div class="stat-box info">
                    <div class="stat-val" style="color: #64748b;">{info_count}</div>
                    <div class="stat-lbl">{info_lbl}</div>
                </div>
            </div>
        </div>

        <!-- Executive Summary -->
        <h2 class="section-title">{sec1_title}</h2>
        <div class="exec-card">
            <p>{_esc(ai_analysis.get('executive_summary', exec_fallback))}</p>
        </div>

        <!-- Purple Team Attack Paths & Remediation -->
        <h2 class="section-title">{sec2_title}</h2>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
                <h4 style="font-size: 13px; text-transform: uppercase; color: #ef4444; margin-bottom: 8px;">Red Team - Attack Paths</h4>
                {attack_paths_html or red_paths_empty}
            </div>
            <div>
                <h4 style="font-size: 13px; text-transform: uppercase; color: #10b981; margin-bottom: 8px;">Blue Team - Remediation Playbook</h4>
                {remediation_plan_html or blue_playbook_empty}
            </div>
        </div>

        <!-- Asset Inventory -->
        <h2 class="section-title page-break-before">{sec3_title}</h2>
        <table class="custom-table">
            <thead>
                <tr>
                    <th style="width: 140px;">{th_ip}</th>
                    <th style="width: 200px;">{th_hostname}</th>
                    <th style="width: 180px;">{th_os}</th>
                    <th>{th_ports}</th>
                </tr>
            </thead>
            <tbody>
                {hosts_table_html or hosts_empty}
            </tbody>
        </table>

        {_build_recon_html_section(summary.get("recon") or {}, is_it)}
        {_build_cloud_posture_html_section(summary.get("cloud_posture") or {}, is_it)}

        <!-- Detailed Technical Dossiers -->
        <h2 class="section-title page-break-before">{sec4_title}</h2>
        {findings_dossier_html or findings_empty}

        <!-- Footer -->
        <div class="report-footer">
            <span>{footer_text}</span>
            <span>{gen_by} {_esc(ai_analysis.get('provider_used', 'Purple Team Heuristic'))}</span>
            <span>{page_txt}</span>
        </div>
    </div>
</body>
</html>
"""

    report_file_path = REPORTS_DIR / f"{report_id}.html"
    with open(report_file_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    summary_json = {
        "report_id": report_id,
        "title": report_title,
        "classification": classification,
        "total_findings": len(findings),
        "risk_score": risk_score,
        "risk_label": risk_label,
        "created_at": created_at_iso
    }

    conn = get_db_connection()
    with conn:
        conn.execute("""
            INSERT INTO reports (id, scan_id, org_id, title, classification, created_at, file_path, summary_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            report_id,
            scan_id,
            scan["org_id"],
            report_title,
            classification,
            created_at_iso,
            str(report_file_path),
            json.dumps(summary_json)
        ))
    conn.close()

    return {
        "id": report_id,
        "scan_id": scan_id,
        "org_id": scan["org_id"],
        "title": report_title,
        "classification": classification,
        "created_at": created_at_iso,
        "file_path": str(report_file_path),
        "summary": summary_json
    }
