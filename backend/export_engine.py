import io
import re
import csv
import struct
import base64
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

from backend.scanners.deduplicator import sort_findings_by_severity

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_urielscan_logo_bytes() -> Optional[bytes]:
    """Loads the official UrielScan PNG logo for report headers."""
    for rel in (
        BASE_DIR / "frontend" / "dist" / "urielscan-header-uriel-ops.png",
        BASE_DIR / "frontend" / "public" / "urielscan-header-uriel-ops.png",
        BASE_DIR / "frontend" / "dist" / "urielscan-header.png",
        BASE_DIR / "frontend" / "public" / "urielscan-header.png",
    ):
        if rel.is_file():
            try:
                return rel.read_bytes()
            except Exception:
                pass
    return None


def _png_dimensions(png_bytes: bytes) -> Tuple[int, int]:
    """Reads width and height from a PNG IHDR chunk (fallback 400x76)."""
    try:
        if png_bytes[:8] == b"\x89PNG\r\n\x1a\n" and len(png_bytes) >= 24:
            w, h = struct.unpack(">II", png_bytes[16:24])
            if w > 0 and h > 0:
                return w, h
    except Exception:
        pass
    return 400, 76


def _detect_image_meta(img_bytes: bytes) -> Tuple[str, str, int, int]:
    """Return (ext, mime, width, height) for PNG or JPEG raster images."""
    if img_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        w, h = _png_dimensions(img_bytes)
        return "png", "image/png", w, h
    if img_bytes[:2] == b"\xff\xd8":
        w, h = 400, 120
        try:
            idx = 2
            while idx + 4 < len(img_bytes):
                if img_bytes[idx] != 0xFF:
                    idx += 1
                    continue
                marker = img_bytes[idx + 1]
                if marker in (0xC0, 0xC1, 0xC2):
                    if idx + 9 <= len(img_bytes):
                        h, w = struct.unpack(">HH", img_bytes[idx + 5 : idx + 9])
                    break
                if marker in (0xD8, 0xD9, 0x01) or (0xD0 <= marker <= 0xD7):
                    idx += 2
                else:
                    seg_len = struct.unpack(">H", img_bytes[idx + 2 : idx + 4])[0]
                    idx += 2 + seg_len
        except Exception:
            pass
        return "jpeg", "image/jpeg", max(1, w), max(1, h)
    return "png", "image/png", 400, 120

_XML_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _clean_xml_text(val: Any) -> str:
    """Strips control chars disallowed in XML 1.0 before escaping."""
    return _XML_CTRL_CHARS_RE.sub(" ", str(val or ""))


def _sanitize_csv_cell(val: Any) -> Any:
    """Prevents CSV/Excel formula injection (CWE-1236) on cells starting with = + - @ tab CR."""
    if not isinstance(val, str):
        return val
    stripped = val.lstrip()
    if stripped and stripped[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{val}"
    return val

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image as RLImage,
    PageBreak,
)


def _decode_data_url_image(data_url: str) -> Optional[bytes]:
    """Extracts raw image bytes from a base64 data URL (PNG/JPEG) for PDF embedding."""
    if not data_url or not isinstance(data_url, str) or "base64," not in data_url:
        return None
    header, b64_part = data_url.split("base64,", 1)
    header_lower = header.lower()
    if "image/png" not in header_lower and "image/jpeg" not in header_lower and "image/jpg" not in header_lower:
        return None
    try:
        return base64.b64decode(b64_part)
    except Exception:
        return None


def _safe_para_text(text: Any) -> str:
    """Escapes text for ReportLab Paragraph XML markup."""
    raw = _clean_xml_text(text)
    return (
        raw.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )


def export_scan_results_csv(
    scans_meta: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    org_map: Dict[int, Dict[str, Any]],
    lang: str = "en",
) -> bytes:
    """Generates a UTF-8 BOM CSV containing all findings sorted by severity."""
    findings = sort_findings_by_severity(findings)
    is_it = (lang or "").lower().startswith("it")
    scan_name_map = {s["id"]: s.get("name", f"Scan #{s['id']}") for s in scans_meta}
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    if is_it:
        writer.writerow([
            "ID",
            "Organizzazione",
            "Scansione",
            "Host",
            "Porta",
            "Protocollo",
            "Servizio",
            "Severita",
            "CVSS",
            "Titolo",
            "Motore",
            "Stato",
            "CVE",
            "CWE",
            "Descrizione",
            "Remediation",
            "Evidenza",
        ])
    else:
        writer.writerow([
            "ID",
            "Organization",
            "Scan",
            "Host",
            "Port",
            "Protocol",
            "Service",
            "Severity",
            "CVSS",
            "Title",
            "Engine",
            "Status",
            "CVE",
            "CWE",
            "Description",
            "Remediation",
            "Evidence",
        ])
    for f in findings:
        org_name = org_map.get(f.get("org_id"), {}).get("name", f"Org #{f.get('org_id', '')}")
        scan_name = scan_name_map.get(f.get("scan_id"), f"Scan #{f.get('scan_id', '')}")
        writer.writerow([
            _sanitize_csv_cell(col) for col in [
                f.get("id", ""),
                org_name,
                scan_name,
                f.get("host", ""),
                f.get("port", "") or "",
                f.get("protocol", "tcp"),
                f.get("service", ""),
                str(f.get("severity", "info")).upper(),
                f.get("cvss", 0.0),
                f.get("title", ""),
                f.get("source_engine", ""),
                f.get("status", "open"),
                f.get("cve_ids", ""),
                f.get("cwe_id", ""),
                (f.get("description") or "").replace("\r\n", " ").replace("\n", " "),
                (f.get("remediation") or "").replace("\r\n", " ").replace("\n", " "),
                (f.get("evidence") or "").replace("\r\n", " | ").replace("\n", " | "),
            ]
        ])
    return ("\ufeff" + buf.getvalue()).encode("utf-8")


def export_scan_results_txt(
    title: str,
    targets: str,
    hosts: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    org_map: Dict[int, Dict[str, Any]],
    lang: str = "en",
) -> bytes:
    """Generates a clean plain-text (.txt) report of hosts, ports, and findings sorted by severity."""
    findings = sort_findings_by_severity(findings)
    is_it = (lang or "").lower().startswith("it")
    now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
    lines: List[str] = [
        "=" * 78,
        "URIELSCAN - ESPORTAZIONE RISULTATI SCANSIONE" if is_it else "URIELSCAN - SCAN RESULTS EXPORT",
        "=" * 78,
        f"{'Titolo     ' if is_it else 'Title      '}: {title}",
        f"{'Target     ' if is_it else 'Target     '}: {targets}",
        f"{'Data Export' if is_it else 'Export Date'}: {now_str}",
        f"{'Host Attivi' if is_it else 'Active Hosts'}: {len(hosts)} | {'Finding Totali' if is_it else 'Total Findings'}: {len(findings)}",
        "",
    ]

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    if is_it:
        lines.append(
            f"Riepilogo Severita -> CRITICA: {sev_counts['critical']} | ALTA: {sev_counts['high']} | "
            f"MEDIA: {sev_counts['medium']} | BASSA: {sev_counts['low']} | INFO: {sev_counts['info']}"
        )
    else:
        lines.append(
            f"Severity Summary -> CRITICAL: {sev_counts['critical']} | HIGH: {sev_counts['high']} | "
            f"MEDIUM: {sev_counts['medium']} | LOW: {sev_counts['low']} | INFO: {sev_counts['info']}"
        )
    lines.append("")

    if hosts:
        lines.append("-" * 78)
        lines.append("1. TOPOLOGIA HOST E PORTE APERTE" if is_it else "1. HOST TOPOLOGY AND OPEN PORTS")
        lines.append("-" * 78)
        no_ports_str = "Nessuna porta TCP aperta" if is_it else "No open TCP ports"
        na_os_str = "N/D" if is_it else "N/A"
        for h in hosts:
            ports_txt = ", ".join(
                f"{p.get('port')}/{p.get('protocol', 'tcp')} ({p.get('service', 'tcp')})"
                for p in h.get("ports", [])
            ) or no_ports_str
            lines.append(f"- {h.get('ip')} ({h.get('hostname', h.get('ip'))}) | OS/Vendor: {h.get('os', na_os_str)}")
            lines.append(f"  {'Porte' if is_it else 'Ports'}: {ports_txt}")
        lines.append("")

    lines.append("-" * 78)
    lines.append("2. ELENCO DETTAGLIATO RISULTATI" if is_it else "2. DETAILED FINDINGS LIST")
    lines.append("-" * 78)
    if not findings:
        lines.append("Nessun risultato registrato." if is_it else "No findings recorded.")
    else:
        org_lbl = "Organizzazione" if is_it else "Organization"
        engine_lbl = "Motore" if is_it else "Engine"
        status_lbl = "Stato" if is_it else "Status"
        desc_lbl = "Descrizione" if is_it else "Description"
        ev_lbl = "Evidenza" if is_it else "Evidence"
        for idx, f in enumerate(findings, 1):
            org_name = org_map.get(f.get("org_id"), {}).get("name", f"Org #{f.get('org_id', '')}")
            port_part = f":{f.get('port')}/{f.get('protocol', 'tcp')}" if f.get("port") else ""
            lines.append(
                f"[{idx}] [{str(f.get('severity', 'info')).upper()} | CVSS {float(f.get('cvss') or 0):.1f}] {f.get('title', '')}"
            )
            lines.append(
                f"    {org_lbl}: {org_name} | Target: {f.get('host', '')}{port_part} | {engine_lbl}: {f.get('source_engine', '')} | {status_lbl}: {f.get('status', 'open')}"
            )
            if f.get("cve_ids"):
                lines.append(f"    CVE: {f.get('cve_ids')}")
            if f.get("description"):
                lines.append(f"    {desc_lbl}: {f.get('description')}")
            if f.get("remediation"):
                lines.append(f"    Remediation: {f.get('remediation')}")
            if f.get("evidence"):
                ev_clean = str(f.get("evidence")).replace("\n", "\n      ")
                lines.append(f"    {ev_lbl}:\n      {ev_clean}")
            lines.append("")

    return "\n".join(lines).encode("utf-8")


def generate_pdf_document(
    report_title: str,
    classification: str,
    mssp_profile: Dict[str, Any],
    client_org: Dict[str, Any],
    targets: str,
    hosts: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    executive_notes: str = "",
    ai_analysis: Optional[Dict[str, Any]] = None,
    include_ai: bool = True,
    include_evidence: bool = True,
    include_host_topology: bool = True,
    org_map: Optional[Dict[int, Dict[str, Any]]] = None,
    lang: str = "en",
    recon_summary: Optional[Dict[str, Any]] = None,
) -> bytes:
    """Generates a structured, printable A4 PDF report/export using ReportLab."""
    findings = sort_findings_by_severity(findings)
    is_it = (lang or "").lower().startswith("it")
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=report_title,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "UrielTitle",
        parent=styles["Heading1"],
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#111827"),
        spaceAfter=4,
    )
    h2_style = ParagraphStyle(
        "UrielH2",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#1e3a5f"),
        spaceBefore=10,
        spaceAfter=5,
    )
    body_style = ParagraphStyle(
        "UrielBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12.5,
        textColor=colors.HexColor("#1f2937"),
    )
    mono_style = ParagraphStyle(
        "UrielMono",
        parent=styles["Code"],
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#111827"),
        backColor=colors.HexColor("#f3f4f6"),
    )
    small_muted = ParagraphStyle(
        "UrielMuted",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#4b5563"),
    )

    story: List[Any] = []

    # Header: MSSP / classification on left; organization logo on right (fallback to UrielScan logo only if org has none)
    mssp_name = mssp_profile.get("scanner_company_name") or mssp_profile.get("company_name") or "UrielScan MSSP"
    client_name = client_org.get("name") or ("Organizzazione Cliente" if is_it else "Client Organization")
    now_str = datetime.now().strftime("%d/%m/%Y %H:%M")

    client_logo_bytes = _decode_data_url_image(client_org.get("logo_data") or client_org.get("logo_url") or "")
    header_logo_bytes = client_logo_bytes if client_logo_bytes else _load_urielscan_logo_bytes()
    header_logo_img = None
    if header_logo_bytes:
        try:
            _, _, pw, ph = _detect_image_meta(header_logo_bytes)
            target_w = (34 * mm) if client_logo_bytes else (42 * mm)
            target_h = target_w * (ph / pw)
            header_logo_img = RLImage(io.BytesIO(header_logo_bytes), width=target_w, height=target_h, kind="proportional")
            header_logo_img.hAlign = "RIGHT"
        except Exception:
            header_logo_img = None

    date_lbl = "Data" if is_it else "Date"
    header_left = Paragraph(
        f"<b>{_safe_para_text(mssp_name)}</b><br/><font size=8 color='#4b5563'>{_safe_para_text(classification)} | {date_lbl}: {now_str}</font>",
        body_style,
    )
    if header_logo_img is not None:
        right_cell: Any = header_logo_img
    else:
        right_cell = Paragraph(
            "<b>URIELSCAN</b>",
            ParagraphStyle("HdrRightFallback", parent=body_style, alignment=2),
        )

    hdr_table = Table([[header_left, right_cell]], colWidths=[128 * mm, 52 * mm])
    hdr_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (-1, 0), (-1, 0), "RIGHT"),
        ("LINEBELOW", (0, 0), (-1, -1), 1, colors.HexColor("#1e3a5f")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(hdr_table)
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph(_safe_para_text(report_title), title_style))
    org_lbl = "Organizzazione" if is_it else "Organization"
    story.append(
        Paragraph(
            f"<b>{org_lbl}:</b> {_safe_para_text(client_name)} | <b>Target Scope:</b> {_safe_para_text(targets)}",
            small_muted,
        )
    )
    story.append(Spacer(1, 4 * mm))

    # Executive notes
    if executive_notes:
        story.append(Paragraph("1. Sintesi Esecutiva" if is_it else "1. Executive Summary", h2_style))
        story.append(Paragraph(_safe_para_text(executive_notes), body_style))
        story.append(Spacer(1, 3 * mm))

    # Severity KPI summary table
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    kpi_cols = ["Critiche", "Alte", "Medie", "Basse", "Info", "Totale"] if is_it else ["Critical", "High", "Medium", "Low", "Info", "Total"]
    kpi_data = [
        kpi_cols,
        [
            str(sev_counts["critical"]),
            str(sev_counts["high"]),
            str(sev_counts["medium"]),
            str(sev_counts["low"]),
            str(sev_counts["info"]),
            str(len(findings)),
        ],
    ]
    kpi_table = Table(kpi_data, colWidths=[30 * mm] * 6)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 4 * mm))

    # AI or Standard Template Section
    if include_ai and isinstance(ai_analysis, dict) and (ai_analysis.get("executive_summary") or ai_analysis.get("remediation_plan")):
        story.append(Paragraph("2. Analisi Strategica & Remediation" if is_it else "2. Strategic Analysis & Remediation", h2_style))
        if ai_analysis.get("executive_summary"):
            story.append(Paragraph(_safe_para_text(ai_analysis["executive_summary"]), body_style))
            story.append(Spacer(1, 2 * mm))
        for rp in (ai_analysis.get("remediation_plan") or [])[:8]:
            if isinstance(rp, dict):
                story.append(Paragraph(f"• <b>[{_safe_para_text(rp.get('priority', 'P1'))}]</b> {_safe_para_text(rp.get('action', ''))}", body_style))
            elif rp:
                story.append(Paragraph(f"• {_safe_para_text(rp)}", body_style))
        story.append(Spacer(1, 3 * mm))
    else:
        story.append(Paragraph("2. Piano di Intervento Consigliato (Template Standard)" if is_it else "2. Recommended Action Plan (Standard Template)", h2_style))
        if is_it:
            story.append(
                Paragraph(
                    "Priorita P1 (Immediata): Chiudere o segmentare i servizi ad alto rischio esposti (es. SMB 445, RDP 3389, database non autenticati).<br/>"
                    "Priorita P2 (Breve Termine): Applicare header di sicurezza HTTP, aggiornare certificati TLS e isolare dispositivi IoT su VLAN dedicata.<br/>"
                    "Priorita P3 (Consolidamento): Censire tutti gli asset attivi rilevati ed eseguire scansioni periodiche di verifica.",
                    body_style,
                )
            )
        else:
            story.append(
                Paragraph(
                    "Priority P1 (Immediate): Close or segment exposed high-risk services (e.g. SMB 445, RDP 3389, unauthenticated databases).<br/>"
                    "Priority P2 (Short Term): Apply HTTP security headers, update TLS certificates, and isolate IoT devices on dedicated VLANs.<br/>"
                    "Priority P3 (Consolidation): Inventory all detected active assets and conduct periodic verification scans.",
                    body_style,
                )
            )
        story.append(Spacer(1, 3 * mm))

    # Host Topology
    if include_host_topology and hosts:
        story.append(Paragraph(
            f"3. Topologia Host & Porte Rilevate ({len(hosts)})" if is_it else f"3. Host Topology & Detected Ports ({len(hosts)})",
            h2_style
        ))
        host_rows = [["IP", "Hostname", "OS / Vendor", "Porte Aperte" if is_it else "Open Ports"]]
        no_ports_str = "Nessuna" if is_it else "None"
        na_os_str = "N/D" if is_it else "N/A"
        for h in hosts[:60]:
            ports_txt = ", ".join(f"{p.get('port')}/{p.get('protocol', 'tcp')}" for p in h.get("ports", [])) or no_ports_str
            host_rows.append([
                Paragraph(_safe_para_text(h.get("ip", "")), small_muted),
                Paragraph(_safe_para_text(h.get("hostname", "")), small_muted),
                Paragraph(_safe_para_text(h.get("os", na_os_str)), small_muted),
                Paragraph(_safe_para_text(ports_txt), small_muted),
            ])
        ht = Table(host_rows, colWidths=[30 * mm, 42 * mm, 48 * mm, 60 * mm], repeatRows=1)
        ht.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(ht)
        story.append(Spacer(1, 4 * mm))

    # Optional Recon & Attack Surface Intelligence
    if isinstance(recon_summary, dict) and (
        recon_summary.get("total_subdomains")
        or recon_summary.get("dns_zones")
        or recon_summary.get("takeovers")
        or recon_summary.get("directories")
    ):
        r_title = "Superficie d'Attacco & Web Recon (SubRaptor / httpx / Subzy / Feroxbuster)" if is_it else "Attack Surface & Web Recon Intelligence (SubRaptor / httpx / Subzy / Feroxbuster)"
        story.append(Paragraph(r_title, h2_style))
        live_subs = recon_summary.get("live_subdomains") or []
        takeovers = recon_summary.get("takeovers") or []
        dirs = recon_summary.get("directories") or []
        dns_zones = recon_summary.get("dns_zones") or []
        axfr_open = sum(1 for z in dns_zones if z.get("axfr_vulnerable"))
        story.append(
            Paragraph(
                f"Subdomains: <b>{int(recon_summary.get('total_subdomains') or 0)}</b> | "
                f"Live HTTP/S: <b>{len(live_subs)}</b> | "
                f"Takeovers: <b>{len(takeovers)}</b> | "
                f"AXFR Open: <b>{axfr_open}</b> | "
                f"Directories: <b>{len(dirs)}</b>",
                body_style,
            )
        )
        story.append(Spacer(1, 2 * mm))
        if live_subs:
            sub_rows = [["Subdomain", "Status", "Title / Server", "Tech Stack"]]
            for lr in live_subs[:20]:
                tech_str = ", ".join((lr.get("tech") or [])[:4]) or "-"
                ts = f"{lr.get('title') or ''} ({lr.get('webserver') or ''})".strip(" ()") or "-"
                sub_rows.append([
                    Paragraph(_safe_para_text(str(lr.get("subdomain") or "")), small_muted),
                    str(lr.get("status_code") or "-"),
                    Paragraph(_safe_para_text(ts[:60]), small_muted),
                    Paragraph(_safe_para_text(tech_str[:45]), small_muted),
                ])
            st = Table(sub_rows, colWidths=[52 * mm, 16 * mm, 64 * mm, 48 * mm], repeatRows=1)
            st.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(st)
            story.append(Spacer(1, 3 * mm))
        if dirs:
            dir_rows = [["Status", "Discovered Path / URL", "Size"]]
            for d in dirs[:25]:
                dir_rows.append([
                    str(d.get("status") or "-"),
                    Paragraph(_safe_para_text(str(d.get("url") or d.get("path") or "")[:95]), small_muted),
                    f"{int(d.get('content_length') or 0)} B",
                ])
            dt = Table(dir_rows, colWidths=[18 * mm, 136 * mm, 26 * mm], repeatRows=1)
            dt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(dt)
            story.append(Spacer(1, 4 * mm))

    # Findings Detail
    story.append(Paragraph(
        f"4. Inventario Vulnerabilita & Evidenze ({len(findings)})" if is_it else f"4. Vulnerability & Evidence Inventory ({len(findings)})",
        h2_style
    ))
    if not findings:
        story.append(Paragraph(
            "Nessun finding registrato per questa scansione." if is_it else "No findings recorded for this scan.",
            body_style
        ))
    else:
        engine_lbl = "Motore" if is_it else "Engine"
        for idx, f in enumerate(findings, 1):
            sev = str(f.get("severity", "info")).upper()
            cvss = float(f.get("cvss") or 0.0)
            org_label = ""
            if org_map and f.get("org_id") in org_map:
                org_label = f" | Org: {org_map[f['org_id']].get('name', '')}"
            port_part = f":{f.get('port')}/{f.get('protocol', 'tcp')}" if f.get("port") else ""

            story.append(
                Paragraph(
                    f"<b>#{idx} [{sev} | CVSS {cvss:.1f}] {_safe_para_text(f.get('title', ''))}</b>",
                    body_style,
                )
            )
            story.append(
                Paragraph(
                    f"Target: {_safe_para_text(f.get('host', ''))}{port_part} | {engine_lbl}: {_safe_para_text(str(f.get('source_engine', '')).upper())}{_safe_para_text(org_label)}",
                    small_muted,
                )
            )
            if f.get("description"):
                story.append(Paragraph(_safe_para_text(f.get("description")), body_style))
            if f.get("remediation"):
                story.append(
                    Paragraph(f"<b>Remediation:</b> {_safe_para_text(f.get('remediation'))}", body_style)
                )
            if include_evidence and f.get("evidence"):
                story.append(Paragraph(_safe_para_text(str(f.get("evidence"))[:800]), mono_style))
            story.append(Spacer(1, 3 * mm))

    default_footer = "Documento Riservato - UrielScan Purple Team" if is_it else "Confidential Document - UrielScan Purple Team"
    footer_txt = mssp_profile.get("report_footer") or default_footer
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(_safe_para_text(footer_txt), small_muted))

    doc.build(story)
    return buf.getvalue()


def generate_docx_report(
    report_title: str,
    classification: str,
    mssp_profile: Dict[str, Any],
    client_org: Dict[str, Any],
    targets: str,
    hosts: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    executive_notes: str = "",
    ai_analysis: Optional[Dict[str, Any]] = None,
    include_ai: bool = True,
    include_evidence: bool = True,
    include_host_topology: bool = True,
    lang: str = "en",
    recon_summary: Optional[Dict[str, Any]] = None,
) -> bytes:
    """
    Generates an editable OpenXML (.docx) report compatible with Microsoft Word,
    LibreOffice Writer, and Google Docs without requiring external libraries.
    """
    findings = sort_findings_by_severity(findings)
    is_it = (lang or "").lower().startswith("it")
    client_logo_bytes = _decode_data_url_image(client_org.get("logo_data") or client_org.get("logo_url") or "")
    if client_logo_bytes:
        logo_bytes: Optional[bytes] = client_logo_bytes
        logo_ext, logo_mime, logo_pw, logo_ph = _detect_image_meta(client_logo_bytes)
        media_name = f"org_logo.{logo_ext}"
        logo_doc_name = "OrganizationLogo"
    else:
        logo_bytes = _load_urielscan_logo_bytes()
        logo_ext, logo_mime = "png", "image/png"
        logo_pw, logo_ph = _png_dimensions(logo_bytes) if logo_bytes else (400, 76)
        media_name = "urielscan_logo.png"
        logo_doc_name = "UrielScanLogo"

    def p_xml(text: str, bold: bool = False, size_half_pt: int = 21, color_hex: str = "1F2937", space_after: int = 100) -> str:
        b_tag = "<w:b/>" if bold else ""
        lines = _clean_xml_text(text).split("\n")
        runs = []
        for idx, line in enumerate(lines):
            br = "<w:br/>" if idx > 0 else ""
            runs.append(
                f'<w:r><w:rPr>{b_tag}<w:color w:val="{color_hex}"/><w:sz w:val="{size_half_pt}"/></w:rPr>'
                f'{br}<w:t xml:space="preserve">{xml_escape(line)}</w:t></w:r>'
            )
        return (
            f'<w:p><w:pPr><w:spacing w:after="{space_after}"/></w:pPr>'
            + "".join(runs)
            + "</w:p>"
        )

    def heading_xml(text: str, level: int = 1) -> str:
        size = 30 if level == 1 else 24
        color = "1E3A5F" if level == 1 else "0F172A"
        return p_xml(text, bold=True, size_half_pt=size, color_hex=color, space_after=120)

    def table_xml(rows: List[List[str]]) -> str:
        tr_list = []
        for r_idx, row in enumerate(rows):
            is_header = r_idx == 0
            tc_list = []
            for cell in row:
                fill = "1E3A5F" if is_header else ("F8FAFC" if r_idx % 2 == 1 else "FFFFFF")
                t_color = "FFFFFF" if is_header else "1F2937"
                tc_list.append(
                    f'<w:tc><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>'
                    f'<w:tcMar><w:top w:w="80" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/>'
                    f'<w:left w:w="110" w:type="dxa"/><w:right w:w="110" w:type="dxa"/></w:tcMar></w:tcPr>'
                    + p_xml(cell, bold=is_header, size_half_pt=18, color_hex=t_color, space_after=20)
                    + "</w:tc>"
                )
            tr_list.append("<w:tr>" + "".join(tc_list) + "</w:tr>")
        borders = (
            '<w:tblBorders>'
            '<w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:left w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:right w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
            '</w:tblBorders>'
        )
        return f'<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/>{borders}</w:tblPr>{"".join(tr_list)}</w:tbl>'

    mssp_name = mssp_profile.get("scanner_company_name") or mssp_profile.get("company_name") or "UrielScan MSSP"
    client_name = client_org.get("name") or ("Organizzazione Cliente" if is_it else "Client Organization")
    now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
    na_str = "N/D" if is_it else "N/A"
    client_ind = client_org.get("industry") or na_str
    client_cname = client_org.get("contact_name") or na_str
    client_cmail = client_org.get("contact_email") or na_str

    header_meta_txt = f"{mssp_name}  |  {classification}  |  {now_str}"
    top_header_parts: List[str] = []
    if logo_bytes:
        cx = 1350000 if client_logo_bytes else 1620000
        cy = max(1, int(cx * (logo_ph / max(1, logo_pw))))
        logo_drawing = (
            '<w:p><w:pPr><w:jc w:val="right"/><w:spacing w:after="40"/></w:pPr><w:r><w:drawing>'
            '<wp:inline distT="0" distB="0" distL="0" distR="0">'
            f'<wp:extent cx="{cx}" cy="{cy}"/>'
            f'<wp:docPr id="1" name="{logo_doc_name}"/>'
            '<wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>'
            '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            '<pic:pic>'
            f'<pic:nvPicPr><pic:cNvPr id="1" name="{media_name}"/><pic:cNvPicPr/></pic:nvPicPr>'
            '<pic:blipFill><a:blip r:embed="rIdLogo"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
            '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
            '</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>'
        )
        left_p = p_xml(header_meta_txt, bold=True, size_half_pt=18, color_hex="4B5563", space_after=40)
        hdr_tbl = (
            '<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/>'
            '<w:tblBorders><w:top w:val="none"/><w:left w:val="none"/><w:bottom w:val="single" w:sz="6" w:space="0" w:color="1E3A5F"/>'
            '<w:right w:val="none"/><w:insideH w:val="none"/><w:insideV w:val="none"/></w:tblBorders>'
            '</w:tblPr><w:tr>'
            f'<w:tc><w:tcPr><w:tcW w:w="3400" w:type="pct"/><w:vAlign w:val="center"/></w:tcPr>{left_p}</w:tc>'
            f'<w:tc><w:tcPr><w:tcW w:w="1600" w:type="pct"/><w:vAlign w:val="center"/></w:tcPr>{logo_drawing}</w:tc>'
            '</w:tr></w:tbl>'
        )
        top_header_parts = [hdr_tbl, p_xml("", space_after=80)]
    else:
        top_header_parts = [p_xml(header_meta_txt, bold=True, size_half_pt=18, color_hex="4B5563", space_after=80)]

    if is_it:
        body_parts: List[str] = top_header_parts + [
            heading_xml(report_title, level=1),
            p_xml(f"Organizzazione Cliente: {client_name} ({client_ind})", bold=True, size_half_pt=20),
            p_xml(f"Referente: {client_cname} ({client_cmail})"),
            p_xml(f"Target Scope Analizzato: {targets}", space_after=180),
            heading_xml("1. Sintesi Esecutiva & Postura di Rischio", level=2),
            p_xml(executive_notes or "Inserire qui le note esecutive per il management."),
        ]
        kpi_cols = ["Critiche", "Alte", "Medie", "Basse", "Info", "Totale Finding"]
    else:
        body_parts: List[str] = top_header_parts + [
            heading_xml(report_title, level=1),
            p_xml(f"Client Organization: {client_name} ({client_ind})", bold=True, size_half_pt=20),
            p_xml(f"Contact Person: {client_cname} ({client_cmail})"),
            p_xml(f"Target Scope Analyzed: {targets}", space_after=180),
            heading_xml("1. Executive Summary & Risk Posture", level=2),
            p_xml(executive_notes or "Insert executive notes for management here."),
        ]
        kpi_cols = ["Critical", "High", "Medium", "Low", "Info", "Total Findings"]

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    body_parts.append(table_xml([
        kpi_cols,
        [
            str(sev_counts["critical"]),
            str(sev_counts["high"]),
            str(sev_counts["medium"]),
            str(sev_counts["low"]),
            str(sev_counts["info"]),
            str(len(findings)),
        ],
    ]))
    body_parts.append(p_xml("", space_after=120))

    # Section 2: Editable Standard Template or AI Analysis
    body_parts.append(heading_xml(
        "2. Analisi & Piano di Remediation (Sezione Modificabile)" if is_it else "2. Analysis & Remediation Plan (Editable Section)",
        level=2
    ))
    if include_ai and isinstance(ai_analysis, dict) and (ai_analysis.get("executive_summary") or ai_analysis.get("remediation_plan")):
        if ai_analysis.get("executive_summary"):
            body_parts.append(p_xml(str(ai_analysis["executive_summary"])))
        if is_it:
            rem_rows = [["Priorita", "Azione Consigliata", "Note / Stato (Da Compilare)"]]
            note_default = "Da pianificare"
        else:
            rem_rows = [["Priority", "Recommended Action", "Notes / Status (To be filled)"]]
            note_default = "To be scheduled"
        for rp in (ai_analysis.get("remediation_plan") or []):
            if isinstance(rp, dict):
                rem_rows.append([str(rp.get("priority", "P1")), str(rp.get("action", "")), note_default])
            elif rp:
                rem_rows.append(["P1", str(rp), note_default])
        if len(rem_rows) > 1:
            body_parts.append(table_xml(rem_rows))
    else:
        if is_it:
            body_parts.append(p_xml("Template operativo compilabile senza AI collegata:", bold=True))
            body_parts.append(table_xml([
                ["Priorita", "Ambito / Intervento Consigliato", "Responsabile", "Scadenza / Stato"],
                ["P1 - Immediata", "Mitigazione vulnerabilita Critiche/Alte e servizi esposti (SMB/RDP/DB).", "IT / SysAdmin", "Da definire"],
                ["P2 - Breve Termine", "Hardening TLS/HTTPS, Security Headers Web e segmentazione VLAN.", "SecOps / Network", "Da definire"],
                ["P3 - Continuo", "Verifica inventario asset attivi e pianificazione audit periodico.", "CISO / MSP", "Da definire"],
            ]))
        else:
            body_parts.append(p_xml("Operational template editable without connected AI:", bold=True))
            body_parts.append(table_xml([
                ["Priority", "Scope / Recommended Action", "Owner", "Deadline / Status"],
                ["P1 - Immediate", "Mitigation of Critical/High vulnerabilities and exposed services (SMB/RDP/DB).", "IT / SysAdmin", "TBD"],
                ["P2 - Short Term", "TLS/HTTPS hardening, Web Security Headers, and VLAN segmentation.", "SecOps / Network", "TBD"],
                ["P3 - Ongoing", "Active asset inventory verification and periodic audit planning.", "CISO / MSP", "TBD"],
            ]))
    body_parts.append(p_xml("", space_after=120))

    # Section 3: Hosts
    if include_host_topology and hosts:
        body_parts.append(heading_xml(
            f"3. Topologia Host & Porte Rilevate ({len(hosts)})" if is_it else f"3. Host Topology & Detected Ports ({len(hosts)})",
            level=2
        ))
        if is_it:
            h_rows = [["Indirizzo IP", "Hostname", "Sistema / Vendor", "Porte Aperte"]]
            no_p_str = "Nessuna"
        else:
            h_rows = [["IP Address", "Hostname", "System / Vendor", "Open Ports"]]
            no_p_str = "None"
        for h in hosts:
            ports_txt = ", ".join(f"{p.get('port')}/{p.get('protocol', 'tcp')}" for p in h.get("ports", [])) or no_p_str
            h_rows.append([str(h.get("ip", "")), str(h.get("hostname", "")), str(h.get("os", na_str)), ports_txt])
        body_parts.append(table_xml(h_rows))
        body_parts.append(p_xml("", space_after=120))

    # Optional Attack Surface & Web Recon section
    if isinstance(recon_summary, dict) and (
        recon_summary.get("total_subdomains")
        or recon_summary.get("dns_zones")
        or recon_summary.get("takeovers")
        or recon_summary.get("directories")
    ):
        body_parts.append(heading_xml(
            "Superficie d'Attacco & Web Recon (SubRaptor / httpx / Subzy / Feroxbuster)"
            if is_it else "Attack Surface & Web Recon Intelligence (SubRaptor / httpx / Subzy / Feroxbuster)",
            level=2,
        ))
        live_subs = recon_summary.get("live_subdomains") or []
        takeovers = recon_summary.get("takeovers") or []
        dns_zones = recon_summary.get("dns_zones") or []
        dirs = recon_summary.get("directories") or []
        axfr_open = sum(1 for z in dns_zones if z.get("axfr_vulnerable"))
        body_parts.append(p_xml(
            f"Subdomains: {int(recon_summary.get('total_subdomains') or 0)} | "
            f"Live HTTP/S: {len(live_subs)} | Takeovers: {len(takeovers)} | "
            f"AXFR Open: {axfr_open} | Directories: {len(dirs)}",
            bold=True,
        ))
        if live_subs:
            sub_rows = [["URL / Subdomain", "Status", "Title", "Tech"]]
            for lr in live_subs[:25]:
                sub_rows.append([
                    str(lr.get("url") or lr.get("subdomain") or ""),
                    str(lr.get("status_code") or "-"),
                    str(lr.get("title") or "-")[:60],
                    ", ".join((lr.get("tech") or [])[:4]) or "-",
                ])
            body_parts.append(table_xml(sub_rows))
        if dirs:
            dir_rows = [["Status", "URL / Path", "Size"]]
            for d in dirs[:25]:
                dir_rows.append([
                    str(d.get("status") or "-"),
                    str(d.get("url") or d.get("path") or ""),
                    f"{int(d.get('content_length') or 0)} B",
                ])
            body_parts.append(table_xml(dir_rows))
        body_parts.append(p_xml("", space_after=120))

    # Section 4: Findings
    body_parts.append(heading_xml(
        f"4. Inventario Dettagliato Risultati ({len(findings)})" if is_it else f"4. Detailed Findings Inventory ({len(findings)})",
        level=2
    ))
    if not findings:
        body_parts.append(p_xml(
            "Nessuna vulnerabilita registrata per questa sessione." if is_it else "No vulnerabilities recorded for this session."
        ))
    else:
        engine_lbl = "Motore" if is_it else "Engine"
        status_lbl = "Stato" if is_it else "Status"
        desc_lbl = "Descrizione" if is_it else "Description"
        ev_lbl = "Evidenza" if is_it else "Evidence"
        for idx, f in enumerate(findings, 1):
            sev = str(f.get("severity", "info")).upper()
            cvss = float(f.get("cvss") or 0.0)
            port_part = f":{f.get('port')}/{f.get('protocol', 'tcp')}" if f.get("port") else ""
            body_parts.append(p_xml(f"#{idx} [{sev} | CVSS {cvss:.1f}] {f.get('title', '')}", bold=True, size_half_pt=22, color_hex="1E3A5F", space_after=40))
            body_parts.append(p_xml(f"Host: {f.get('host', '')}{port_part} | {engine_lbl}: {str(f.get('source_engine', '')).upper()} | {status_lbl}: {f.get('status', 'open')}", size_half_pt=18, color_hex="4B5563", space_after=40))
            if f.get("description"):
                body_parts.append(p_xml(f"{desc_lbl}: {f.get('description')}", space_after=40))
            if f.get("remediation"):
                body_parts.append(p_xml(f"Remediation: {f.get('remediation')}", color_hex="065F46", space_after=40))
            if include_evidence and f.get("evidence"):
                body_parts.append(p_xml(f"{ev_lbl}: {f.get('evidence')}", size_half_pt=17, color_hex="374151", space_after=100))

    default_footer = "Documento Riservato - UrielScan Purple Team" if is_it else "Confidential Document - UrielScan Purple Team"
    sig_lbl = "Firma / Approvazione" if is_it else "Signature / Approval"
    footer_txt = mssp_profile.get("report_footer") or default_footer
    body_parts.append(p_xml("", space_after=120))
    body_parts.append(p_xml(f"{footer_txt}  |  {sig_lbl}: ___________________________", size_half_pt=18, color_hex="4B5563"))

    doc_ns = (
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"'
    )
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document {doc_ns}>'
        f'<w:body>{"".join(body_parts)}<w:sectPr/></w:body>'
        '</w:document>'
    )

    img_ct = f'<Default Extension="{logo_ext}" ContentType="{logo_mime}"/>' if logo_bytes else ""
    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f'{img_ct}'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>'
    )

    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '</Relationships>'
    )

    doc_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rIdLogo" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/{media_name}"/>'
        '</Relationships>'
    )

    out_buf = io.BytesIO()
    with zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", rels_xml)
        zf.writestr("word/document.xml", document_xml)
        if logo_bytes:
            zf.writestr("word/_rels/document.xml.rels", doc_rels_xml)
            zf.writestr(f"word/media/{media_name}", logo_bytes)
    return out_buf.getvalue()
