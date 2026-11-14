import os
import json
from typing import Dict, Any, List, Optional
import httpx


async def test_ai_connection(settings: Dict[str, str]) -> Dict[str, Any]:
    provider = settings.get("ai_provider", "offline")
    api_key = settings.get("ai_api_key", "").strip()
    model = settings.get("ai_model", "").strip()
    base_url = settings.get("ai_base_url", "").strip()

    if provider == "offline" or not api_key and provider != "ollama":
        return {
            "success": True,
            "provider": "offline",
            "message": "Motore Euristico Purple Team Integrato UrielScan pronto e operativo (Zero dipendenze cloud/API)."
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            if provider in ["openai", "ollama"]:
                url = f"{base_url.rstrip('/')}/chat/completions" if base_url else "https://api.openai.com/v1/chat/completions"
                headers = {"Authorization": f"Bearer {api_key}" if api_key else "Bearer ollama"}
                payload = {
                    "model": model or ("gpt-4o" if provider == "openai" else "llama3"),
                    "messages": [{"role": "user", "content": "Ping test: rispondi 'OK'."}],
                    "max_tokens": 10
                }
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    return {"success": True, "provider": provider, "message": f"Connessione a {provider} ({model}) riuscita!"}
                else:
                    return {"success": False, "provider": provider, "message": f"Errore {provider}: HTTP {resp.status_code} - {resp.text[:200]}"}

            elif provider == "gemini":
                model_name = model or "gemini-1.5-pro"
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
                payload = {
                    "contents": [{"parts": [{"text": "Ping test: rispondi 'OK'."}]}]
                }
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    return {"success": True, "provider": "gemini", "message": f"Connessione a Google Gemini ({model_name}) riuscita!"}
                else:
                    return {"success": False, "provider": "gemini", "message": f"Errore Gemini: HTTP {resp.status_code} - {resp.text[:200]}"}

            elif provider == "anthropic":
                model_name = model or "claude-3-5-sonnet-20241022"
                url = "https://api.anthropic.com/v1/messages"
                headers = {
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                }
                payload = {
                    "model": model_name,
                    "max_tokens": 20,
                    "messages": [{"role": "user", "content": "Ping test"}]
                }
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    return {"success": True, "provider": "anthropic", "message": f"Connessione ad Anthropic ({model_name}) riuscita!"}
                else:
                    return {"success": False, "provider": "anthropic", "message": f"Errore Anthropic: HTTP {resp.status_code} - {resp.text[:200]}"}

    except Exception as e:
        return {"success": False, "provider": provider, "message": f"Eccezione di connessione ad AI: {str(e)}"}

    return {"success": False, "provider": provider, "message": f"Provider {provider} non riconosciuto."}


async def analyze_findings(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    org: Dict[str, Any],
    scanner_settings: Dict[str, str],
    mode: str = "purple_team",
    custom_prompt: str = "",
    lang: str = "en"
) -> Dict[str, Any]:
    provider = scanner_settings.get("ai_provider", "offline")
    api_key = scanner_settings.get("ai_api_key", "").strip()
    model = scanner_settings.get("ai_model", "").strip()
    base_url = scanner_settings.get("ai_base_url", "").strip()

    # If external provider is configured, attempt call
    if provider in ["openai", "gemini", "anthropic", "ollama"] and (api_key or provider == "ollama"):
        try:
            external_result = await _call_external_llm(
                provider=provider,
                api_key=api_key,
                model=model,
                base_url=base_url,
                scan=scan,
                findings=findings,
                org=org,
                mode=mode,
                custom_prompt=custom_prompt,
                lang=lang
            )
            if external_result:
                return external_result
        except Exception:
            pass  # Fall back smoothly to smart heuristic engine

    # Fallback / Default: Smart Offline Heuristic Engine
    return _generate_smart_offline_analysis(scan, findings, org, mode, lang=lang)


async def _call_external_llm(
    provider: str,
    api_key: str,
    model: str,
    base_url: str,
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    org: Dict[str, Any],
    mode: str,
    custom_prompt: str,
    lang: str = "en"
) -> Optional[Dict[str, Any]]:
    is_it = (lang or "").lower().startswith("it")
    if is_it:
        system_prompt = (
            "Sei un Senior Purple Team Security Specialist e Lead Vulnerability Assessor per UrielScan.\n"
            "Analizza i dati tecnici forniti (host, porte aperte, vulnerabilità, CVE, evidenze) ed elabora una valutazione rigorosa in lingua ITALIANA in formato JSON.\n"
            "Tutti i testi descrittivi generati (compresi executive_summary, attack_paths, remediation_plan, markdown_report) devono essere redatti in lingua ITALIANA.\n"
            "Il JSON deve contenere esattamente queste chiavi:\n"
            "- provider_used: string\n"
            "- risk_rating: string\n"
            "- executive_summary: string\n"
            "- attack_paths: array di oggetti {step: int, title: string, details: string, mitre: string}\n"
            "- remediation_plan: array di oggetti {priority: string, action: string, command: string}\n"
            "- mitre_mapping: array di oggetti {tactic: string, technique: string, count: int}\n"
            "- markdown_report: string (report formattato in markdown)\n"
        )
        user_content = f"""
Organizzazione: {org.get('name', 'N/D')} (Settore: {org.get('industry', 'N/D')})
Perimetro Target: {scan.get('targets', 'N/D')}
Numero Finding: {len(findings)}
Dettagli Finding:
{json.dumps([{
    'host': f.get('host'), 'port': f.get('port'), 'service': f.get('service'),
    'title': f.get('title'), 'severity': f.get('severity'), 'cvss': f.get('cvss'),
    'cve': f.get('cve_ids'), 'evidence': (f.get('evidence') or '')[:300]
} for f in findings[:25]], indent=2)}
{f"Richiesta specifica utente: {custom_prompt}" if custom_prompt else ""}
        """
    else:
        system_prompt = (
            "You are a Senior Purple Team Security Specialist and Lead Vulnerability Assessor for UrielScan.\n"
            "Analyze the technical data provided (hosts, open ports, vulnerabilities, CVEs, evidence) and produce a rigorous evaluation in ENGLISH in JSON format.\n"
            "All descriptive texts generated (including executive_summary, attack_paths, remediation_plan, markdown_report) must be written in ENGLISH.\n"
            "The JSON must contain exactly these keys:\n"
            "- provider_used: string\n"
            "- risk_rating: string\n"
            "- executive_summary: string\n"
            "- attack_paths: array of objects {step: int, title: string, details: string, mitre: string}\n"
            "- remediation_plan: array of objects {priority: string, action: string, command: string}\n"
            "- mitre_mapping: array of objects {tactic: string, technique: string, count: int}\n"
            "- markdown_report: string (markdown formatted report)\n"
        )
        user_content = f"""
Organization: {org.get('name', 'N/A')} (Industry: {org.get('industry', 'N/A')})
Target Scope: {scan.get('targets', 'N/A')}
Number of Findings: {len(findings)}
Finding Details:
{json.dumps([{
    'host': f.get('host'), 'port': f.get('port'), 'service': f.get('service'),
    'title': f.get('title'), 'severity': f.get('severity'), 'cvss': f.get('cvss'),
    'cve': f.get('cve_ids'), 'evidence': (f.get('evidence') or '')[:300]
} for f in findings[:25]], indent=2)}
{f"Specific user instruction: {custom_prompt}" if custom_prompt else ""}
        """

    async with httpx.AsyncClient(timeout=40.0) as client:
        raw_text = ""
        if provider in ["openai", "ollama"]:
            url = f"{base_url.rstrip('/')}/chat/completions" if base_url else "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}" if api_key else "Bearer ollama"}
            payload = {
                "model": model or ("gpt-4o" if provider == "openai" else "llama3"),
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                "response_format": {"type": "json_object"} if provider == "openai" else None
            }
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                raw_text = data["choices"][0]["message"]["content"]

        elif provider == "gemini":
            model_name = model or "gemini-1.5-pro"
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": f"{system_prompt}\n\n{user_content}"}]}]
            }
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                raw_text = data["candidates"][0]["content"]["parts"][0]["text"]

        elif provider == "anthropic":
            model_name = model or "claude-3-5-sonnet-20241022"
            url = "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            payload = {
                "model": model_name,
                "max_tokens": 3000,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_content}]
            }
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                raw_text = data["content"][0]["text"]

        if raw_text:
            # Strip potential ```json markers
            clean_json = raw_text.strip()
            if clean_json.startswith("```json"):
                clean_json = clean_json[7:]
            if clean_json.startswith("```"):
                clean_json = clean_json[3:]
            if clean_json.endswith("```"):
                clean_json = clean_json[:-3]
            clean_json = clean_json.strip()

            parsed = json.loads(clean_json)
            parsed["provider_used"] = f"{provider.upper()} ({model or 'default'})"
            return parsed

    return None


def _generate_smart_offline_analysis(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    org: Dict[str, Any],
    mode: str,
    lang: str = "en"
) -> Dict[str, Any]:
    is_it = (lang or "").lower().startswith("it")
    org_name = org.get("name") or ("Organizzazione Target" if is_it else "Target Organization")
    industry = org.get("industry") or ("Settore Tecnologico" if is_it else "Technology Sector")
    targets = scan.get("targets") or ("Asset perimetrali" if is_it else "Perimeter assets")

    crit = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    med = [f for f in findings if f.get("severity") == "medium"]
    low = [f for f in findings if f.get("severity") == "low"]
    info = [f for f in findings if f.get("severity") == "info"]

    # Calculate overall risk
    risk_score = min(100, (len(crit) * 25) + (len(high) * 15) + (len(med) * 5) + (len(low) * 2))
    if is_it:
        if risk_score >= 75:
            risk_label = f"CRITICO ({risk_score}/100)"
        elif risk_score >= 50:
            risk_label = f"ALTO ({risk_score}/100)"
        elif risk_score >= 25:
            risk_label = f"MEDIO ({risk_score}/100)"
        else:
            risk_label = f"BASSO ({risk_score}/100)"
    else:
        if risk_score >= 75:
            risk_label = f"CRITICAL ({risk_score}/100)"
        elif risk_score >= 50:
            risk_label = f"HIGH ({risk_score}/100)"
        elif risk_score >= 25:
            risk_label = f"MEDIUM ({risk_score}/100)"
        else:
            risk_label = f"LOW ({risk_score}/100)"

    # Build Executive Summary
    if is_it:
        if crit:
            first_crit = crit[0]
            exec_summary = (
                f"La valutazione di sicurezza condotta per {org_name} ({industry}) sui target [{targets}] "
                f"ha evidenziato una postura di rischio {risk_label}. Sono state individuate {len(crit)} vulnerabilità CRITICHE "
                f"e {len(high)} ad ALTO impatto. L'esposizione primaria più allarmante riguarda '{first_crit.get('title')}' "
                f"su {first_crit.get('host')}:{first_crit.get('port')}, che consente a un attaccante non autenticato "
                f"l'esecuzione remota di codice o la compromissione diretta dei dati. È necessaria l'immediata attivazione delle contromisure di difesa."
            )
        elif high:
            first_high = high[0]
            exec_summary = (
                f"L'audit sui sistemi di {org_name} ha rilevato una postura di rischio {risk_label} con {len(high)} vulnerabilità ad ALTO impatto "
                f"e {len(med)} a medio impatto. La criticità principale rilevata riguarda '{first_high.get('title')}' su {first_high.get('host')}:{first_high.get('port')}. "
                f"La superficie di attacco presenta varchi che potrebbero consentire l'accesso non autorizzato a servizi interni o l'estrazione di informazioni riservate."
            )
        elif med:
            exec_summary = (
                f"L'analisi di sicurezza per {org_name} evidenzia una postura di rischio {risk_label}. "
                f"Non sono state rilevate vulnerabilità critiche sfruttabili direttamente dall'esterno, ma sussistono {len(med)} anomalie a impatto medio "
                f"legate a configurazioni crittografiche o header protettivi mancanti che richiedono rettifica programmata."
            )
        else:
            exec_summary = (
                f"L'audit perimetrale per {org_name} sui target [{targets}] ha registrato una postura eccellente (Rischio {risk_label}). "
                f"Tutti i servizi esaminati risultano opportunamente protetti o privi di debolezze note direttamente accessibili."
            )
    else:
        if crit:
            first_crit = crit[0]
            exec_summary = (
                f"The security assessment conducted for {org_name} ({industry}) on targets [{targets}] "
                f"revealed a {risk_label} risk posture. {len(crit)} CRITICAL and {len(high)} HIGH impact "
                f"vulnerabilities were identified. The most urgent exposure is '{first_crit.get('title')}' "
                f"on {first_crit.get('host')}:{first_crit.get('port')}, which may allow an unauthenticated attacker "
                f"remote code execution or direct compromise of sensitive data. Immediate defense countermeasures are required."
            )
        elif high:
            first_high = high[0]
            exec_summary = (
                f"The security audit on {org_name} systems identified a {risk_label} risk posture with {len(high)} "
                f"HIGH impact and {len(med)} medium impact vulnerabilities. The primary issue detected is "
                f"'{first_high.get('title')}' on {first_high.get('host')}:{first_high.get('port')}. The attack surface "
                f"presents gaps that could allow unauthorized access to internal services or confidential data exfiltration."
            )
        elif med:
            exec_summary = (
                f"The security analysis for {org_name} indicates a {risk_label} risk posture. No directly "
                f"exploitable critical vulnerabilities were found externally, but {len(med)} medium impact anomalies "
                f"exist related to cryptographic settings or missing protective headers requiring scheduled remediation."
            )
        else:
            exec_summary = (
                f"The perimeter audit for {org_name} on targets [{targets}] recorded an excellent security posture "
                f"(Risk {risk_label}). All examined services are properly secured with no known directly accessible weaknesses."
            )

    # Build Attack Paths (Red Team Perspective)
    attack_paths = []
    step_num = 1

    # Stage 1: External exploitation or Recon
    if crit:
        c = crit[0]
        if is_it:
            attack_paths.append({
                "step": step_num,
                "title": f"Fase 1: Sfruttamento Vulnerabilità Critica ({c.get('service', 'web')})",
                "details": f"L'avversario invia richieste appositamente modificate sfruttando '{c.get('title')}' su {c.get('host')}:{c.get('port')}. "
                           f"Questo consente l'aggiramento dei controlli di accesso o l'esecuzione di comandi su host esposto.",
                "mitre": c.get("mitre_technique", "T1190 - Exploit Public-Facing Application")
            })
        else:
            attack_paths.append({
                "step": step_num,
                "title": f"Phase 1: Exploitation of Critical Vulnerability ({c.get('service', 'web')})",
                "details": f"The adversary sends crafted requests exploiting '{c.get('title')}' on {c.get('host')}:{c.get('port')}. "
                           f"This enables bypassing access controls or executing commands on the exposed host.",
                "mitre": c.get("mitre_technique", "T1190 - Exploit Public-Facing Application")
            })
        step_num += 1

    # Stage 2: Information Leak or Credential Theft
    cred_leak = next((f for f in high + med if "git" in f.get("title", "").lower() or "credential" in f.get("title", "").lower() or "cors" in f.get("title", "").lower() or "redis" in f.get("title", "").lower()), None)
    if cred_leak:
        if is_it:
            attack_paths.append({
                "step": step_num,
                "title": f"Fase {step_num}: Estrazione Credenziali e Informazioni Riservate",
                "details": f"Attraverso '{cred_leak.get('title')}', l'attaccante estrae token di autenticazione, chiavi API o configurazioni interne archiviate sul server.",
                "mitre": cred_leak.get("mitre_technique", "T1552 - Unsecured Credentials")
            })
        else:
            attack_paths.append({
                "step": step_num,
                "title": f"Phase {step_num}: Credential and Sensitive Information Exfiltration",
                "details": f"Leveraging '{cred_leak.get('title')}', the attacker extracts authentication tokens, API keys, or internal configurations stored on the server.",
                "mitre": cred_leak.get("mitre_technique", "T1552 - Unsecured Credentials")
            })
        step_num += 1

    # Stage 3: Lateral Movement or Persistence
    lat_mov = next((f for f in findings if f.get("port") in [445, 3389, 22, 139, 21]), None)
    if lat_mov:
        if is_it:
            attack_paths.append({
                "step": step_num,
                "title": f"Fase {step_num}: Movimento Laterale & Espansione nel Perimetro",
                "details": f"Utilizzando le credenziali ottenute o sessioni non firmate sul servizio {lat_mov.get('service')} (porta {lat_mov.get('port')}), "
                           f"l'attaccante tenta la propagazione verso nodi di gestione e database di produzione.",
                "mitre": "T1021 - Remote Services"
            })
        else:
            attack_paths.append({
                "step": step_num,
                "title": f"Phase {step_num}: Lateral Movement & Perimeter Expansion",
                "details": f"Using acquired credentials or unsigned sessions on service {lat_mov.get('service')} (port {lat_mov.get('port')}), "
                           f"the attacker attempts propagation to management nodes and production databases.",
                "mitre": "T1021 - Remote Services"
            })
    elif not attack_paths:
        if is_it:
            attack_paths.append({
                "step": 1,
                "title": "Ricognizione Perimetrale e Mappatura Servizi",
                "details": f"L'attaccante effettua scansioni passive e attive per individuare porte aperte e impronte dei server su {targets}.",
                "mitre": "T1046 - Network Service Discovery"
            })
        else:
            attack_paths.append({
                "step": 1,
                "title": "Perimeter Reconnaissance & Service Mapping",
                "details": f"The attacker conducts passive and active scans to discover open ports and server footprints across {targets}.",
                "mitre": "T1046 - Network Service Discovery"
            })

    # Build Remediation Plan (Blue Team Playbook)
    remediation_plan = []
    if is_it:
        if crit:
            for c in crit[:2]:
                remediation_plan.append({
                    "priority": "P0 - Critica Immediata (< 4h)",
                    "action": f"Sanare '{c.get('title')}' su {c.get('host')}:{c.get('port')}. {c.get('remediation', '')}",
                    "command": "Applicare la patch rilasciata dal vendor o isolare la porta tramite ACL perimetrali."
                })
        if high:
            for h in high[:2]:
                remediation_plan.append({
                    "priority": "P1 - Alta Priorità (< 24h)",
                    "action": f"Risolvere '{h.get('title')}' su {h.get('host')}. {h.get('remediation', '')}",
                    "command": "Revisionare i permessi di accesso e le policy di cifratura/firewall."
                })
        if med:
            for m in med[:2]:
                remediation_plan.append({
                    "priority": "P2 - Media Priorità (< 7gg)",
                    "action": f"Configurare corretti parametri per '{m.get('title')}'.",
                    "command": "Aggiornare le configurazioni di web server o cipher suite TLS supportate."
                })
        if not remediation_plan:
            remediation_plan.append({
                "priority": "P3 - Manutenzione Ordinaria",
                "action": "Mantenere attivi i cicli periodici di patching del sistema operativo e scansione perimetrale.",
                "command": "apt update && apt upgrade -y"
            })
    else:
        if crit:
            for c in crit[:2]:
                remediation_plan.append({
                    "priority": "P0 - Immediate Critical (< 4h)",
                    "action": f"Remediate '{c.get('title')}' on {c.get('host')}:{c.get('port')}. {c.get('remediation', '')}",
                    "command": "Apply vendor security patch or isolate port via perimeter ACLs."
                })
        if high:
            for h in high[:2]:
                remediation_plan.append({
                    "priority": "P1 - High Priority (< 24h)",
                    "action": f"Resolve '{h.get('title')}' on {h.get('host')}. {h.get('remediation', '')}",
                    "command": "Review access permissions, encryption policies, and firewall rules."
                })
        if med:
            for m in med[:2]:
                remediation_plan.append({
                    "priority": "P2 - Medium Priority (< 7d)",
                    "action": f"Configure appropriate parameters for '{m.get('title')}'.",
                    "command": "Update web server configurations or supported TLS cipher suites."
                })
        if not remediation_plan:
            remediation_plan.append({
                "priority": "P3 - Routine Maintenance",
                "action": "Maintain regular operating system patching cycles and perimeter scans.",
                "command": "apt update && apt upgrade -y"
            })

    # MITRE ATT&CK Mapping
    mitre_dict: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        tactic = f.get("mitre_tactic", "Discovery")
        technique = f.get("mitre_technique", "T1046 - Network Service Discovery")
        key = f"{tactic}|{technique}"
        if key not in mitre_dict:
            mitre_dict[key] = {"tactic": tactic, "technique": technique, "count": 0}
        mitre_dict[key]["count"] += 1

    mitre_mapping = list(mitre_dict.values())
    if not mitre_mapping:
        mitre_mapping = [{"tactic": "Discovery", "technique": "T1046 - Network Service Discovery", "count": 1}]

    # Markdown Report compilation
    if is_it:
        md_lines = [
            f"# Rapporto di Sicurezza Purple Team - {org_name}",
            f"**Data Valutazione**: {scan.get('completed_at') or 'Recente'}  ",
            f"**Perimetro Analizzato**: `{targets}`  ",
            f"**Livello di Rischio Globale**: `{risk_label}`  ",
            "",
            "## 1. Sintesi Esecutiva (Executive Summary)",
            exec_summary,
            "",
            "## 2. Matrice Scenari di Attacco (Red Team Attack Paths)",
        ]
        for ap in attack_paths:
            md_lines.append(f"### {ap['title']}")
            md_lines.append(f"- **Descrizione**: {ap['details']}")
            md_lines.append(f"- **MITRE ATT&CK**: `{ap['mitre']}`")
            md_lines.append("")

        md_lines.append("## 3. Piano di Bonifica Prioritizzato (Blue Team Remediation)")
        for rp in remediation_plan:
            md_lines.append(f"- **[{rp['priority']}]** {rp['action']}")
            if rp.get("command"):
                md_lines.append(f"  - *Azione consigliata*: `{rp['command']}`")
        md_lines.append("")
    else:
        md_lines = [
            f"# Purple Team Security Report - {org_name}",
            f"**Assessment Date**: {scan.get('completed_at') or 'Recent'}  ",
            f"**Target Scope**: `{targets}`  ",
            f"**Overall Risk Level**: `{risk_label}`  ",
            "",
            "## 1. Executive Summary",
            exec_summary,
            "",
            "## 2. Red Team Attack Scenarios (Attack Paths)",
        ]
        for ap in attack_paths:
            md_lines.append(f"### {ap['title']}")
            md_lines.append(f"- **Description**: {ap['details']}")
            md_lines.append(f"- **MITRE ATT&CK**: `{ap['mitre']}`")
            md_lines.append("")

        md_lines.append("## 3. Prioritized Remediation Plan (Blue Team Remediation)")
        for rp in remediation_plan:
            md_lines.append(f"- **[{rp['priority']}]** {rp['action']}")
            if rp.get("command"):
                md_lines.append(f"  - *Recommended action*: `{rp['command']}`")
        md_lines.append("")

    return {
        "provider_used": "Purple Team Heuristic Engine (Offline / Local)",
        "risk_rating": risk_label,
        "executive_summary": exec_summary,
        "attack_paths": attack_paths,
        "remediation_plan": remediation_plan,
        "mitre_mapping": mitre_mapping,
        "markdown_report": "\n".join(md_lines)
    }
