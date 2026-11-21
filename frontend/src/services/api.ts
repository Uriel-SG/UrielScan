import { 
  Organization, 
  ScannerProfile, 
  EngineStatus, 
  Scan, 
  Finding, 
  HostInfo, 
  NSEScript, 
  Schedule, 
  FindingStatus,
  LoginResponse,
  AuthUser,
  Setup2FAResponse,
  RemoteAgent,
  SavedReport,
  SavedAIReport,
  NatCheckResult,
  ProbeInstallerPackage
} from '../types';

const API_BASE = '/api';

const DEFAULT_SCANNER_PROFILE: ScannerProfile = {
  company_name: 'UrielScan Purple Team MSSP',
  contact_email: 'secops@urielscan.io',
  website: 'https://urielscan.io',
  report_footer: 'Documento Riservato - Generato dalla piattaforma UrielScan Purple Team Assessment.',
  logo_url: '',
  ai_provider: 'gemini',
  ai_api_key: '',
  ai_model: 'gemini-2.5-flash',
  ai_base_url: ''
};

function getAuthHeaders(includeContentType = true): Record<string, string> {
  const headers: Record<string, string> = {};
  if (includeContentType) {
    headers['Content-Type'] = 'application/json';
  }
  const token = localStorage.getItem('uriel_token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

function normalizeOrg(raw: any): Organization {
  return {
    id: String(raw.id),
    name: raw.name || 'Organizzazione Senza Nome',
    contact_email: raw.contact_email || '',
    industry: raw.industry || 'Tecnologia & Servizi',
    logo_url: raw.logo_url || raw.logo_data || '',
    notes: raw.notes || raw.description || '',
    target_scope: raw.target_scope || '',
    created_at: raw.created_at || new Date().toISOString(),
    scans_count: raw.scans_count ?? raw.scan_count ?? 0,
    open_vulns_count: raw.open_vulns_count ?? raw.open_findings_count ?? 0,
  };
}

function normalizeProfile(raw: any): ScannerProfile {
  const s = raw.settings || raw;
  return {
    company_name: s.company_name || s.scanner_company_name || DEFAULT_SCANNER_PROFILE.company_name,
    contact_email: s.contact_email || s.scanner_company_email || DEFAULT_SCANNER_PROFILE.contact_email,
    website: s.website || s.scanner_company_website || DEFAULT_SCANNER_PROFILE.website,
    report_footer: s.report_footer || DEFAULT_SCANNER_PROFILE.report_footer,
    logo_url: s.logo_url || s.scanner_company_logo || '',
    ai_provider: (s.ai_provider || 'gemini') as ScannerProfile['ai_provider'],
    ai_api_key: s.ai_api_key || '',
    ai_api_key_configured: Boolean(s.ai_api_key_configured),
    ai_api_key_masked: s.ai_api_key_masked || '',
    ai_model: s.ai_model || 'gemini-2.5-flash',
    ai_base_url: s.ai_base_url || '',
  };
}

function normalizeSeverity(sev: string): Finding['severity'] {
  const s = (sev || 'info').toLowerCase();
  if (s === 'critical') return 'Critical';
  if (s === 'high') return 'High';
  if (s === 'medium') return 'Medium';
  if (s === 'low') return 'Low';
  return 'Info';
}

function normalizeScan(raw: any): Scan {
  const sum = raw.findings_count || raw.summary || {};
  const cfg = raw.config || {};
  const ai = raw.ai_analysis && Object.keys(raw.ai_analysis).length > 0 ? {
    executive_summary: raw.ai_analysis.executive_summary || 'Analisi Purple Team disponibile.',
    red_team_paths: raw.ai_analysis.red_team_paths || (raw.ai_analysis.attack_paths || []).map((ap: any) =>
      typeof ap === 'string' ? ap : `${ap.title || 'Fase'}: ${ap.details || ''}`
    ),
    blue_team_priorities: raw.ai_analysis.blue_team_priorities || (raw.ai_analysis.remediation_plan || []).map((rp: any) =>
      typeof rp === 'string' ? rp : `[${rp.priority || 'P1'}] ${rp.action || ''}`
    ),
    risk_score_reduction: raw.ai_analysis.risk_score_reduction || `Indice di rischio: ${sum.risk_score ?? 50}/100 (${sum.risk_label || 'MEDIO'})`,
  } : undefined;

  return {
    id: String(raw.id),
    org_id: String(raw.org_id),
    agent_id: raw.agent_id ? String(raw.agent_id) : null,
    agent_name: raw.agent_name || null,
    name: raw.name || 'Scansione di Sicurezza',
    targets: raw.targets || '',
    scan_type: raw.scan_type || raw.scan_profile || 'Full Purple Assessment',
    engines: Array.isArray(raw.engines) ? raw.engines : (raw.engines_json ? JSON.parse(raw.engines_json) : ['native']),
    nmap_args: raw.nmap_args || cfg.nmap_flags || '-sV -T4',
    nse_scripts: raw.nse_scripts || cfg.nse_scripts || [],
    nuclei_tags: raw.nuclei_tags || cfg.nuclei_tags || [],
    nuclei_severity: raw.nuclei_severity || cfg.nuclei_severities || [],
    web_checks: raw.web_checks || cfg.web_checks || [],
    zap_mode: raw.zap_mode || cfg.zap_mode || 'baseline',
    onion_mode: Boolean(cfg.onion_mode),
    proxy_url: cfg.proxy_url || undefined,
    routing: sum.routing || undefined,
    status: (raw.status || 'pending') as Scan['status'],
    progress: typeof raw.progress === 'number' ? raw.progress : 0,
    started_at: raw.started_at || new Date().toISOString(),
    completed_at: raw.completed_at || undefined,
    findings_count: {
      critical: sum.critical ?? 0,
      high: sum.high ?? 0,
      medium: sum.medium ?? 0,
      low: sum.low ?? 0,
      info: sum.info ?? 0,
    },
    hosts_count: raw.hosts_count ?? (Array.isArray(raw.hosts) ? raw.hosts.length : (sum.total_hosts ?? 0)),
    hosts: Array.isArray(raw.hosts) ? raw.hosts.map((h: any) => ({
      ip: h.ip || '0.0.0.0',
      hostname: h.hostname || h.ip || '',
      os: h.os || 'Network Host',
      ports: Array.isArray(h.ports) ? h.ports : [],
      vulns_count: h.vulns_count || { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    })) : [],
    logs: (Array.isArray(raw.logs) ? raw.logs : (raw.logs_json ? JSON.parse(raw.logs_json) : [])).map((l: any) =>
      typeof l === 'string' ? l : `[${l.time || ''}] [${l.level || 'INFO'}] ${l.msg || ''}`
    ),
    ai_analysis: ai,
  };
}

function normalizeFinding(raw: any): Finding {
  let cveList: string[] = [];
  if (Array.isArray(raw.cve_ids)) {
    cveList = raw.cve_ids;
  } else if (typeof raw.cve_ids === 'string' && raw.cve_ids.trim()) {
    try {
      const parsed = JSON.parse(raw.cve_ids);
      cveList = Array.isArray(parsed) ? parsed : [raw.cve_ids];
    } catch {
      cveList = raw.cve_ids.split(',').map((c: string) => c.trim()).filter(Boolean);
    }
  }

  let insight = raw.ai_insight;
  if (typeof insight === 'string' && insight.trim()) {
    try {
      insight = JSON.parse(insight);
    } catch {
      insight = {
        red_team_scenario: insight,
        blue_team_fix: raw.remediation || 'Applicare le contromisure raccomandate.',
        mitre_attack_id: raw.mitre_technique || 'T1190',
      };
    }
  }

  return {
    id: String(raw.id),
    scan_id: String(raw.scan_id),
    org_id: String(raw.org_id),
    host: raw.host || '127.0.0.1',
    port: raw.port ?? undefined,
    protocol: raw.protocol || 'tcp',
    service: raw.service || 'tcp',
    title: raw.title || 'Finding',
    severity: normalizeSeverity(raw.severity),
    cvss: typeof raw.cvss === 'number' ? raw.cvss : 0,
    cve_ids: cveList,
    cwe_id: raw.cwe_id || undefined,
    source_engine: (raw.source_engine || 'native_net') as Finding['source_engine'],
    description: raw.description || '',
    evidence: raw.evidence || undefined,
    remediation: raw.remediation || undefined,
    mitre_tactic: raw.mitre_tactic || undefined,
    mitre_technique: raw.mitre_technique || undefined,
    status: (raw.status || 'open') as FindingStatus,
    ai_insight: insight && typeof insight === 'object' ? insight : undefined,
    created_at: raw.created_at || new Date().toISOString(),
  };
}

function normalizeAgent(raw: any): RemoteAgent {
  let engines = raw.engines;
  if (typeof engines === 'string') {
    try { engines = JSON.parse(engines); } catch { engines = {}; }
  }
  return {
    id: String(raw.id),
    org_id: String(raw.org_id),
    org_name: raw.org_name || undefined,
    name: raw.name || 'Remote Probe',
    token_prefix: raw.token_prefix || '',
    token: raw.token || undefined,
    status: (raw.status || 'offline') as 'online' | 'offline',
    last_seen: raw.last_seen || undefined,
    hostname: raw.hostname || undefined,
    ip_address: raw.ip_address || undefined,
    os_info: raw.os_info || undefined,
    engines: engines || undefined,
    version: raw.version || undefined,
    created_at: raw.created_at || new Date().toISOString(),
  };
}

function normalizeSchedule(raw: any): Schedule {
  let cfg = raw.scan_config || {};
  if (typeof cfg === 'string') {
    try { cfg = JSON.parse(cfg); } catch { cfg = {}; }
  } else if (raw.scan_config_json) {
    try { cfg = JSON.parse(raw.scan_config_json); } catch { cfg = {}; }
  }

  return {
    id: String(raw.id ?? raw.schedule_id),
    org_id: String(raw.org_id),
    name: raw.name || 'Pianificazione',
    targets: raw.targets || '',
    profile: raw.profile || cfg.profile || 'Full Purple Assessment (Rete + Web)',
    frequency: (raw.frequency || 'weekly') as Schedule['frequency'],
    cron_expr: raw.cron_expr || undefined,
    time_of_day: raw.time_of_day || '02:00',
    day_of_week: typeof raw.day_of_week === 'number' ? raw.day_of_week : 1,
    enabled: Boolean(raw.enabled),
    last_run: raw.last_run || 'Mai eseguito',
    next_run: raw.next_run || 'Pianificato',
  };
}

export const api = {
  // Authentication & 2FA
  async login(username: string, password: string): Promise<LoginResponse> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Credenziali non valide.' }));
      throw new Error(err.detail || 'Accesso non riuscito');
    }
    const data: any = await res.json();
    if (data.token) {
      localStorage.setItem('uriel_token', data.token);
    }
    const rawUser = data.user;
    return {
      ...data,
      user: rawUser ? {
        id: rawUser.id || 1,
        username: rawUser.username || username,
        two_factor_enabled: Boolean(rawUser.two_factor_enabled ?? rawUser.totp_enabled),
        totp_enabled: Boolean(rawUser.totp_enabled ?? rawUser.two_factor_enabled),
      } : undefined
    };
  },

  async verify2FA(temp_token: string, code: string): Promise<LoginResponse> {
    const res = await fetch(`${API_BASE}/auth/verify-2fa`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ temp_token, code })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Codice 2FA errato.' }));
      throw new Error(err.detail || 'Verifica 2FA non riuscita');
    }
    const data: any = await res.json();
    if (data.token) {
      localStorage.setItem('uriel_token', data.token);
    }
    const rawUser = data.user;
    return {
      ...data,
      user: rawUser ? {
        id: rawUser.id || 1,
        username: rawUser.username || 'admin',
        two_factor_enabled: Boolean(rawUser.two_factor_enabled ?? rawUser.totp_enabled),
        totp_enabled: Boolean(rawUser.totp_enabled ?? rawUser.two_factor_enabled),
      } : undefined
    };
  },

  async getAuthMe(): Promise<{ user: AuthUser }> {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Non autenticato');
    }
    const data = await res.json();
    const rawUser = data.user || data;
    return {
      user: {
        id: rawUser.id || 1,
        username: rawUser.username || 'admin',
        two_factor_enabled: Boolean(rawUser.two_factor_enabled ?? rawUser.totp_enabled ?? data.totp_enabled),
        totp_enabled: Boolean(rawUser.totp_enabled ?? rawUser.two_factor_enabled ?? data.totp_enabled),
      }
    };
  },

  async setup2FA(): Promise<Setup2FAResponse> {
    const res = await fetch(`${API_BASE}/auth/2fa/setup`, {
      method: 'POST',
      headers: getAuthHeaders(true)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore setup 2FA' }));
      throw new Error(err.detail || 'Impossibile configurare 2FA');
    }
    return await res.json();
  },

  async enable2FA(code: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/auth/2fa/enable`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify({ code })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Codice 2FA non valido.' }));
      throw new Error(err.detail || 'Verifica 2FA fallita');
    }
    return await res.json();
  },

  async disable2FA(password: string, code: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/auth/2fa/disable`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify({ password, code })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Credenziali o codice 2FA non validi.' }));
      throw new Error(err.detail || 'Disattivazione 2FA fallita');
    }
    return await res.json();
  },

  async logout(): Promise<void> {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        headers: getAuthHeaders(false)
      });
    } catch {
      // ignore network errors on logout
    }
    localStorage.removeItem('uriel_token');
  },

  async changePassword(current_password: string, new_password: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/auth/change-password`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify({ current_password, new_password })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Password attuale errata.' }));
      throw new Error(err.detail || 'Cambio password fallito');
    }
    return await res.json();
  },

  // Organizations
  async getOrganizations(): Promise<Organization[]> {
    try {
      const res = await fetch(`${API_BASE}/organizations`, { headers: getAuthHeaders(false) });
      if (res.ok) {
        const data = await res.json();
        return Array.isArray(data) ? data.map(normalizeOrg) : [];
      }
    } catch (e) {
      console.warn('Errore recupero organizzazioni:', e);
    }
    return [];
  },

  async createOrganization(org: Omit<Organization, 'id' | 'created_at'>): Promise<Organization> {
    const res = await fetch(`${API_BASE}/organizations`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify({
        ...org,
        logo_data: org.logo_url || '',
        description: org.notes || '',
      })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore creazione organizzazione' }));
      throw new Error(err.detail || 'Errore creazione organizzazione');
    }
    return normalizeOrg(await res.json());
  },

  async updateOrganization(id: string, updates: Partial<Organization>): Promise<Organization> {
    const res = await fetch(`${API_BASE}/organizations/${id}`, {
      method: 'PUT',
      headers: getAuthHeaders(true),
      body: JSON.stringify({
        ...updates,
        logo_data: updates.logo_url,
        description: updates.notes,
      })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore aggiornamento organizzazione' }));
      throw new Error(err.detail || 'Errore aggiornamento organizzazione');
    }
    return normalizeOrg(await res.json());
  },

  async deleteOrganization(id: string): Promise<boolean> {
    const res = await fetch(`${API_BASE}/organizations/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(false)
    });
    return res.ok;
  },

  // Scanner Profile & Branding
  async getScannerProfile(): Promise<ScannerProfile> {
    try {
      const res = await fetch(`${API_BASE}/settings`, { headers: getAuthHeaders(false) });
      if (res.ok) {
        return normalizeProfile(await res.json());
      }
    } catch (e) {
      console.warn('Errore recupero impostazioni scanner:', e);
    }
    return DEFAULT_SCANNER_PROFILE;
  },

  async updateScannerProfile(profile: Partial<ScannerProfile>): Promise<ScannerProfile> {
    const res = await fetch(`${API_BASE}/settings`, {
      method: 'PUT',
      headers: getAuthHeaders(true),
      body: JSON.stringify(profile)
    });
    if (!res.ok) {
      throw new Error('Errore nel salvataggio del profilo MSSP');
    }
    return normalizeProfile(await res.json());
  },

  async clearAiApiKey(): Promise<ScannerProfile> {
    const res = await fetch(`${API_BASE}/settings/ai-api-key`, {
      method: 'DELETE',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Errore durante la rimozione della chiave API');
    }
    return normalizeProfile(await res.json());
  },

  // Engine Status & Nuclei Installer
  async getEngineStatus(): Promise<EngineStatus> {
    try {
      const res = await fetch(`${API_BASE}/system/status`, { headers: getAuthHeaders(false) });
      if (res.ok) {
        const raw = await res.json();
        if (raw.engines) {
          return {
            nmap: {
              available: Boolean(raw.engines.nmap?.installed ?? raw.engines.nmap?.available ?? false),
              version: raw.engines.nmap?.version || 'Nmap 7.95',
              scripts_count: raw.engines.nmap?.nse_count || raw.engines.nmap?.scripts_count || 609,
            },
            nuclei: {
              available: Boolean(raw.engines.nuclei?.installed ?? raw.engines.nuclei?.available ?? false),
              version: raw.engines.nuclei?.version || undefined,
            },
            zap: {
              available: Boolean(raw.engines.zap?.installed ?? raw.engines.zap?.available ?? false),
              version: raw.engines.zap?.version || undefined,
              mode: raw.engines.zap?.mode || undefined,
            },
            tor: {
              available: Boolean(raw.engines.tor?.installed ?? raw.engines.tor?.available ?? false),
              installed: Boolean(raw.engines.tor?.installed ?? false),
              version: raw.engines.tor?.version || undefined,
              running: Boolean(raw.engines.tor?.running ?? false),
              socks_port: raw.engines.tor?.socks_port,
              control_port: raw.engines.tor?.control_port,
              proxy_url: raw.engines.tor?.proxy_url || undefined,
            },
            native: {
              available: true,
            },
            ai: {
              configured: Boolean(raw.system?.ai_configured),
              provider: raw.system?.ai_provider || 'Google Gemini',
              model: raw.system?.ai_model || 'gemini-2.5-flash',
            },
            bootstrap: raw.bootstrap,
          };
        }
        return raw;
      }
    } catch (e) {
      console.warn('Errore stato motori:', e);
    }
    return {
      nmap: { available: false, version: 'Non rilevato', scripts_count: 0 },
      nuclei: { available: false },
      zap: { available: false },
      tor: { available: false, installed: false, running: false },
      native: { available: true },
      ai: { configured: false, provider: 'None', model: '' }
    };
  },

  async installNmap(): Promise<{ success: boolean; message: string; version?: string }> {
    const res = await fetch(`${API_BASE}/system/install-nmap`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Installazione Nmap fallita');
    }
    return await res.json();
  },

  async installNuclei(): Promise<{ success: boolean; message: string; version?: string }> {
    const res = await fetch(`${API_BASE}/system/install-nuclei`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Installazione Nuclei fallita');
    }
    return await res.json();
  },

  async installZap(): Promise<{ success: boolean; message: string; version?: string }> {
    const res = await fetch(`${API_BASE}/system/install-zap`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Installazione OWASP ZAP fallita');
    }
    return await res.json();
  },

  async installTor(): Promise<{ success: boolean; message: string; version?: string }> {
    const res = await fetch(`${API_BASE}/system/install-tor`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Installazione Tor fallita');
    }
    return await res.json();
  },

  async startTor(): Promise<{ ok: boolean; ip?: string; is_tor?: boolean; proxy_url?: string; error?: string; tor?: EngineStatus['tor'] }> {
    const res = await fetch(`${API_BASE}/system/tor/start`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Avvio demone Tor fallito' }));
      throw new Error(err.detail || 'Avvio demone Tor fallito');
    }
    return await res.json();
  },

  async stopTor(): Promise<{ ok: boolean; stopped?: boolean; message?: string; tor?: EngineStatus['tor'] }> {
    const res = await fetch(`${API_BASE}/system/tor/stop`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Arresto demone Tor fallito');
    }
    return await res.json();
  },

  async newTorIdentity(): Promise<{ ok: boolean; ip?: string; is_tor?: boolean; message?: string; error?: string; tor?: EngineStatus['tor'] }> {
    const res = await fetch(`${API_BASE}/system/tor/new-identity`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Rotazione circuito Tor fallita' }));
      throw new Error(err.detail || 'Rotazione circuito Tor fallita');
    }
    return await res.json();
  },

  async testProxy(proxyUrl: string): Promise<{ ok: boolean; ip?: string; is_tor?: boolean; proxy_url?: string; error?: string }> {
    const res = await fetch(`${API_BASE}/system/proxy/test`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify({ proxy_url: proxyUrl })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Test proxy fallito' }));
      throw new Error(err.detail || 'Test proxy fallito');
    }
    return await res.json();
  },

  async installAllEngines(): Promise<{ started: boolean; bootstrap?: EngineStatus['bootstrap'] }> {
    const res = await fetch(`${API_BASE}/system/install-all-engines`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Avvio installazione motori fallito');
    }
    return await res.json();
  },

  async resetAllData(includeOrganizations = false): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/system/reset-data?include_organizations=${includeOrganizations}`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Errore durante il reset del database.');
    }
    return await res.json();
  },

  async seedDemoData(): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/system/seed-demo`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Errore durante il ripristino dei dati demo.');
    }
    return await res.json();
  },

  async testAIConnection(config: { provider: string; api_key?: string; model: string; base_url?: string }): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/ai/test`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify(config)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore test AI' }));
      throw new Error(err.detail || 'Connessione AI non riuscita');
    }
    return await res.json();
  },

  // Scans
  async getScans(orgId?: string): Promise<Scan[]> {
    try {
      const url = orgId ? `${API_BASE}/scans?org_id=${encodeURIComponent(orgId)}` : `${API_BASE}/scans`;
      const res = await fetch(url, { headers: getAuthHeaders(false) });
      if (res.ok) {
        const data = await res.json();
        return Array.isArray(data) ? data.map(normalizeScan) : [];
      }
    } catch (e) {
      console.warn('Errore recupero scansioni:', e);
    }
    return [];
  },

  async getScan(id: string): Promise<Scan> {
    const res = await fetch(`${API_BASE}/scans/${id}`, { headers: getAuthHeaders(false) });
    if (!res.ok) {
      throw new Error(`Scansione #${id} non trovata`);
    }
    return normalizeScan(await res.json());
  },

  async createScan(scanData: {
    org_id: string;
    agent_id?: string | null;
    name: string;
    targets: string;
    scan_type: string;
    engines: string[];
    config?: Record<string, any>;
    nmap_args?: string;
    nse_scripts?: string[];
    nuclei_tags?: string[];
    nuclei_severity?: string[];
    web_checks?: string[];
    zap_mode?: 'baseline' | 'full';
    onion_mode?: boolean;
    proxy_url?: string;
  }): Promise<Scan> {
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify(scanData)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore creazione scansione' }));
      throw new Error(err.detail || 'Impossibile avviare la scansione');
    }
    return normalizeScan(await res.json());
  },

  async stopScan(id: string): Promise<boolean> {
    const res = await fetch(`${API_BASE}/scans/${id}/stop`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    return res.ok;
  },

  async deleteScan(id: string): Promise<boolean> {
    const res = await fetch(`${API_BASE}/scans/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(false)
    });
    return res.ok;
  },

  // Remote Probes & Agents
  async getAgents(orgId?: string): Promise<RemoteAgent[]> {
    try {
      const url = orgId ? `${API_BASE}/agents?org_id=${encodeURIComponent(orgId)}` : `${API_BASE}/agents`;
      const res = await fetch(url, { headers: getAuthHeaders(false) });
      if (res.ok) {
        const data = await res.json();
        return Array.isArray(data) ? data.map(normalizeAgent) : [];
      }
    } catch (e) {
      console.warn('Errore recupero sonde remote:', e);
    }
    return [];
  },

  async createAgent(payload: { org_id: string; name: string }): Promise<RemoteAgent> {
    const res = await fetch(`${API_BASE}/agents`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore creazione sonda remota' }));
      throw new Error(err.detail || 'Errore creazione sonda remota');
    }
    return normalizeAgent(await res.json());
  },

  async deleteAgent(id: string): Promise<boolean> {
    const res = await fetch(`${API_BASE}/agents/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(false)
    });
    return res.ok;
  },

  async downloadProbeScript(): Promise<void> {
    const res = await fetch(`${API_BASE}/agents/probe-script`, {
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore download probe script' }));
      throw new Error(err.detail || 'Impossibile scaricare urielscan_probe.py');
    }
    await triggerBlobDownload(res, 'urielscan_probe.py');
  },

  // Findings
  async getFindings(scanId?: string, orgId?: string): Promise<Finding[]> {
    try {
      const params = new URLSearchParams();
      if (scanId) params.append('scan_id', scanId);
      if (orgId) params.append('org_id', orgId);
      const url = scanId ? `${API_BASE}/scans/${scanId}/findings` : `${API_BASE}/findings?${params.toString()}`;
      const res = await fetch(url, { headers: getAuthHeaders(false) });
      if (res.ok) {
        const data = await res.json();
        return Array.isArray(data) ? data.map(normalizeFinding) : [];
      }
    } catch (e) {
      console.warn('Errore recupero findings:', e);
    }
    return [];
  },

  async updateFindingStatus(id: string, status: FindingStatus): Promise<Finding> {
    const res = await fetch(`${API_BASE}/findings/${id}`, {
      method: 'PATCH',
      headers: getAuthHeaders(true),
      body: JSON.stringify({ status })
    });
    if (!res.ok) {
      throw new Error('Impossibile aggiornare lo stato della vulnerabilità');
    }
    return normalizeFinding(await res.json());
  },

  // NSE Catalog & Hosts
  async getNSEScripts(): Promise<NSEScript[]> {
    try {
      const res = await fetch(`${API_BASE}/nmap/scripts`, { headers: getAuthHeaders(false) });
      if (res.ok) {
        const raw = await res.json();
        const list = Array.isArray(raw) ? raw : (raw.scripts || []);
        return list.map((s: any) => ({
          name: s.id || s.name,
          categories: Array.isArray(s.categories) ? s.categories : [s.category || 'safe'],
          description: s.name && s.id && s.name !== s.id ? `${s.name} — ${s.description || ''}` : (s.description || ''),
          author: s.author,
          arguments: s.arguments || (s.args ? [s.args] : []),
        }));
      }
    } catch (e) {
      console.warn('Errore catalogo NSE:', e);
    }
    return [];
  },

  async getHosts(scanId?: string): Promise<HostInfo[]> {
    try {
      const url = scanId ? `${API_BASE}/scans/${scanId}/hosts` : `${API_BASE}/hosts`;
      const res = await fetch(url, { headers: getAuthHeaders(false) });
      if (res.ok) {
        const raw = await res.json();
        if (Array.isArray(raw)) {
          return raw.map((h: any) => ({
            ip: h.ip || '127.0.0.1',
            hostname: h.hostname || h.ip,
            os: h.os || 'Rilevato',
            ports: (h.ports || []).map((p: any) => ({
              port: p.port,
              protocol: p.protocol || 'tcp',
              state: p.state || 'open',
              service: p.service || 'tcp',
              version: p.version || '',
              banner: p.banner || '',
            })),
            vulns_count: h.vulns_count || { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          }));
        }
      }
    } catch (e) {
      console.warn('Errore recupero hosts:', e);
    }
    return [];
  },

  // AI Purple Team Analyst
  async analyzeWithAI(payload: {
    scan_id?: string;
    finding_ids?: string[];
    mode: 'purple' | 'red' | 'blue' | 'executive';
    extra_prompt?: string;
    lang?: 'en' | 'it';
  }): Promise<{
    executive_summary: string;
    red_team_paths: string[];
    blue_team_priorities: string[];
    mitre_techniques: { id: string; name: string; tactic: string; description: string }[];
    remediation_script?: string;
  }> {
    const res = await fetch(`${API_BASE}/ai/analyze`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore durante l\'analisi AI.' }));
      throw new Error(err.detail || 'Analisi AI fallita');
    }
    const raw = await res.json();
    return {
      executive_summary: raw.executive_summary || 'Analisi completata.',
      red_team_paths: raw.red_team_paths || [],
      blue_team_priorities: raw.blue_team_priorities || [],
      mitre_techniques: raw.mitre_techniques || [],
      remediation_script: raw.remediation_script || undefined,
    };
  },

  // Schedules
  async getSchedules(orgId?: string): Promise<Schedule[]> {
    try {
      const url = orgId ? `${API_BASE}/schedules?org_id=${encodeURIComponent(orgId)}` : `${API_BASE}/schedules`;
      const res = await fetch(url, { headers: getAuthHeaders(false) });
      if (res.ok) {
        const data = await res.json();
        return Array.isArray(data) ? data.map(normalizeSchedule) : [];
      }
    } catch (e) {
      console.warn('Errore recupero schedulazioni:', e);
    }
    return [];
  },

  async createSchedule(schedule: Omit<Schedule, 'id' | 'last_run' | 'next_run'>): Promise<Schedule> {
    const res = await fetch(`${API_BASE}/schedules`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify(schedule)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore creazione pianificazione' }));
      throw new Error(err.detail || 'Impossibile creare la pianificazione');
    }
    return normalizeSchedule(await res.json());
  },

  async updateSchedule(id: string, updates: Partial<Schedule>): Promise<Schedule> {
    const res = await fetch(`${API_BASE}/schedules/${id}`, {
      method: 'PUT',
      headers: getAuthHeaders(true),
      body: JSON.stringify(updates)
    });
    if (!res.ok) {
      throw new Error('Errore aggiornamento pianificazione');
    }
    return normalizeSchedule(await res.json());
  },

  async deleteSchedule(id: string): Promise<boolean> {
    const res = await fetch(`${API_BASE}/schedules/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(false)
    });
    return res.ok;
  },

  async runScheduleNow(id: string): Promise<{ success: boolean; scan_id: string }> {
    const res = await fetch(`${API_BASE}/schedules/${id}/run`, {
      method: 'POST',
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Impossibile eseguire la schedulazione');
    }
    const raw = await res.json();
    return { success: true, scan_id: String(raw.scan_id) };
  },

  async downloadScanExport(scanId: string, format: 'csv' | 'txt' | 'pdf', lang: 'en' | 'it' = 'en'): Promise<void> {
    const res = await fetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/export?format=${format}&lang=${lang}`, {
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore durante l\'esportazione' }));
      throw new Error(err.detail || 'Esportazione fallita');
    }
    await triggerBlobDownload(res, `urielscan_${scanId === 'ALL' ? 'all_scans' : `scan_${scanId}`}.${format}`);
  },

  async downloadCustomReport(payload: {
    scan_id: string | number;
    format: 'pdf' | 'docx' | 'html';
    report_title: string;
    classification: string;
    executive_notes: string;
    include_ai: boolean;
    include_evidence: boolean;
    include_host_topology: boolean;
    lang?: 'en' | 'it';
  }): Promise<void> {
    const res = await fetch(`${API_BASE}/reports/export`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Errore nella generazione del report' }));
      throw new Error(err.detail || 'Generazione report fallita');
    }
    await triggerBlobDownload(res, `urielscan_report_scan_${payload.scan_id}.${payload.format}`);
  },

  // Saved Reports Management
  async getReports(orgId?: string): Promise<SavedReport[]> {
    const url = orgId && orgId !== 'ALL' ? `${API_BASE}/reports?org_id=${encodeURIComponent(orgId)}` : `${API_BASE}/reports`;
    const res = await fetch(url, { headers: getAuthHeaders(false) });
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  },

  async deleteReport(reportId: string): Promise<boolean> {
    const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(reportId)}`, {
      method: 'DELETE',
      headers: getAuthHeaders(false)
    });
    return res.ok;
  },

  async openSavedReport(reportId: string, download: boolean = false): Promise<void> {
    const endpoint = download ? 'download' : 'view';
    const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(reportId)}/${endpoint}`, {
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Failed to open saved report');
    }
    const contentType = res.headers.get('Content-Type') || '';
    const isDocx = contentType.includes('wordprocessingml');
    if (download || isDocx) {
      const ext = contentType.includes('pdf') ? 'pdf' : isDocx ? 'docx' : 'html';
      await triggerBlobDownload(res, `${reportId}.${ext}`);
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank', 'noopener,noreferrer');
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  },

  // Saved AI Purple Analyst Reports
  async getAiReports(orgId?: string): Promise<SavedAIReport[]> {
    const url = orgId && orgId !== 'ALL' ? `${API_BASE}/ai/reports?org_id=${encodeURIComponent(orgId)}` : `${API_BASE}/ai/reports`;
    const res = await fetch(url, { headers: getAuthHeaders(false) });
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  },

  async deleteAiReport(reportId: string): Promise<boolean> {
    const res = await fetch(`${API_BASE}/ai/reports/${encodeURIComponent(reportId)}`, {
      method: 'DELETE',
      headers: getAuthHeaders(false)
    });
    return res.ok;
  },

  // NAT Loopback Guard Check
  async checkNatLoopback(targets: string): Promise<NatCheckResult> {
    const res = await fetch(`${API_BASE}/network/nat-check?targets=${encodeURIComponent(targets)}`, {
      headers: getAuthHeaders(false)
    });
    if (!res.ok) {
      return { egress_public_ip: null, has_nat_loopback: false, loopback_targets: [], details: [] };
    }
    return await res.json();
  },

  // Remote Probe Self-Contained Installers (.msi / .sh)
  async downloadProbeInstaller(
    agentId: string | number,
    payload: { platform: 'windows_msi' | 'linux_sh'; server_url?: string; token?: string; insecure?: boolean }
  ): Promise<void> {
    const res = await fetch(`${API_BASE}/agents/${encodeURIComponent(String(agentId))}/installer`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Installer generation failed' }));
      throw new Error(err.detail || 'Installer generation failed');
    }
    const ext = payload.platform === 'windows_msi' ? 'msi' : 'sh';
    await triggerBlobDownload(res, `urielscan-probe-${agentId}.${ext}`);
  },

  async createProbeInstallerLink(
    agentId: string | number,
    payload: { platform: 'windows_msi' | 'linux_sh'; server_url?: string; token?: string; insecure?: boolean }
  ): Promise<ProbeInstallerPackage> {
    const res = await fetch(`${API_BASE}/agents/${encodeURIComponent(String(agentId))}/installer-link`, {
      method: 'POST',
      headers: getAuthHeaders(true),
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to prepare probe installer link' }));
      throw new Error(err.detail || 'Failed to prepare probe installer link');
    }
    return await res.json();
  }
};

async function triggerBlobDownload(res: Response, fallbackFilename: string): Promise<void> {
  const blob = await res.blob();
  const disposition = res.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="?([^"]+)"?/i);
  const filename = match?.[1] || fallbackFilename;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
