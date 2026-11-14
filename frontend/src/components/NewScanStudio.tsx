import React, { useState, useMemo, useEffect } from 'react';
import { 
  Crosshair, 
  Terminal, 
  Search, 
  Sliders, 
  Layers, 
  Play, 
  Globe, 
  Lock, 
  Sparkles, 
  Check, 
  Loader2,
  Radio
} from 'lucide-react';
import { Organization, NSEScript, Scan, RemoteAgent } from '../types';
import { api } from '../services/api';
import { useToast } from './UIFeedback';
import { useI18n } from '../i18n/LanguageContext';

interface NewScanStudioProps {
  organizations: Organization[];
  selectedOrgId: string;
  nseScripts: NSEScript[];
  onScanCreated: (scan: Scan) => void;
  onStartScan?: (payload: any) => Promise<Scan>;
  scans?: Scan[];
  onRefreshData?: () => void;
}

interface ProfileTemplate {
  id: string;
  name: string;
  description: string;
  engines: string[];
  ports: string;
  nmapFlags: { [flag: string]: boolean };
  nseScripts: string[];
  nucleiSeverity: string[];
  nucleiTags: string[];
  webChecks: string[];
}

const getProfiles = (L: (en: string, it: string) => string): ProfileTemplate[] => [
  {
    id: 'full-purple',
    name: L('Full Purple Assessment (Network + Web)', 'Full Purple Assessment (Rete + Web)'),
    description: L('Complete offensive/defensive assessment: Nmap NSE, Nuclei OWASP templates, and Native Engine across network and web.', 'Valutazione completa offensiva/difensiva: Nmap NSE, Nuclei OWASP templates e Native Engine su rete e web.'),
    engines: ['nmap', 'native_web', 'native_net', 'nuclei'],
    ports: 'top-1000',
    nmapFlags: { '-sV': true, '-sC': true, '-O': true, '-Pn': true, '-T4': true, '-sS': true },
    nseScripts: ['ssl-enum-ciphers', 'http-headers', 'ssl-cert', 'http-title', 'ssh2-enum-algos', 'banner'],
    nucleiSeverity: ['critical', 'high', 'medium'],
    nucleiTags: ['cve', 'owasp', 'misconfig', 'exposure'],
    webChecks: ['headers', 'cors', 'cookies', 'sensitive_files', 'sqli_probe', 'xss_probe', 'ssl']
  },
  {
    id: 'quick-discovery',
    name: L('Quick Network Discovery', 'Quick Network Discovery'),
    description: L('Rapid reconnaissance scan: host discovery, top open ports, and service banners in seconds.', 'Scansione rapida di ricognizione: host discovery, top porte aperte e banner dei servizi in pochi secondi.'),
    engines: ['nmap', 'native_net'],
    ports: 'top-100',
    nmapFlags: { '-sV': true, '-sC': false, '-O': false, '-Pn': true, '-T4': true, '-sS': true },
    nseScripts: ['banner'],
    nucleiSeverity: ['critical', 'high'],
    nucleiTags: ['cve'],
    webChecks: []
  },
  {
    id: 'nse-sweep',
    name: L('NSE Vulnerability Sweep', 'NSE Vulnerability Sweep'),
    description: L('Massive sweep with Nmap NSE scripts for known vulnerabilities (EternalBlue, Path Traversal, weak SSL).', 'Sweep massivo con script Nmap NSE per vulnerabilità note (EternalBlue, Path Traversal, SSL deboli).'),
    engines: ['nmap'],
    ports: 'top-1000',
    nmapFlags: { '-sV': true, '-sC': true, '-O': true, '-Pn': true, '-T4': true, '-sS': true },
    nseScripts: ['vuln', 'ssl-enum-ciphers', 'smb-vuln-ms17-010', 'http-vuln-cve2021-41773'],
    nucleiSeverity: [],
    nucleiTags: [],
    webChecks: []
  },
  {
    id: 'web-owasp',
    name: L('Web Application & OWASP Audit', 'Web Application & OWASP Audit'),
    description: L('Audit focused on HTTP/HTTPS applications, security headers, sensitive files, and Nuclei templates.', 'Audit incentrato su applicazioni HTTP/HTTPS, security headers, file sensibili e Nuclei templates.'),
    engines: ['native_web', 'nuclei'],
    ports: '80,443,8080,8443',
    nmapFlags: { '-sV': true, '-sC': false, '-O': false, '-Pn': true, '-T4': true, '-sS': false },
    nseScripts: ['http-headers', 'http-title', 'http-enum'],
    nucleiSeverity: ['critical', 'high', 'medium', 'low', 'info'],
    nucleiTags: ['owasp', 'cve', 'exposure', 'misconfig'],
    webChecks: ['headers', 'cors', 'cookies', 'sensitive_files', 'sqli_probe', 'xss_probe', 'ssl']
  },
  {
    id: 'ssl-crypto',
    name: L('SSL/TLS & Crypto Check', 'SSL/TLS & Crypto Check'),
    description: L('In-depth cryptographic inspection of X.509 certificates, weak cipher suites, TLS 1.0/1.1, and HSTS.', 'Ispezione crittografica approfondita dei certificati X.509, cipher suite deboli, TLS 1.0/1.1 e HSTS.'),
    engines: ['nmap', 'native_web', 'native_net'],
    ports: '443,8443',
    nmapFlags: { '-sV': true, '-sC': false, '-O': false, '-Pn': true, '-T4': true, '-sS': false },
    nseScripts: ['ssl-enum-ciphers', 'ssl-cert'],
    nucleiSeverity: ['medium', 'low', 'info'],
    nucleiTags: ['ssl', 'tls'],
    webChecks: ['headers', 'ssl']
  }
];

export const NewScanStudio: React.FC<NewScanStudioProps> = ({
  organizations,
  selectedOrgId,
  nseScripts,
  onScanCreated,
  onStartScan,
  scans = [],
  onRefreshData,
}) => {
  const { locale, L } = useI18n();
  const { showToast } = useToast();

  const profiles = useMemo(() => getProfiles(L), [L]);

  const initialOrg = organizations.find((o) => o.id === (selectedOrgId !== 'ALL' ? selectedOrgId : organizations[0]?.id)) || organizations[0];

  const [orgId, setOrgId] = useState<string>(initialOrg?.id || '');
  const [agents, setAgents] = useState<RemoteAgent[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');
  const [scanName, setScanName] = useState<string>(() => L('Purple Assessment - Corporate Perimeter', 'Purple Assessment - Perimetro Aziendale'));
  const [targets, setTargets] = useState<string>(initialOrg?.target_scope || '192.168.1.0/24');
  const [isSavingScope, setIsSavingScope] = useState<boolean>(false);

  useEffect(() => {
    api.getAgents().then((data) => {
      setAgents(data);
    }).catch((err) => {
      console.warn('Errore recupero sonde:', err);
    });
  }, []);

  const availableProbes = useMemo(() => {
    return agents.filter((a) => String(a.org_id) === String(orgId));
  }, [agents, orgId]);

  const selectedOrg = useMemo(
    () => organizations.find((o) => o.id === orgId) || organizations[0],
    [organizations, orgId]
  );

  // Extract registered networks for the selected organization + historical scanned targets for this org
  const orgNetworkOptions = useMemo(() => {
    const registeredRaw = selectedOrg?.target_scope || '';
    const splitItems = registeredRaw
      .split(/[,;\n]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    const options: { value: string; label: string; group: 'registered' | 'history' | 'preset' }[] = [];
    const seen = new Set<string>();

    // If the organization has multiple comma-separated targets, offer both the full scope and individual networks
    if (splitItems.length > 1) {
      const fullScope = splitItems.join(', ');
      seen.add(fullScope);
      options.push({
        value: fullScope,
        label: `${L('All registered networks', 'Tutte le reti registrate')} (${splitItems.length} targets: ${fullScope})`,
        group: 'registered',
      });
    }

    for (const item of splitItems) {
      if (!seen.has(item)) {
        seen.add(item);
        options.push({
          value: item,
          label: `${L('Registered Network', 'Rete Registrata')} [${selectedOrg?.name || L('Company', 'Azienda')}]: ${item}`,
          group: 'registered',
        });
      }
    }

    // Also include any networks previously scanned for this organization
    const orgScans = scans.filter((s) => s.org_id === orgId);
    for (const sc of orgScans) {
      const t = (sc.targets || '').trim();
      if (t && !seen.has(t)) {
        seen.add(t);
        options.push({
          value: t,
          label: `${L('Recently scanned', 'Scansionata di recente')} [${selectedOrg?.name || L('Company', 'Azienda')}]: ${t}`,
          group: 'history',
        });
      }
    }

    // Standard presets
    const presets = [
      { value: '192.168.1.0/24', label: `${L('Local LAN Subnet', 'Sottorete LAN Locale')} (192.168.1.0/24)` },
      { value: '127.0.0.1', label: `${L('Localhost Loopback', 'Localhost Loopback')} (127.0.0.1)` },
    ];
    for (const p of presets) {
      if (!seen.has(p.value)) {
        seen.add(p.value);
        options.push({ ...p, group: 'preset' });
      }
    }

    return options;
  }, [selectedOrg, scans, orgId, L]);

  const handleOrgChange = (newOrgId: string) => {
    setOrgId(newOrgId);
    setSelectedAgentId('');
    const nextOrg = organizations.find((o) => o.id === newOrgId);
    if (nextOrg?.target_scope) {
      setTargets(nextOrg.target_scope);
    }
  };

  const isTargetAlreadyRegistered = useMemo(() => {
    const trimmed = targets.trim();
    if (!trimmed || !selectedOrg) return true;
    const existing = (selectedOrg.target_scope || '')
      .split(/[,;\n]+/)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    return (
      selectedOrg.target_scope?.trim().toLowerCase() === trimmed.toLowerCase() ||
      existing.includes(trimmed.toLowerCase())
    );
  }, [targets, selectedOrg]);

  const handleSaveTargetToOrgScope = async () => {
    const trimmed = targets.trim();
    if (!trimmed || !selectedOrg) return;
    setIsSavingScope(true);
    try {
      const currentScope = (selectedOrg.target_scope || '').trim();
      const updatedScope = currentScope ? `${currentScope}, ${trimmed}` : trimmed;
      await api.updateOrganization(selectedOrg.id, { target_scope: updatedScope });
      showToast(L(`Network "${trimmed}" added to registered networks of ${selectedOrg.name}.`, `Rete "${trimmed}" aggiunta alle reti registrate di ${selectedOrg.name}.`), 'success');
      if (onRefreshData) onRefreshData();
    } catch (err: any) {
      showToast(err.message || L('Error saving corporate network.', 'Errore salvataggio rete aziendale.'), 'error');
    } finally {
      setIsSavingScope(false);
    }
  };

  const [activeProfile, setActiveProfile] = useState<string>('full-purple');

  const [engines, setEngines] = useState<{ [k: string]: boolean }>({
    nmap: true,
    nuclei: true,
    native_web: true,
    native_net: true,
  });

  const [portSelection, setPortSelection] = useState<string>('top-1000');
  const [customPorts, setCustomPorts] = useState<string>('22,80,443,3389,8080');

  const [nmapFlags, setNmapFlags] = useState<{ [k: string]: boolean }>({
    '-sV': true,
    '-sC': true,
    '-O': true,
    '-Pn': true,
    '-T4': true,
    '-sS': true,
  });

  const [selectedNseScripts, setSelectedNseScripts] = useState<string[]>([
    'ssl-enum-ciphers',
    'http-headers',
    'ssl-cert',
    'http-title',
  ]);

  const [nucleiSeverity, setNucleiSeverity] = useState<string[]>(['critical', 'high', 'medium']);
  const [nucleiTags, setNucleiTags] = useState<string[]>(['cve', 'owasp', 'misconfig']);
  const [webChecks, setWebChecks] = useState<string[]>([
    'headers',
    'cors',
    'cookies',
    'sensitive_files',
    'sqli_probe',
    'ssl',
  ]);

  const [nseSearch, setNseSearch] = useState<string>('');
  const [nseCategoryFilter, setNseCategoryFilter] = useState<string>('all');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const handleApplyProfile = (profId: string) => {
    const prof = profiles.find((p) => p.id === profId);
    if (!prof) return;

    setActiveProfile(prof.id);
    const newEngines: { [k: string]: boolean } = {
      nmap: prof.engines.includes('nmap'),
      nuclei: prof.engines.includes('nuclei'),
      native_web: prof.engines.includes('native_web'),
      native_net: prof.engines.includes('native_net'),
    };
    setEngines(newEngines);

    if (prof.ports === 'top-100' || prof.ports === 'top-1000' || prof.ports === '1-65535') {
      setPortSelection(prof.ports);
    } else {
      setPortSelection('custom');
      setCustomPorts(prof.ports);
    }

    setNmapFlags({ ...prof.nmapFlags });
    setSelectedNseScripts([...prof.nseScripts]);
    setNucleiSeverity([...prof.nucleiSeverity]);
    setNucleiTags([...prof.nucleiTags]);
    setWebChecks([...prof.webChecks]);
    showToast(L(`Profile "${prof.name}" applied to configuration.`, `Profilo "${prof.name}" applicato alla configurazione.`), 'info');
  };

  const toggleEngine = (eng: string) => {
    setEngines((prev) => ({ ...prev, [eng]: !prev[eng] }));
  };

  const toggleNmapFlag = (flag: string) => {
    setNmapFlags((prev) => ({ ...prev, [flag]: !prev[flag] }));
  };

  const toggleNseScript = (scriptName: string) => {
    setSelectedNseScripts((prev) =>
      prev.includes(scriptName)
        ? prev.filter((s) => s !== scriptName)
        : [...prev, scriptName]
    );
  };

  const toggleWebCheck = (checkId: string) => {
    setWebChecks((prev) =>
      prev.includes(checkId) ? prev.filter((c) => c !== checkId) : [...prev, checkId]
    );
  };

  const toggleNucleiSeverity = (sev: string) => {
    setNucleiSeverity((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
    );
  };

  const filteredNSEScripts = useMemo(() => {
    return nseScripts.filter((script) => {
      const matchSearch =
        script.name.toLowerCase().includes(nseSearch.toLowerCase()) ||
        script.description.toLowerCase().includes(nseSearch.toLowerCase());
      const matchCategory =
        nseCategoryFilter === 'all' ||
        script.categories.includes(nseCategoryFilter);
      return matchSearch && matchCategory;
    });
  }, [nseScripts, nseSearch, nseCategoryFilter]);

  const activeFlagsString = useMemo(() => {
    return Object.entries(nmapFlags)
      .filter(([, val]) => val)
      .map(([flag]) => flag)
      .join(' ');
  }, [nmapFlags]);

  const liveNmapCommand = useMemo(() => {
    let portArg = '';
    if (portSelection === 'top-100') portArg = '--top-ports 100';
    else if (portSelection === 'top-1000') portArg = '--top-ports 1000';
    else if (portSelection === '1-65535') portArg = '-p 1-65535';
    else if (portSelection === 'custom') portArg = `-p ${customPorts}`;

    let scriptArg = '';
    if (selectedNseScripts.length > 0) {
      scriptArg = `--script=${selectedNseScripts.join(',')}`;
    }

    return `nmap ${activeFlagsString} ${portArg} ${scriptArg} -oX - ${targets || '<target>'}`.replace(/\s+/g, ' ').trim();
  }, [activeFlagsString, portSelection, customPorts, selectedNseScripts, targets]);

  const liveNucleiCommand = useMemo(() => {
    const sevArg = nucleiSeverity.length > 0 ? `-s ${nucleiSeverity.join(',')}` : '';
    const tagArg = nucleiTags.length > 0 ? `-tags ${nucleiTags.join(',')}` : '';
    return `nuclei -u ${targets.split(',')[0]?.trim() || '<target>'} ${sevArg} ${tagArg} -jsonl`.replace(/\s+/g, ' ').trim();
  }, [nucleiSeverity, nucleiTags, targets]);

  const handleLaunchScan = async () => {
    if (!targets.trim()) {
      showToast(L('Please enter at least one valid target (IP, host or CIDR).', 'Inserisci almeno un target valido (IP, host o CIDR).'), 'warning', L('Missing Target', 'Target Mancante'));
      return;
    }

    const activeEnginesList = Object.entries(engines)
      .filter(([, v]) => v)
      .map(([k]) => k);

    if (activeEnginesList.length === 0) {
      showToast(L('Please select at least one active scanning engine.', 'Seleziona almeno un motore di scansione attivo.'), 'warning', L('Engines Disabled', 'Motori Disattivati'));
      return;
    }

    setIsSubmitting(true);
    const activeProfileObj = profiles.find((p) => p.id === activeProfile);

    const scanPayload = {
      org_id: orgId || (organizations[0]?.id || '1'),
      agent_id: selectedAgentId || null,
      name: scanName.trim() || `${L('Scan', 'Scansione')} ${new Date().toLocaleTimeString(locale)}`,
      targets: targets.trim(),
      scan_type: activeProfileObj?.name || 'Purple Assessment',
      engines: activeEnginesList,
      config: {
        ports: portSelection === 'custom' ? customPorts : portSelection,
        nmap_flags: activeFlagsString,
        nse_scripts: selectedNseScripts,
        nuclei_tags: nucleiTags,
        nuclei_severities: nucleiSeverity,
        web_checks: webChecks,
      },
      nmap_args: liveNmapCommand,
      nse_scripts: selectedNseScripts,
      nuclei_tags: nucleiTags,
      nuclei_severity: nucleiSeverity,
      web_checks: webChecks,
    };

    try {
      const created = onStartScan ? await onStartScan(scanPayload) : await api.createScan(scanPayload);
      showToast(L(`Scan #${created.id} launched successfully on backend.`, `Scansione #${created.id} avviata con successo sul backend.`), 'success', L('Scan Launched', 'Scansione Avviata'));
      onScanCreated(created);
    } catch (err: any) {
      showToast(err.message || L('Unable to launch scan on server.', 'Impossibile avviare la scansione sul server.'), 'error', L('Launch Error', 'Errore di Avvio'));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header bar */}
      <div className="card-industrial p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-[11px] uppercase font-bold tracking-wider text-theme-accent">
            <Crosshair className="w-3.5 h-3.5" />
            <span>{L('Purple Team & ZenMap++ Studio Configurator', 'Configuratore Purple Team & ZenMap++ Studio')}</span>
          </div>
          <h1 className="text-base font-bold text-theme-primary mt-0.5 tracking-tight">
            {L('New Hybrid Security Scan', 'Nuova Scansione Ibrida di Sicurezza')}
          </h1>
          <p className="text-xs text-theme-secondary mt-0.5">
            {L('Orchestrate Nmap with NSE scripts, native async probes and Nuclei templates in a single analysis cycle.', 'Orchestra Nmap con script NSE, probe asincrone native e template Nuclei in un unico ciclo di analisi.')}
          </p>
        </div>

        <div>
          <button
            onClick={handleLaunchScan}
            disabled={isSubmitting}
            className="btn-primary flex items-center space-x-2 px-4 py-2 text-xs font-semibold shadow-sm disabled:opacity-50"
          >
            {isSubmitting ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5 fill-current" />
            )}
            <span>{isSubmitting ? L('Initializing...', 'Inizializzazione...') : L('Launch Real Scan', 'Avvia Scansione Reale')}</span>
          </button>
        </div>
      </div>

      {/* Target & Scope */}
      <div className="card-industrial p-4 space-y-3">
        <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-2">
          <Globe className="w-3.5 h-3.5 text-theme-accent" />
          <span>{L('1. Target & Tenant Definition', '1. Definizione Target & Tenant')}</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="block text-xs font-medium text-theme-secondary mb-1">
              {L('Client Organization', 'Organizzazione Cliente')}
            </label>
            <select
              value={orgId}
              onChange={(e) => handleOrgChange(e.target.value)}
              className="input-industrial w-full px-2.5 py-1.5 text-xs"
            >
              {organizations.map((org) => (
                <option key={org.id} value={org.id} className="bg-panel text-theme-primary">
                  {org.name} ({org.industry})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-theme-secondary mb-1 flex items-center justify-between">
              <span>{L('Execution Probe', 'Sonda di Esecuzione')}</span>
              {availableProbes.length > 0 && (
                <span className="text-[10px] font-mono text-theme-accent">
                  {availableProbes.filter((p) => p.status === 'online').length} {L('online', 'online')}
                </span>
              )}
            </label>
            <select
              value={selectedAgentId}
              onChange={(e) => setSelectedAgentId(e.target.value)}
              className="input-industrial w-full px-2.5 py-1.5 text-xs"
            >
              <option value="" className="bg-panel text-theme-primary">
                {L('Local MSP Server (Direct)', 'Server MSP Locale (Diretto)')}
              </option>
              {availableProbes.map((agent) => (
                <option key={agent.id} value={agent.id} className="bg-panel text-theme-primary">
                  [{agent.status.toUpperCase()}] {agent.name} ({agent.ip_address || agent.hostname || 'Remote'})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-theme-secondary mb-1">
              {L('Identifying Name', 'Nome Identificativo')}
            </label>
            <input
              type="text"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              placeholder={L('e.g. Q4 External Perimeter Audit', 'es. Audit Perimetro Esterno Q4')}
              className="input-industrial w-full px-2.5 py-1.5 text-xs"
            />
          </div>
        </div>

        {selectedAgentId && (
          <div className="text-[11px] font-mono flex items-center space-x-1.5 text-theme-muted bg-subtle p-2 rounded border border-theme">
            <Radio className="w-3.5 h-3.5 text-theme-accent shrink-0" />
            <span>
              {L('Target scan will be pulled and executed by remote probe:', 'La scansione verrà prelevata ed eseguita dalla sonda remota:')}
            </span>
            <strong className="text-theme-primary">
              {availableProbes.find((a) => a.id === selectedAgentId)?.name}
            </strong>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
          <div>
            <label className="block text-xs font-medium text-theme-secondary mb-1">
              {L('Registered Internal Networks', 'Reti Interne Registrate')} ({selectedOrg?.name || L('Company', 'Azienda')})
            </label>
            <select
              value={orgNetworkOptions.some((o) => o.value === targets.trim()) ? targets.trim() : '__custom__'}
              onChange={(e) => {
                if (e.target.value !== '__custom__') {
                  setTargets(e.target.value);
                }
              }}
              className="input-industrial w-full px-2.5 py-2 text-xs font-mono"
            >
              {orgNetworkOptions.map((opt) => (
                <option key={opt.value} value={opt.value} className="bg-panel text-theme-primary">
                  {opt.label}
                </option>
              ))}
              <option value="__custom__" className="bg-panel text-theme-accent font-semibold">
                {L('Manual entry / Custom target...', 'Inserimento manuale / Target personalizzato...')}
              </option>
            </select>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-medium text-theme-secondary">
                {L('Effective Target Scope (IP, CIDR or URL — Editable)', 'Target Scope Effettivo (IP, CIDR o URL — Modificabile)')}
              </label>
              {!isTargetAlreadyRegistered && targets.trim() && (
                <button
                  type="button"
                  disabled={isSavingScope}
                  onClick={handleSaveTargetToOrgScope}
                  className="text-[11px] text-theme-accent hover:underline font-mono font-semibold"
                  title={L("Save this network to the organization's registered perimeter", "Salva questa rete nel perimetro registrato dell'organizzazione")}
                >
                  {isSavingScope ? L('Saving...', 'Salvataggio...') : `+ ${L('Register in', 'Registra in')} ${selectedOrg?.name}`}
                </button>
              )}
            </div>
            <input
              type="text"
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              placeholder={L('e.g. 192.168.1.0/24, 10.10.10.0/24, https://portal.local', 'es. 192.168.1.0/24, 10.10.10.0/24, https://portale.local')}
              className="input-industrial w-full px-3 py-2 text-xs font-mono tabular-nums"
            />
          </div>
        </div>
      </div>

      {/* Profiles */}
      <div className="card-industrial p-4 space-y-3">
        <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-2">
          <Sparkles className="w-3.5 h-3.5 text-theme-accent" />
          <span>{L('2. Preconfigured Quick Profiles', '2. Profili Rapidi Preconfigurati')}</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
          {profiles.map((prof) => {
            const isSelected = activeProfile === prof.id;
            return (
              <div
                key={prof.id}
                onClick={() => handleApplyProfile(prof.id)}
                className={`p-3 rounded border transition cursor-pointer flex flex-col justify-between ${
                  isSelected
                    ? 'border-theme-accent bg-subtle'
                    : 'border-theme bg-panel hover:bg-subtle'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold text-theme-primary">
                      {prof.name}
                    </span>
                    {isSelected && (
                      <Check className="w-3.5 h-3.5 text-theme-accent shrink-0" />
                    )}
                  </div>
                  <p className="text-[11px] text-theme-secondary leading-snug mb-2">
                    {prof.description}
                  </p>
                </div>

                <div className="flex items-center space-x-1.5 pt-2 border-t border-theme-subtle text-[10px] text-theme-muted font-mono">
                  <span>{prof.ports}</span>
                  <span>•</span>
                  <span>{prof.engines.length} {L('engines', 'motori')}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Active Engines */}
      <div className="card-industrial p-4 space-y-3">
        <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-2">
          <Layers className="w-3.5 h-3.5 text-theme-accent" />
          <span>{L('3. Active Engine Selection', '3. Selezione Motori Operativi')}</span>
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {[
            { id: 'nmap', label: 'Nmap 7.95 + NSE', desc: L('Port discovery, OS & script NSE', 'Port discovery, OS & script NSE') },
            { id: 'nuclei', label: 'Nuclei Engine', desc: L('Template matching CVE & misconfig', 'Template matching CVE & misconfig') },
            { id: 'native_web', label: 'Native Web OWASP', desc: L('Headers, cookies, secrets, CORS', 'Headers, cookies, secrets, CORS') },
            { id: 'native_net', label: 'Native Network/SSL', desc: L('TLS cipher, certificates & banner', 'Cipher TLS, certificati & banner') },
          ].map((item) => (
            <label
              key={item.id}
              onClick={() => toggleEngine(item.id)}
              className={`p-2.5 rounded border flex items-center space-x-2.5 cursor-pointer transition ${
                engines[item.id] ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel opacity-60'
              }`}
            >
              <input
                type="checkbox"
                checked={Boolean(engines[item.id])}
                readOnly
                className="rounded"
              />
              <div className="min-w-0">
                <div className="text-xs font-bold text-theme-primary truncate">{item.label}</div>
                <div className="text-[10px] text-theme-muted truncate">{item.desc}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      {/* ZenMap++ Nmap & NSE Studio */}
      {engines.nmap && (
        <div className="card-industrial p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-theme-subtle pb-2">
            <div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-theme-accent font-semibold">
                ZenMap++ Studio
              </div>
              <h2 className="text-xs font-bold text-theme-primary">
                {L('Advanced Nmap Flags & NSE Script Configuration', 'Configurazione Avanzata Nmap Flags & Script NSE')}
              </h2>
            </div>
            <div className="text-[11px] font-mono text-theme-secondary">
              <span className="font-bold text-theme-accent">{selectedNseScripts.length}</span> {L('scripts selected', 'script selezionati')}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Port selection */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-theme-secondary flex items-center space-x-1.5">
                <Sliders className="w-3 h-3 text-theme-accent" />
                <span>{L('Port Range', 'Intervallo Porte')}</span>
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
                {[
                  { id: 'top-100', label: 'Top 100' },
                  { id: 'top-1000', label: 'Top 1000' },
                  { id: '1-65535', label: '1-65535' },
                  { id: 'custom', label: 'Custom' },
                ].map((p) => (
                  <button
                    type="button"
                    key={p.id}
                    onClick={() => setPortSelection(p.id)}
                    className={`py-1 px-2 text-xs font-medium border rounded transition ${
                      portSelection === p.id
                        ? 'border-theme-accent bg-subtle text-theme-primary'
                        : 'border-theme bg-panel text-theme-muted hover:text-theme-primary'
                    }`}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
              {portSelection === 'custom' && (
                <input
                  type="text"
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  placeholder="21,22,80,443,3389,8000-8100"
                  className="input-industrial w-full px-2.5 py-1 text-xs font-mono mt-1"
                />
              )}
            </div>

            {/* Nmap flags */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-theme-secondary flex items-center space-x-1.5">
                <Terminal className="w-3 h-3 text-theme-accent" />
                <span>{L('Nmap Scan Flags', 'Flag di Scansione Nmap')}</span>
              </label>
              <div className="grid grid-cols-3 sm:grid-cols-6 gap-1.5 text-xs font-mono">
                {['-sV', '-sC', '-O', '-Pn', '-T4', '-sS'].map((flag) => (
                  <button
                    type="button"
                    key={flag}
                    onClick={() => toggleNmapFlag(flag)}
                    className={`py-1 px-1.5 text-center rounded border transition font-bold ${
                      nmapFlags[flag]
                        ? 'border-theme-accent bg-subtle text-theme-primary'
                        : 'border-theme bg-panel text-theme-muted hover:text-theme-primary'
                    }`}
                  >
                    {flag}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* NSE Scripts catalog */}
          <div className="space-y-2 pt-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="text-xs font-semibold text-theme-secondary">
                {L('NSE Script Catalog', 'Catalogo Script NSE')} ({nseScripts.length} {L('available', 'disponibili')})
              </div>
              <div className="flex items-center space-x-1 overflow-x-auto text-[10px] font-mono">
                {['all', 'vuln', 'safe', 'discovery', 'auth', 'ssl', 'http'].map((cat) => (
                  <button
                    type="button"
                    key={cat}
                    onClick={() => setNseCategoryFilter(cat)}
                    className={`px-1.5 py-0.5 rounded uppercase font-semibold transition ${
                      nseCategoryFilter === cat
                        ? 'bg-subtle text-theme-primary border border-theme-accent'
                        : 'text-theme-muted hover:text-theme-primary'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-theme-muted absolute left-2.5 top-2" />
              <input
                type="text"
                value={nseSearch}
                onChange={(e) => setNseSearch(e.target.value)}
                placeholder={L('Filter scripts by name or category...', 'Filtra script per nome o categoria...')}
                className="input-industrial w-full pl-8 pr-2.5 py-1.5 text-xs"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 max-h-52 overflow-y-auto pr-1">
              {filteredNSEScripts.map((script) => {
                const isSelected = selectedNseScripts.includes(script.name);
                return (
                  <div
                    key={script.name}
                    onClick={() => toggleNseScript(script.name)}
                    className={`p-2 rounded border transition cursor-pointer flex flex-col justify-between ${
                      isSelected
                        ? 'border-theme-accent bg-subtle'
                        : 'border-theme bg-panel hover:bg-subtle'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between text-xs font-mono font-bold text-theme-primary">
                        <span>{script.name}</span>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          readOnly
                          className="rounded"
                        />
                      </div>
                      <p className="text-[10px] text-theme-secondary line-clamp-2 mt-0.5 leading-snug">
                        {script.description}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Live Command Preview */}
          <div className="p-2.5 rounded bg-subtle border border-theme space-y-1">
            <div className="text-[10px] font-mono text-theme-muted flex items-center justify-between">
              <span>{L('EFFECTIVE NMAP COMMAND ON SERVER:', 'COMANDO NMAP EFFETTIVO SUL SERVER:')}</span>
              <span>{L('synchronized in real time', 'sincronizzato in tempo reale')}</span>
            </div>
            <pre className="text-xs font-mono text-theme-primary overflow-x-auto select-all">
              {liveNmapCommand}
            </pre>
          </div>
        </div>
      )}

      {/* Web & Nuclei */}
      {(engines.native_web || engines.nuclei) && (
        <div className="card-industrial p-4 space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-2">
            <Lock className="w-3.5 h-3.5 text-theme-accent" />
            <span>{L('4. Web & Nuclei Audit Parameters', '4. Parametri Audit Web & Nuclei')}</span>
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {engines.native_web && (
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-theme-secondary block">
                  {L('Native Web OWASP Checks', 'Controlli Native Web OWASP')}
                </label>
                <div className="space-y-1">
                  {[
                    { id: 'headers', label: L('Security Headers (CSP, HSTS, X-Frame, Nosniff)', 'Security Headers (CSP, HSTS, X-Frame, Nosniff)') },
                    { id: 'cors', label: L('CORS Misconfiguration & Origin Reflection', 'CORS Misconfiguration & Origin Reflection') },
                    { id: 'cookies', label: L('Cookie Security Flags (HttpOnly, Secure)', 'Cookie Security Flags (HttpOnly, Secure)') },
                    { id: 'sensitive_files', label: L('Sensitive Files (/.env, /.git, /swagger.json)', 'File Sensibili (/.env, /.git, /swagger.json)') },
                    { id: 'sqli_probe', label: L('SQL Injection Syntax Probe', 'SQL Injection Syntax Probe') },
                    { id: 'ssl', label: L('TLS 1.0/1.1 Cryptographic Audit & Cert Expiry', 'Audit Crittografico TLS 1.0/1.1 & Scadenza Cert') },
                  ].map((check) => (
                    <label
                      key={check.id}
                      onClick={() => toggleWebCheck(check.id)}
                      className="flex items-center space-x-2 text-xs text-theme-secondary hover:text-theme-primary cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={webChecks.includes(check.id)}
                        readOnly
                        className="rounded"
                      />
                      <span>{check.label}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {engines.nuclei && (
              <div className="space-y-2">
                <label className="text-xs font-semibold text-theme-secondary block">
                  {L('Nuclei Template Severity', 'Severità Template Nuclei')}
                </label>
                <div className="flex flex-wrap gap-1.5">
                  {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
                    const isSel = nucleiSeverity.includes(sev);
                    return (
                      <button
                        type="button"
                        key={sev}
                        onClick={() => toggleNucleiSeverity(sev)}
                        className={`px-2 py-0.5 rounded text-xs font-mono uppercase font-semibold border transition ${
                          isSel
                            ? 'border-theme-accent bg-subtle text-theme-primary'
                            : 'border-theme bg-panel text-theme-muted hover:text-theme-primary'
                        }`}
                      >
                        {sev}
                      </button>
                    );
                  })}
                </div>

                <div className="p-2 rounded bg-subtle border border-theme space-y-0.5 mt-2">
                  <div className="text-[10px] font-mono text-theme-muted">{L('NUCLEI COMMAND:', 'COMANDO NUCLEI:')}</div>
                  <pre className="text-xs font-mono text-theme-primary overflow-x-auto">
                    {liveNucleiCommand}
                  </pre>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
