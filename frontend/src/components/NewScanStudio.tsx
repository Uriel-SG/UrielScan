import React, { useState, useMemo, useEffect, useRef } from 'react';
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
  Radio,
  AlertTriangle,
  ShieldCheck,
  RefreshCw,
  Upload,
  Trash2,
} from 'lucide-react';
import { Organization, NSEScript, Scan, RemoteAgent, NatCheckResult, WordlistItem } from '../types';
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
    description: L('Complete offensive/defensive assessment: Nmap NSE, Nuclei OWASP templates, OWASP ZAP, and Native Engine across network and web.', 'Valutazione completa offensiva/difensiva: Nmap NSE, Nuclei, OWASP ZAP e Native Engine su rete e web.'),
    engines: ['nmap', 'native_web', 'native_net', 'nuclei', 'zap'],
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
    description: L('Audit focused on HTTP/HTTPS applications, security headers, sensitive files, OWASP ZAP, and Nuclei templates.', 'Audit incentrato su applicazioni HTTP/HTTPS, security headers, file sensibili, OWASP ZAP e Nuclei templates.'),
    engines: ['native_web', 'nuclei', 'zap'],
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
  const [isManualTargetMode, setIsManualTargetMode] = useState<boolean>(false);
  const targetInputRef = useRef<HTMLInputElement>(null);
  const [isSavingScope, setIsSavingScope] = useState<boolean>(false);
  const [natCheck, setNatCheck] = useState<NatCheckResult | null>(null);
  const [routingMode, setRoutingMode] = useState<'direct' | 'tor' | 'custom_proxy'>('direct');
  const [customProxyUrl, setCustomProxyUrl] = useState<string>('');
  const [isTestingRouting, setIsTestingRouting] = useState<boolean>(false);
  const [routingStatus, setRoutingStatus] = useState<{ ok: boolean; ip?: string; is_tor?: boolean; message?: string } | null>(null);

  // Strictly opt-in Web Recon & Discovery Modules (both OFF by default)
  const [enableSubdomainEnum, setEnableSubdomainEnum] = useState<boolean>(false);
  const [subdomainWordlist, setSubdomainWordlist] = useState<string>('n0kovo');
  const [subdomainChecks, setSubdomainChecks] = useState<string[]>(['httpx', 'takeover', 'dns_zone']);
  const [cascadeSubdomains, setCascadeSubdomains] = useState<boolean>(true);
  const [cascadeLimit, setCascadeLimit] = useState<string>('20');

  const [enableDirEnum, setEnableDirEnum] = useState<boolean>(false);
  const [dirWordlist, setDirWordlist] = useState<string>('dirbuster_medium');
  const [dirExtensions, setDirExtensions] = useState<string>('');
  const [dirRecursion, setDirRecursion] = useState<boolean>(false);
  const [dirMaxDepth, setDirMaxDepth] = useState<string>('2');
  const [dirRateLimit, setDirRateLimit] = useState<string>('100');
  const [dirTimeLimit, setDirTimeLimit] = useState<string>('180');
  const [enableTechFingerprint, setEnableTechFingerprint] = useState<boolean>(true);
  const [enableCveIntel, setEnableCveIntel] = useState<boolean>(true);

  const clampIntStr = (raw: string, min: number, max: number, fallback: number): number => {
    const parsed = parseInt(raw, 10);
    if (Number.isNaN(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
  };

  const [wordlistsData, setWordlistsData] = useState<{ dns: WordlistItem[]; web: WordlistItem[] }>({ dns: [], web: [] });
  const [uploadingCategory, setUploadingCategory] = useState<'dns' | 'web' | null>(null);

  useEffect(() => {
    api.getWordlists().then((data) => {
      setWordlistsData(data);
    }).catch(() => {});
  }, []);

  const handleUploadCustomWordlist = async (category: 'dns' | 'web', file: File | null) => {
    if (!file) return;
    setUploadingCategory(category);
    try {
      const res = await api.uploadWordlist(category, file);
      const updated = await api.getWordlists();
      setWordlistsData(updated);
      if (category === 'dns') setSubdomainWordlist(res.wordlist.id);
      else setDirWordlist(res.wordlist.id);
      showToast(L(`Custom wordlist uploaded: ${res.wordlist.filename}`, `Wordlist caricata: ${res.wordlist.filename}`), 'success');
    } catch (err: any) {
      showToast(err?.message || L('Wordlist upload failed.', 'Caricamento wordlist fallito.'), 'error');
    } finally {
      setUploadingCategory(null);
    }
  };

  const handleDeleteCustomWordlist = async (category: 'dns' | 'web', filename: string) => {
    try {
      const ok = await api.deleteWordlist(category, filename);
      if (ok) {
        const updated = await api.getWordlists();
        setWordlistsData(updated);
        if (category === 'dns' && subdomainWordlist === `custom:${filename}`) setSubdomainWordlist('n0kovo');
        if (category === 'web' && dirWordlist === `custom:${filename}`) setDirWordlist('dirbuster_medium');
        showToast(L('Custom wordlist deleted.', 'Wordlist personalizzata rimossa.'), 'info');
      }
    } catch (err: any) {
      showToast(err?.message || L('Delete failed.', 'Eliminazione fallita.'), 'error');
    }
  };

  const toggleSubdomainCheck = (chk: string) => {
    setSubdomainChecks((prev) => (prev.includes(chk) ? prev.filter((c) => c !== chk) : [...prev, chk]));
  };

  useEffect(() => {
    const trimmed = targets.trim();
    if (!trimmed || trimmed.length < 3 || selectedAgentId || routingMode !== 'direct') {
      setNatCheck(null);
      return;
    }
    let active = true;
    const timer = setTimeout(() => {
      api.checkNatLoopback(trimmed).then((res) => {
        if (active) setNatCheck(res);
      }).catch(() => {
        if (active) setNatCheck(null);
      });
    }, 500);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [targets, selectedAgentId, routingMode]);

  const handleVerifyRouting = async (rotate = false) => {
    setIsTestingRouting(true);
    setRoutingStatus(null);
    try {
      if (routingMode === 'tor') {
        const res = rotate ? await api.newTorIdentity() : await api.startTor();
        setRoutingStatus({
          ok: Boolean(res.ok),
          ip: res.ip,
          is_tor: res.is_tor,
          message: res.ip
            ? `${L('Visible Exit IP', 'Exit IP visibile')}: ${res.ip}${res.is_tor ? ' (Tor Exit Verified)' : ''}`
            : L('Tor daemon started.', 'Demone Tor avviato.'),
        });
        showToast(
          res.ip ? `Tor Exit IP: ${res.ip}` : L('Tor circuit active.', 'Circuito Tor attivo.'),
          'success'
        );
      } else if (routingMode === 'custom_proxy') {
        if (!customProxyUrl.trim()) {
          showToast(L('Enter a SOCKS5 or HTTP proxy URL first.', 'Inserisci prima un URL proxy SOCKS5 o HTTP.'), 'warning');
          return;
        }
        const res = await api.testProxy(customProxyUrl.trim());
        setRoutingStatus({
          ok: Boolean(res.ok),
          ip: res.ip,
          is_tor: res.is_tor,
          message: res.ok
            ? `${L('Visible Exit IP', 'Exit IP visibile')}: ${res.ip || 'OK'}`
            : (res.error || L('Proxy test failed', 'Test proxy fallito')),
        });
        showToast(
          res.ok ? `${L('Proxy connected — Exit IP', 'Proxy connesso — Exit IP')}: ${res.ip}` : (res.error || L('Proxy failed', 'Proxy non raggiungibile')),
          res.ok ? 'success' : 'error'
        );
      }
    } catch (err: any) {
      const msg = err?.message || L('Routing check failed.', 'Verifica instradamento fallita.');
      setRoutingStatus({ ok: false, message: msg });
      showToast(msg, 'error');
    } finally {
      setIsTestingRouting(false);
    }
  };

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
    setIsManualTargetMode(false);
    const nextOrg = organizations.find((o) => o.id === newOrgId);
    if (nextOrg?.target_scope) {
      setTargets(nextOrg.target_scope);
    }
  };

  const selectedNetworkValue = useMemo(() => {
    if (isManualTargetMode) return '__custom__';
    return orgNetworkOptions.some((o) => o.value === targets.trim()) ? targets.trim() : '__custom__';
  }, [isManualTargetMode, orgNetworkOptions, targets]);

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
    zap: true,
    native_web: true,
    native_net: true,
  });
  const [zapMode, setZapMode] = useState<'baseline' | 'full'>('baseline');

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
      zap: prof.engines.includes('zap'),
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

    if (!selectedAgentId && routingMode === 'custom_proxy' && !customProxyUrl.trim()) {
      showToast(
        L('Please enter a valid SOCKS5 or HTTP proxy URL, or switch routing back to Direct.', 'Inserisci un URL proxy SOCKS5 o HTTP valido, oppure imposta l\'instradamento su Diretto.'),
        'warning',
        L('Missing Proxy URL', 'URL Proxy Mancante')
      );
      return;
    }

    setIsSubmitting(true);
    const activeProfileObj = profiles.find((p) => p.id === activeProfile);
    const effectiveOnion = !selectedAgentId && routingMode === 'tor';
    const effectiveProxy = !selectedAgentId && routingMode === 'custom_proxy' ? customProxyUrl.trim() : undefined;

    const scanPayload = {
      org_id: orgId || (organizations[0]?.id || '1'),
      agent_id: selectedAgentId || null,
      name: scanName.trim() || `${L('Scan', 'Scansione')} ${new Date().toLocaleTimeString(locale)}`,
      targets: targets.trim(),
      scan_type: activeProfileObj?.name || 'Purple Assessment',
      engines: activeEnginesList,
      onion_mode: effectiveOnion,
      proxy_url: effectiveProxy,
      enable_subdomain_enum: enableSubdomainEnum,
      subdomain_wordlist: enableSubdomainEnum ? subdomainWordlist : undefined,
      subdomain_checks: enableSubdomainEnum ? subdomainChecks : undefined,
      cascade_subdomains: enableSubdomainEnum ? cascadeSubdomains : undefined,
      cascade_limit: enableSubdomainEnum ? clampIntStr(cascadeLimit, 1, 50, 20) : undefined,
      enable_dir_enum: enableDirEnum,
      dir_wordlist: enableDirEnum ? dirWordlist : undefined,
      dir_extensions: enableDirEnum ? dirExtensions.trim() : undefined,
      dir_recursion: enableDirEnum ? dirRecursion : undefined,
      dir_max_depth: enableDirEnum ? clampIntStr(dirMaxDepth, 1, 10, 2) : undefined,
      dir_rate_limit: enableDirEnum ? clampIntStr(dirRateLimit, 10, 500, 100) : undefined,
      dir_time_limit: enableDirEnum ? clampIntStr(dirTimeLimit, 30, 600, 180) : undefined,
      enable_tech_fingerprint: enableTechFingerprint,
      enable_cve_intel: enableTechFingerprint ? enableCveIntel : false,
      config: {
        ports: portSelection === 'custom' ? customPorts : portSelection,
        nmap_flags: activeFlagsString,
        nse_scripts: selectedNseScripts,
        nuclei_tags: nucleiTags,
        nuclei_severities: nucleiSeverity,
        web_checks: webChecks,
        zap_mode: zapMode,
        onion_mode: effectiveOnion,
        ...(effectiveProxy ? { proxy_url: effectiveProxy } : {}),
        enable_subdomain_enum: enableSubdomainEnum,
        enable_dir_enum: enableDirEnum,
      },
      nmap_args: liveNmapCommand,
      nse_scripts: selectedNseScripts,
      nuclei_tags: nucleiTags,
      nuclei_severity: nucleiSeverity,
      web_checks: webChecks,
      zap_mode: zapMode,
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
    <div className="h-full flex flex-col">
      {/* Fixed Header bar (non-scrolling) */}
      <div className="shrink-0 px-4 lg:px-6 pt-4 lg:pt-6 pb-4 bg-canvas">
        <div className="max-w-7xl mx-auto">
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
                <span>{isSubmitting ? L('Initializing...', 'Inizializzazione...') : L('Launch Scan', 'Avvia Scansione')}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Scrollable Configuration Sections */}
      <div className="flex-1 min-h-0 overflow-y-auto px-4 lg:px-6 pb-16">
        <div className="max-w-7xl mx-auto space-y-4">
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
              value={selectedNetworkValue}
              onChange={(e) => {
                if (e.target.value === '__custom__') {
                  setIsManualTargetMode(true);
                  setTargets('');
                  setTimeout(() => targetInputRef.current?.focus(), 0);
                } else {
                  setIsManualTargetMode(false);
                  setTargets(e.target.value);
                }
              }}
              className={`input-industrial w-full px-2.5 py-2 text-xs font-mono ${
                selectedNetworkValue === '__custom__' ? 'text-theme-accent font-semibold' : ''
              }`}
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
              ref={targetInputRef}
              type="text"
              value={targets}
              onChange={(e) => {
                const val = e.target.value;
                setTargets(val);
                if (isManualTargetMode && !val.trim()) {
                  setIsManualTargetMode(true);
                }
              }}
              placeholder={L('e.g. 192.168.1.0/24, 10.10.10.0/24, https://portal.local', 'es. 192.168.1.0/24, 10.10.10.0/24, https://portale.local')}
              className="input-industrial w-full px-3 py-2 text-xs font-mono tabular-nums"
            />
          </div>
        </div>

        {natCheck?.has_nat_loopback && !selectedAgentId && (
          <div className="p-3 rounded border border-amber-500/60 bg-amber-950/20 flex items-start space-x-2.5 text-xs">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1 text-theme-secondary">
              <div className="font-bold text-amber-300">
                {L(
                  `NAT Loopback / Hairpinning Detected (${natCheck.egress_public_ip})`,
                  `NAT Loopback / Hairpinning Rilevato (${natCheck.egress_public_ip})`
                )}
              </div>
              <p className="leading-snug text-[11px]">
                {L(
                  'Target resolves to your own public WAN egress IP. Scanning from inside the LAN normally hits internal router management ports causing false positives. UrielScan NAT Guard will automatically verify true external WAN exposure via Shodan InternetDB and suppress router LAN hairpin findings. For active external testing, run the scan via an external Remote Probe.',
                  'Il target corrisponde al tuo IP pubblico WAN di uscita. Scansionarlo dall\'interno della LAN colpisce il router locale causando falsi positivi. UrielScan NAT Guard verificherà automaticamente la reale esposizione WAN esterna via Shodan InternetDB sopprimendo i falsi positivi del router. Per un test attivo dall\'esterno usa una Sonda Remota esterna.'
                )}
              </p>
            </div>
          </div>
        )}

        {/* Outbound Network Routing (Tor Onion / SOCKS5 Proxy) */}
        <div className="pt-2 border-t border-theme-subtle space-y-2.5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-3.5 h-3.5 text-purple-400 shrink-0" />
              <span className="text-[11px] font-bold uppercase tracking-wider text-theme-secondary">
                {L('Outbound Network Routing', 'Instradamento Rete in Uscita')}
              </span>
            </div>
            {selectedAgentId && (
              <span className="text-[11px] font-mono text-theme-muted">
                {L('Disabled when delegating to a Remote Probe', 'Disabilitato quando si delega a una Sonda Remota')}
              </span>
            )}
          </div>

          <div className={`grid grid-cols-1 sm:grid-cols-3 gap-2 ${selectedAgentId ? 'opacity-50 pointer-events-none' : ''}`}>
            <button
              type="button"
              onClick={() => {
                setRoutingMode('direct');
                setRoutingStatus(null);
              }}
              className={`px-3 py-2 rounded border text-left transition ${
                routingMode === 'direct'
                  ? 'border-theme-accent bg-subtle text-theme-primary'
                  : 'border-theme bg-panel text-theme-secondary hover:bg-subtle'
              }`}
            >
              <div className="text-xs font-bold flex items-center justify-between">
                <span>{L('Direct (Local IP)', 'Diretto (IP Locale)')}</span>
                {routingMode === 'direct' && <Check className="w-3.5 h-3.5 text-theme-accent" />}
              </div>
              <div className="text-[10px] text-theme-muted mt-0.5">
                {L('Standard server egress & LAN subnet scanning', 'Uscita diretta server e scansioni subnet LAN')}
              </div>
            </button>

            <button
              type="button"
              onClick={() => {
                setRoutingMode('tor');
                setRoutingStatus(null);
              }}
              className={`px-3 py-2 rounded border text-left transition ${
                routingMode === 'tor'
                  ? 'border-purple-500 bg-purple-950/30 text-purple-100'
                  : 'border-theme bg-panel text-theme-secondary hover:bg-subtle'
              }`}
            >
              <div className="text-xs font-bold flex items-center justify-between">
                <span>Onion Routing (Tor)</span>
                {routingMode === 'tor' && <Check className="w-3.5 h-3.5 text-purple-400" />}
              </div>
              <div className="text-[10px] text-theme-muted mt-0.5">
                {L('Anonymous Tor SOCKS5h circuit + .onion support', 'Circuito Tor SOCKS5h anonimo + supporto .onion')}
              </div>
            </button>

            <button
              type="button"
              onClick={() => {
                setRoutingMode('custom_proxy');
                setRoutingStatus(null);
              }}
              className={`px-3 py-2 rounded border text-left transition ${
                routingMode === 'custom_proxy'
                  ? 'border-sky-500 bg-sky-950/30 text-sky-100'
                  : 'border-theme bg-panel text-theme-secondary hover:bg-subtle'
              }`}
            >
              <div className="text-xs font-bold flex items-center justify-between">
                <span>{L('Custom SOCKS5 / HTTP Proxy', 'Proxy SOCKS5 / HTTP Custom')}</span>
                {routingMode === 'custom_proxy' && <Check className="w-3.5 h-3.5 text-sky-400" />}
              </div>
              <div className="text-[10px] text-theme-muted mt-0.5">
                {L('Dedicated VPS tunnel, VPN gateway or HTTP proxy', 'Tunnel VPS dedicato, VPN gateway o proxy HTTP')}
              </div>
            </button>
          </div>

          {!selectedAgentId && routingMode === 'tor' && (
            <div className="p-2.5 rounded border border-purple-500/40 bg-purple-950/20 space-y-2 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-[11px] text-purple-200/90 leading-snug">
                  {L(
                    'All Native TCP/SSL/Web, Nuclei and OWASP ZAP probes will tunnel through embedded Tor SOCKS5h. Direct Nmap raw SYN/UDP is skipped to avoid IP/DNS leaks. Note: public Tor Exit Nodes may trigger Cloudflare/WAF challenges.',
                    'Tutte le sonde Native TCP/SSL/Web, Nuclei e OWASP ZAP passeranno dal tunnel Tor SOCKS5h integrato. Nmap raw viene sostituito da Native Net via SOCKS5 per impedire IP/DNS leak. Nota: gli Exit Node Tor pubblici possono attivare blocchi Cloudflare/WAF.'
                  )}
                </p>
                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    type="button"
                    disabled={isTestingRouting}
                    onClick={() => handleVerifyRouting(false)}
                    className="px-2.5 py-1 rounded border border-purple-500/60 bg-purple-900/40 hover:bg-purple-800/50 text-[11px] font-semibold text-purple-100 flex items-center space-x-1 disabled:opacity-50"
                  >
                    {isTestingRouting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Globe className="w-3 h-3" />}
                    <span>{L('Check Tor IP', 'Verifica IP Tor')}</span>
                  </button>
                  <button
                    type="button"
                    disabled={isTestingRouting}
                    onClick={() => handleVerifyRouting(true)}
                    className="px-2.5 py-1 rounded border border-theme bg-panel hover:bg-subtle text-[11px] font-semibold text-theme-primary flex items-center space-x-1 disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3 h-3 ${isTestingRouting ? 'animate-spin' : ''}`} />
                    <span>{L('New Circuit', 'Nuovo Circuito')}</span>
                  </button>
                </div>
              </div>
              {routingStatus && (
                <div className={`text-[11px] font-mono ${routingStatus.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                  {routingStatus.message}
                </div>
              )}
            </div>
          )}

          {!selectedAgentId && routingMode === 'custom_proxy' && (
            <div className="p-2.5 rounded border border-sky-500/40 bg-sky-950/20 space-y-2 text-xs">
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="text"
                  value={customProxyUrl}
                  onChange={(e) => setCustomProxyUrl(e.target.value)}
                  placeholder="socks5h://127.0.0.1:1080 or http://user:pass@proxy.host:8080"
                  className="input-industrial flex-1 px-3 py-1.5 text-xs font-mono"
                />
                <button
                  type="button"
                  disabled={isTestingRouting || !customProxyUrl.trim()}
                  onClick={() => handleVerifyRouting(false)}
                  className="px-3 py-1.5 rounded border border-sky-500/60 bg-sky-900/40 hover:bg-sky-800/50 text-xs font-semibold text-sky-100 flex items-center justify-center space-x-1.5 shrink-0 disabled:opacity-50"
                >
                  {isTestingRouting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Globe className="w-3.5 h-3.5" />}
                  <span>{L('Verify Exit IP', 'Verifica IP Proxy')}</span>
                </button>
              </div>
              {routingStatus && (
                <div className={`text-[11px] font-mono ${routingStatus.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                  {routingStatus.message}
                </div>
              )}
            </div>
          )}
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

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
          {[
            { id: 'nmap', label: 'Nmap 7.95 + NSE', desc: L('Port discovery, OS & script NSE', 'Port discovery, OS & script NSE') },
            { id: 'nuclei', label: 'Nuclei Engine', desc: L('Template matching CVE & misconfig', 'Template matching CVE & misconfig') },
            { id: 'zap', label: 'OWASP ZAP', desc: L('Integrated web DAST (deduped w/ Nuclei)', 'Web DAST integrato (no duplicati con Nuclei)') },
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

      {/* Web, ZAP & Nuclei */}
      {(engines.native_web || engines.nuclei || engines.zap) && (
        <div className="card-industrial p-4 space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-2">
            <Lock className="w-3.5 h-3.5 text-theme-accent" />
            <span>{L('4. Web, OWASP ZAP & Nuclei Parameters', '4. Parametri Audit Web, OWASP ZAP & Nuclei')}</span>
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

            {engines.zap && (
              <div className="space-y-2 md:col-span-2 pt-2 border-t border-theme-subtle">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-xs font-semibold text-theme-secondary">
                      {L('OWASP ZAP Scan Mode (Cross-Engine Deduplicated)', 'Modalità Scansione OWASP ZAP (Con Deduplicazione Integrata)')}
                    </div>
                    <div className="text-[11px] text-theme-muted">
                      {L(
                        'Duplicate alerts already found by Nuclei, Nmap NSE, or Native Web are automatically merged.',
                        'Eventuali vulnerabilità già rilevate da Nuclei, Nmap NSE o Native Web vengono automaticamente unificate senza doppioni.'
                      )}
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      type="button"
                      onClick={() => setZapMode('baseline')}
                      className={`px-2.5 py-1 rounded text-xs font-mono border ${
                        zapMode === 'baseline' ? 'border-theme-accent bg-subtle text-theme-primary font-semibold' : 'border-theme bg-panel text-theme-muted'
                      }`}
                    >
                      {L('Spider Baseline (Safe)', 'Spider Baseline (Sicuro)')}
                    </button>
                    <button
                      type="button"
                      onClick={() => setZapMode('full')}
                      className={`px-2.5 py-1 rounded text-xs font-mono border ${
                        zapMode === 'full' ? 'border-theme-accent bg-subtle text-theme-primary font-semibold' : 'border-theme bg-panel text-theme-muted'
                      }`}
                    >
                      {L('Full Active Scan', 'Active Scan Completo')}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5. Optional Web Recon & Discovery Modules (Strictly Opt-In) */}
      <div className="card-industrial p-4 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-theme-subtle pb-2">
          <div>
            <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-2">
              <Search className="w-3.5 h-3.5 text-theme-accent" />
              <span>{L('5. Optional Web Recon & Discovery Modules (Opt-In)', '5. Moduli Facoltativi Web Recon & Discovery')}</span>
            </h2>
            <p className="text-[11px] text-theme-muted mt-0.5">
              {L(
                'Disabled by default. Enable explicitly to discover subdomains (SubRaptor + httpx + Subzy + DNS Zone) or enumerate directories (Feroxbuster).',
                'Disattivati di default. Abilita solo se vuoi includere scoperta sottodomini (SubRaptor + httpx + Subzy + DNS Zone) o enumerazione directory (Feroxbuster).'
              )}
            </p>
          </div>
          {selectedAgentId && (
            <span className="text-[11px] font-mono text-amber-400">
              {L('Local server execution only (not delegated to Remote Probes)', 'Disponibile solo in scansione locale (non su Sonda Remota)')}
            </span>
          )}
        </div>

        <div className={`grid grid-cols-1 lg:grid-cols-2 gap-4 ${selectedAgentId ? 'opacity-50 pointer-events-none' : ''}`}>
          {/* Module A: Subdomain & DNS / Takeover Intelligence */}
          <div className={`p-3 rounded border space-y-3 transition ${enableSubdomainEnum ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'}`}>
            <label className="flex items-start justify-between gap-3 cursor-pointer">
              <div>
                <div className="text-xs font-bold text-theme-primary">
                  {L('SubRaptor Subdomain, Live httpx, Takeover & DNS Zone', 'SubRaptor Sottodomini, Live httpx, Takeover & Zona DNS')}
                </div>
                <div className="text-[11px] text-theme-secondary mt-0.5">
                  {L('Passive Subfinder + Assetfinder + crt.sh aggregation, AXFR/SPF/DMARC audit, httpx probe & Subzy takeover verification.', 'Aggregazione passiva Subfinder + Assetfinder + crt.sh, audit AXFR/SPF/DMARC, probe httpx e verifica Subzy Takeover.')}
                </div>
              </div>
              <input
                type="checkbox"
                checked={enableSubdomainEnum}
                onChange={(e) => setEnableSubdomainEnum(e.target.checked)}
                className="mt-1 h-4 w-4 accent-theme-accent shrink-0"
              />
            </label>

            {enableSubdomainEnum && (
              <div className="pt-2 border-t border-theme-subtle space-y-3 text-xs">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-theme-secondary">
                      {L('Subdomain Discovery Wordlist (DNS Bruteforce)', 'Wordlist Sottodomini (DNS Bruteforce)')}
                    </span>
                    <label className="inline-flex items-center space-x-1 text-[11px] text-theme-accent hover:underline cursor-pointer font-semibold">
                      {uploadingCategory === 'dns' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Upload className="w-3 h-3" />}
                      <span>{L('Upload Custom .txt', 'Carica .txt Custom')}</span>
                      <input
                        type="file"
                        accept=".txt"
                        className="hidden"
                        onChange={(e) => {
                          handleUploadCustomWordlist('dns', e.target.files?.[0] || null);
                          e.target.value = '';
                        }}
                      />
                    </label>
                  </div>
                  <select
                    value={subdomainWordlist}
                    onChange={(e) => setSubdomainWordlist(e.target.value)}
                    className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                  >
                    {(wordlistsData.dns.length > 0
                      ? wordlistsData.dns
                      : [
                          { id: 'n0kovo', name: 'n0kovo_subdomains.txt (SecLists)', source: 'seclists' as const },
                          { id: 'top1m_110k', name: 'subdomains-top1million-110000.txt (SecLists)', source: 'seclists' as const },
                          { id: 'italian', name: 'italian-subdomains.txt (SecLists)', source: 'seclists' as const },
                        ]
                    ).map((w) => (
                      <option key={w.id} value={w.id} className="bg-panel text-theme-primary">
                        {w.name}
                      </option>
                    ))}
                    <option value="passive_only" className="bg-panel text-theme-primary">
                      {L('Passive Only (Subfinder + crt.sh + Assetfinder — No Bruteforce)', 'Solo Passivo (Subfinder + crt.sh + Assetfinder — Nessun Bruteforce)')}
                    </option>
                  </select>

                  {wordlistsData.dns.some((w) => w.source === 'custom') && (
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {wordlistsData.dns
                        .filter((w) => w.source === 'custom')
                        .map((cw) => (
                          <span key={cw.id} className="inline-flex items-center space-x-1 px-2 py-0.5 rounded border border-theme bg-panel text-[10px] font-mono text-theme-secondary">
                            <span>{cw.filename}</span>
                            <button
                              type="button"
                              onClick={() => handleDeleteCustomWordlist('dns', cw.filename)}
                              className="text-red-400 hover:text-red-300"
                              title={L('Delete custom wordlist', 'Elimina wordlist')}
                            >
                              <Trash2 className="w-3 h-3" />
                            </button>
                          </span>
                        ))}
                    </div>
                  )}
                </div>

                <div className="space-y-1.5">
                  <span className="font-semibold text-theme-secondary block">
                    {L('Verification & Security Checks', 'Controlli di Verifica & Sicurezza')}
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-1.5">
                    {[
                      { id: 'httpx', label: L('Live httpx Probe', 'Live httpx Probe') },
                      { id: 'takeover', label: L('Subzy Takeover', 'Subzy Takeover') },
                      { id: 'dns_zone', label: L('DNS Zone / AXFR', 'DNS Zone / AXFR') },
                    ].map((chk) => (
                      <label
                        key={chk.id}
                        className="flex items-center space-x-1.5 p-1.5 rounded border border-theme bg-panel cursor-pointer text-[11px] text-theme-secondary hover:text-theme-primary"
                      >
                        <input
                          type="checkbox"
                          checked={subdomainChecks.includes(chk.id)}
                          onChange={() => toggleSubdomainCheck(chk.id)}
                          className="rounded"
                        />
                        <span>{chk.label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                  <label className="flex items-center space-x-2 text-[11px] text-theme-secondary cursor-pointer">
                    <input
                      type="checkbox"
                      checked={cascadeSubdomains}
                      onChange={(e) => setCascadeSubdomains(e.target.checked)}
                      className="rounded"
                    />
                    <span>{L('Pass live subdomains to Web/Nuclei/ZAP/Feroxbuster', 'Passa sottodomini vivi ai motori Web/Nuclei/ZAP/Feroxbuster')}</span>
                  </label>
                  {cascadeSubdomains && (
                    <div
                      className="flex items-center space-x-1.5 text-[11px] font-mono"
                      title={L(
                        'Maximum number of live subdomains forwarded to Web, Nuclei, ZAP and Feroxbuster',
                        'Numero massimo di sottodomini vivi passati a Web, Nuclei, ZAP e Feroxbuster'
                      )}
                    >
                      <span className="text-theme-muted">{L('Max live hosts:', 'Max host vivi:')}</span>
                      <input
                        type="text"
                        inputMode="numeric"
                        value={cascadeLimit}
                        onChange={(e) => {
                          if (/^\d*$/.test(e.target.value)) setCascadeLimit(e.target.value);
                        }}
                        onBlur={() => setCascadeLimit(String(clampIntStr(cascadeLimit, 1, 50, 20)))}
                        className="input-industrial w-14 px-2 py-0.5 text-xs text-center"
                      />
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Module B: Feroxbuster Directory Enumeration */}
          <div className={`p-3 rounded border space-y-3 transition ${enableDirEnum ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'}`}>
            <label className="flex items-start justify-between gap-3 cursor-pointer">
              <div>
                <div className="text-xs font-bold text-theme-primary">
                  {L('Feroxbuster Directory & Content Enumeration', 'Feroxbuster Enumerazione Directory & Contenuti')}
                </div>
                <div className="text-[11px] text-theme-secondary mt-0.5">
                  {L('Fast wildcard-filtered content discovery with SecLists or custom wordlists, sensitive file flagging & proxy/Tor support.', 'Scoperta rapida percorsi con auto-filtro wildcard, wordlist SecLists o custom, alert file critici e supporto proxy/Tor.')}
                </div>
              </div>
              <input
                type="checkbox"
                checked={enableDirEnum}
                onChange={(e) => setEnableDirEnum(e.target.checked)}
                className="mt-1 h-4 w-4 accent-theme-accent shrink-0"
              />
            </label>

            {enableDirEnum && (
              <div className="pt-2 border-t border-theme-subtle space-y-3 text-xs">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-theme-secondary">
                      {L('Directory Enumeration Wordlist', 'Wordlist Enumerazione Directory')}
                    </span>
                    <label className="inline-flex items-center space-x-1 text-[11px] text-theme-accent hover:underline cursor-pointer font-semibold">
                      {uploadingCategory === 'web' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Upload className="w-3 h-3" />}
                      <span>{L('Upload Custom .txt', 'Carica .txt Custom')}</span>
                      <input
                        type="file"
                        accept=".txt"
                        className="hidden"
                        onChange={(e) => {
                          handleUploadCustomWordlist('web', e.target.files?.[0] || null);
                          e.target.value = '';
                        }}
                      />
                    </label>
                  </div>
                  <select
                    value={dirWordlist}
                    onChange={(e) => setDirWordlist(e.target.value)}
                    className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                  >
                    {(wordlistsData.web.length > 0
                      ? wordlistsData.web
                      : [
                          { id: 'dirbuster_medium', name: 'DirBuster 2.3 Medium (SecLists)', source: 'seclists' as const },
                          { id: 'dirbuster_big', name: 'DirBuster 2.3 Big (SecLists)', source: 'seclists' as const },
                        ]
                    ).map((w) => (
                      <option key={w.id} value={w.id} className="bg-panel text-theme-primary">
                        {w.name}
                      </option>
                    ))}
                  </select>

                  {wordlistsData.web.some((w) => w.source === 'custom') && (
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {wordlistsData.web
                        .filter((w) => w.source === 'custom')
                        .map((cw) => (
                          <span key={cw.id} className="inline-flex items-center space-x-1 px-2 py-0.5 rounded border border-theme bg-panel text-[10px] font-mono text-theme-secondary">
                            <span>{cw.filename}</span>
                            <button
                              type="button"
                              onClick={() => handleDeleteCustomWordlist('web', cw.filename)}
                              className="text-red-400 hover:text-red-300"
                              title={L('Delete custom wordlist', 'Elimina wordlist')}
                            >
                              <Trash2 className="w-3 h-3" />
                            </button>
                          </span>
                        ))}
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <div>
                    <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                      {L('Extensions (optional)', 'Estensioni (opzionale)')}
                    </label>
                    <input
                      type="text"
                      value={dirExtensions}
                      onChange={(e) => setDirExtensions(e.target.value)}
                      placeholder="php,txt,bak,json"
                      className="input-industrial w-full px-2.5 py-1 text-xs font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                      {L('Rate Limit (req/s)', 'Rate Limit (req/s)')}
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      value={dirRateLimit}
                      onChange={(e) => {
                        if (/^\d*$/.test(e.target.value)) setDirRateLimit(e.target.value);
                      }}
                      onBlur={() => setDirRateLimit(String(clampIntStr(dirRateLimit, 10, 500, 100)))}
                      placeholder="100"
                      className="input-industrial w-full px-2.5 py-1 text-xs font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                      {L('Time Limit (sec)', 'Limite Tempo (sec)')}
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      value={dirTimeLimit}
                      onChange={(e) => {
                        if (/^\d*$/.test(e.target.value)) setDirTimeLimit(e.target.value);
                      }}
                      onBlur={() => setDirTimeLimit(String(clampIntStr(dirTimeLimit, 30, 600, 180)))}
                      placeholder="180"
                      className="input-industrial w-full px-2.5 py-1 text-xs font-mono"
                    />
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5">
                  <label className="flex items-center space-x-2 text-[11px] text-theme-secondary cursor-pointer">
                    <input
                      type="checkbox"
                      checked={dirRecursion}
                      onChange={(e) => setDirRecursion(e.target.checked)}
                      className="rounded"
                    />
                    <span>{L('Enable recursive scanning (slower)', 'Abilita scansione ricorsiva (più lenta)')}</span>
                  </label>
                  <div className="flex items-center space-x-1.5 text-[11px] font-mono">
                    <span className="text-theme-muted">{L('Max Depth:', 'Profondità Max:')}</span>
                    <input
                      type="text"
                      inputMode="numeric"
                      value={dirMaxDepth}
                      disabled={!dirRecursion}
                      onChange={(e) => {
                        if (/^\d*$/.test(e.target.value)) setDirMaxDepth(e.target.value);
                      }}
                      onBlur={() => setDirMaxDepth(String(clampIntStr(dirMaxDepth, 1, 10, 2)))}
                      placeholder="2"
                      className={`input-industrial w-14 px-2 py-0.5 text-xs text-center ${!dirRecursion ? 'opacity-50 cursor-not-allowed' : ''}`}
                    />
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Module C: Tech Stack Fingerprinting & CVE / PoC Intel */}
        <div className={`grid grid-cols-1 md:grid-cols-2 gap-4 pt-1 ${selectedAgentId ? 'opacity-50 pointer-events-none' : ''}`}>
          <div className={`p-3 rounded border transition ${enableTechFingerprint ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'}`}>
            <label className="flex items-start justify-between gap-3 cursor-pointer">
              <div>
                <div className="text-xs font-bold text-theme-primary">
                  {L('Tech Stack Fingerprinting (Wappalyzer / httpx + Nmap CPE)', 'Fingerprinting Stack Tecnologico (Wappalyzer / httpx + Nmap CPE)')}
                </div>
                <div className="text-[11px] text-theme-secondary mt-0.5">
                  {L(
                    'Identifies CMS, frameworks, web servers & backend versions independently from SubRaptor (external & LAN).',
                    'Rileva CMS, framework, web server e versioni dei servizi anche senza SubRaptor (scansioni esterne e interne).'
                  )}
                </div>
              </div>
              <input
                type="checkbox"
                checked={enableTechFingerprint}
                onChange={(e) => {
                  const next = e.target.checked;
                  setEnableTechFingerprint(next);
                  if (!next) setEnableCveIntel(false);
                }}
                className="mt-0.5 rounded"
              />
            </label>
          </div>

          <div className={`p-3 rounded border transition ${enableTechFingerprint && enableCveIntel ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'} ${!enableTechFingerprint ? 'opacity-50 pointer-events-none' : ''}`}>
            <label className="flex items-start justify-between gap-3 cursor-pointer">
              <div>
                <div className="text-xs font-bold text-theme-primary">
                  {L('CVE, CISA KEV, EPSS & PoC-in-GitHub Intelligence', 'Correlazione CVE recenti, CISA KEV, EPSS & PoC GitHub')}
                </div>
                <div className="text-[11px] text-theme-secondary mt-0.5">
                  {L(
                    'Correlates detected versions against NVD, CISA KEV active exploits, EPSS scores & public GitHub PoCs (labeled VERSION-BASED).',
                    'Associa alle versioni rilevate le CVE recenti NVD, flag CISA KEV, EPSS e link PoC GitHub (etichettati VERSION-BASED).'
                  )}
                </div>
              </div>
              <input
                type="checkbox"
                checked={enableTechFingerprint && enableCveIntel}
                disabled={!enableTechFingerprint}
                onChange={(e) => setEnableCveIntel(e.target.checked)}
                className="mt-0.5 rounded"
              />
            </label>
          </div>
        </div>
      </div>
        </div>
      </div>
    </div>
  );
};
