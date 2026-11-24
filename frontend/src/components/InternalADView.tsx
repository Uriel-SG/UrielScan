import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  ExternalLink,
  FolderUp,
  Network,
  Play,
  Radio,
  RefreshCw,
  ShieldAlert,
  Terminal,
  UploadCloud,
} from 'lucide-react';
import { InternalADCatalog, Organization, Scan } from '../types';
import { api } from '../services/api';
import { useI18n } from '../i18n/LanguageContext';
import { useToast } from './UIFeedback';

interface InternalADViewProps {
  organizations: Organization[];
  selectedOrgId: string;
  scans: Scan[];
  onScanCreated: (scan: Scan) => void;
  onNavigateToScan: (scanId: string) => void;
}

const CHECK_LABELS: Record<string, { en: string; it: string }> = {
  smb_signing: { en: 'SMB Signing', it: 'SMB Signing' },
  smbv1: { en: 'SMBv1 Legacy', it: 'SMBv1 Obsoleto' },
  null_shares: { en: 'Null/Guest Shares', it: 'Share Anonime/Guest' },
  ldap_anon: { en: 'LDAP Anon Bind', it: 'LDAP Bind Anonimo' },
  pass_pol: { en: 'Password Policy', it: 'Password Policy' },
  kerberoast: { en: 'Kerberoasting', it: 'Kerberoasting' },
  asrep: { en: 'AS-REP Roasting', it: 'AS-REP Roasting' },
  adcs: { en: 'ADCS Templates', it: 'Template ADCS' },
  delegation: { en: 'Delegations', it: 'Deleghe Kerberos' },
  laps: { en: 'LAPS Coverage', it: 'Copertura LAPS' },
};

export const InternalADView: React.FC<InternalADViewProps> = ({
  organizations,
  selectedOrgId,
  scans,
  onScanCreated,
  onNavigateToScan,
}) => {
  const { L } = useI18n();
  const { showToast } = useToast();

  const [catalog, setCatalog] = useState<InternalADCatalog | null>(null);
  const [installingTool, setInstallingTool] = useState<string | null>(null);
  const [launching, setLaunching] = useState<boolean>(false);
  const [uploading, setUploading] = useState<boolean>(false);

  const [orgId, setOrgId] = useState<string>(
    selectedOrgId && selectedOrgId !== 'ALL' ? selectedOrgId : organizations[0]?.id || ''
  );
  const [auditName, setAuditName] = useState<string>('Internal LAN & AD Security Audit');
  const [targets, setTargets] = useState<string>('');
  const [domain, setDomain] = useState<string>('');
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');

  // NetExec flags
  const [enableNetexec, setEnableNetexec] = useState<boolean>(true);
  const [nxcProtocols, setNxcProtocols] = useState<string[]>(['smb', 'ldap']);
  const [nxcChecks, setNxcChecks] = useState<string[]>(['smb_signing', 'smbv1', 'null_shares', 'ldap_anon']);

  // Enum4linux-ng
  const [enableEnum4linux, setEnableEnum4linux] = useState<boolean>(false);

  // BloodHound AD & AzureHound Entra ID
  const [enableBloodhound, setEnableBloodhound] = useState<boolean>(false);
  const [enableAzurehound, setEnableAzurehound] = useState<boolean>(false);
  const [azTenantId, setAzTenantId] = useState<string>('');
  const [azClientId, setAzClientId] = useState<string>('');
  const [azClientSecret, setAzClientSecret] = useState<string>('');
  const [uploadKind, setUploadKind] = useState<'auto' | 'bloodhound' | 'azurehound'>('auto');

  // Responder / LAN Broadcast (Passive default + Authorized Active warning)
  const [enableResponder, setEnableResponder] = useState<boolean>(false);
  const [responderMode, setResponderMode] = useState<'passive' | 'active'>('passive');
  const [responderActiveAuthorized, setResponderActiveAuthorized] = useState<boolean>(false);
  const [responderDuration, setResponderDuration] = useState<number>(30);
  const [responderInterface, setResponderInterface] = useState<string>('eth0');

  useEffect(() => {
    if (selectedOrgId && selectedOrgId !== 'ALL') {
      setOrgId(selectedOrgId);
    } else if (!orgId && organizations.length > 0) {
      setOrgId(organizations[0].id);
    }
  }, [selectedOrgId, organizations, orgId]);

  const loadCatalog = async () => {
    try {
      const cat = await api.getInternalCatalog();
      setCatalog(cat);
    } catch {
      // ignore initial error
    }
  };

  useEffect(() => {
    loadCatalog();
  }, []);

  const internalScans = scans.filter(
    (s) =>
      (s.engines.some((e) => ['netexec', 'enum4linux_ng', 'bloodhound', 'azurehound', 'responder', 'internal_ad'].includes(e))) &&
      (selectedOrgId === 'ALL' || s.org_id === selectedOrgId)
  );

  const handleInstall = async (tool: string) => {
    setInstallingTool(tool);
    try {
      const res = await api.installInternalTool(tool);
      showToast(res.message || `${tool} configurato.`, res.success ? 'success' : 'error');
      await loadCatalog();
    } catch (err: any) {
      showToast(err?.message || `Errore installazione ${tool}`, 'error');
    } finally {
      setInstallingTool(null);
    }
  };

  const toggleItem = (list: string[], val: string, setter: (next: string[]) => void) => {
    setter(list.includes(val) ? list.filter((x) => x !== val) : [...list, val]);
  };

  const handleLaunchAudit = async () => {
    if (!orgId) {
      showToast(L('Select an organization first.', 'Seleziona prima una organizzazione.'), 'error');
      return;
    }
    if (enableResponder && responderMode === 'active' && !responderActiveAuthorized) {
      showToast(
        L(
          'Explicit client authorization checkbox is required to launch Responder Active Mode.',
          'Devi confermare esplicitamente la autorizzazione del cliente per avviare Responder Active Mode.'
        ),
        'error'
      );
      return;
    }
    setLaunching(true);
    try {
      const created = await api.launchInternalADScan({
        org_id: orgId,
        name: auditName.trim() || 'Internal LAN & AD Security Audit',
        targets: targets.trim(),
        domain: domain.trim(),
        username: username.trim(),
        password,
        enable_netexec: enableNetexec,
        netexec_protocols: nxcProtocols,
        netexec_checks: nxcChecks,
        enable_enum4linux: enableEnum4linux,
        enable_bloodhound: enableBloodhound,
        enable_azurehound: enableAzurehound,
        azure_tenant_id: azTenantId.trim(),
        azure_client_id: azClientId.trim(),
        azure_client_secret: azClientSecret,
        enable_responder: enableResponder,
        responder_mode: responderMode,
        responder_active_authorized: responderActiveAuthorized,
        responder_duration_sec: responderDuration,
        responder_interface: responderInterface.trim(),
      });
      showToast(L('Internal & AD Security audit launched.', 'Audit Internal & AD Security avviato.'), 'success');
      onScanCreated(created);
    } catch (err: any) {
      showToast(err?.message || 'Errore avvio audit', 'error');
    } finally {
      setLaunching(false);
    }
  };

  const handleUploadArchive = async (file: File | null) => {
    if (!file || !orgId) return;
    setUploading(true);
    try {
      const fd = new FormData();
      fd.append('org_id', orgId);
      fd.append('name', `Identity Graph (${file.name})`);
      fd.append('kind', uploadKind);
      fd.append('file', file);
      const scan = await api.uploadIdentityArchive(fd);
      showToast(L('Identity archive analyzed cleanly.', 'Archivio BloodHound/AzureHound analizzato con successo.'), 'success');
      onScanCreated(scan);
    } catch (err: any) {
      showToast(err?.message || 'Errore analisi file', 'error');
    } finally {
      setUploading(false);
    }
  };

  const toolBadges: Array<{ key: keyof InternalADCatalog['tools']; label: string; installable: boolean }> = [
    { key: 'netexec', label: 'NetExec', installable: true },
    { key: 'bloodhound', label: 'BloodHound', installable: true },
    { key: 'azurehound', label: 'AzureHound', installable: true },
    { key: 'enum4linux_ng', label: 'Enum4linux-ng', installable: true },
    { key: 'responder', label: 'LAN Sniffer', installable: false },
  ];

  return (
    <div className="space-y-6">
      {/* Header + Provisioning Bar */}
      <div className="card-industrial p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded bg-subtle border border-theme flex items-center justify-center text-theme-accent">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-base font-bold text-theme-primary flex items-center space-x-2">
                <span>Internal &amp; AD Security</span>
                <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-subtle border border-theme text-theme-accent">
                  LAN / AD / ENTRA ID
                </span>
              </h1>
              <p className="text-xs text-theme-secondary">
                {L(
                  'Internal network, Active Directory & Entra ID auditing with NetExec, Enum4linux-ng, BloodHound, AzureHound & LAN broadcast analysis.',
                  'Audit LAN interna, Active Directory & Entra ID con NetExec, Enum4linux-ng, BloodHound, AzureHound e analisi broadcast LAN.'
                )}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {toolBadges.map((tb) => {
              const info = catalog?.tools?.[tb.key];
              const ok = Boolean(info?.installed);
              return (
                <div
                  key={tb.key}
                  className={`px-2 py-1 rounded border text-[11px] font-mono flex items-center space-x-1.5 ${
                    ok
                      ? 'bg-emerald-950/30 border-emerald-700/60 text-emerald-400'
                      : 'bg-subtle border-theme text-theme-secondary'
                  }`}
                >
                  {ok ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3 text-amber-400" />}
                  <span>{tb.label}</span>
                  {!ok && tb.installable && (
                    <button
                      type="button"
                      disabled={installingTool === tb.key}
                      onClick={() => handleInstall(tb.key)}
                      className="ml-1 px-1.5 py-0.5 rounded bg-panel border border-theme text-[10px] text-theme-accent hover:border-theme-accent flex items-center space-x-1"
                    >
                      {installingTool === tb.key ? (
                        <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                      ) : (
                        <Download className="w-2.5 h-2.5" />
                      )}
                      <span>{L('Install', 'Installa')}</span>
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Main 2-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-7 space-y-4">
          <div className="card-industrial p-4 space-y-4">
            {/* Target & AD Context */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                  {L('Client Organization', 'Organizzazione Cliente')}
                </label>
                <select
                  value={orgId}
                  onChange={(e) => setOrgId(e.target.value)}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs"
                >
                  {organizations.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                  {L('Audit Session Name', 'Nome Sessione Audit')}
                </label>
                <input
                  type="text"
                  value={auditName}
                  onChange={(e) => setAuditName(e.target.value)}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs"
                />
              </div>
              <div>
                <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                  {L('LAN Targets / Domain Controller IP', 'Target LAN / IP Domain Controller')}
                </label>
                <input
                  type="text"
                  value={targets}
                  onChange={(e) => setTargets(e.target.value)}
                  placeholder="192.168.10.0/24, 192.168.10.5"
                  className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                />
              </div>
              <div>
                <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                  {L('AD Domain (optional)', 'Dominio AD (opzionale)')}
                </label>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="corp.local"
                  className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                />
              </div>
              <div>
                <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                  {L('Audit AD Username (optional read-only)', 'Utente AD Audit (opzionale read-only)')}
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="audit.svc"
                  className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                />
              </div>
              <div>
                <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                  {L('Audit AD Password (ephemeral)', 'Password AD Audit (temporanea)')}
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="********"
                  className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                />
              </div>
            </div>

            {/* 1. NetExec Modular Flags */}
            <div className={`p-3 rounded border space-y-3 transition ${enableNetexec ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'}`}>
              <label className="flex items-start justify-between gap-3 cursor-pointer">
                <div>
                  <div className="text-xs font-bold text-theme-primary flex items-center space-x-1.5">
                    <Terminal className="w-3.5 h-3.5 text-theme-accent" />
                    <span>1. NetExec (`nxc`) — {L('Protocol & Check Flags', 'Protocolli & Flag Selezionabili')}</span>
                  </div>
                  <div className="text-[11px] text-theme-secondary mt-0.5">
                    {L(
                      'Select specific protocols and non-destructive AD/SMB checks (no password spray to prevent lockouts).',
                      'Seleziona protocolli e controlli mirati SMB/LDAP/AD (nessun password spray per evitare blocchi account).'
                    )}
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={enableNetexec}
                  onChange={(e) => setEnableNetexec(e.target.checked)}
                  className="mt-0.5 rounded"
                />
              </label>

              {enableNetexec && (
                <div className="space-y-2.5 pt-2 border-t border-theme-subtle">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[10px] font-mono uppercase text-theme-muted mr-1">{L('Protocols:', 'Protocolli:')}</span>
                    {(catalog?.netexec_protocols || ['smb', 'ldap', 'winrm', 'rdp', 'mssql', 'ssh']).map((p) => {
                      const active = nxcProtocols.includes(p);
                      return (
                        <button
                          key={p}
                          type="button"
                          onClick={() => toggleItem(nxcProtocols, p, setNxcProtocols)}
                          className={`px-2 py-0.5 rounded border text-[11px] font-mono uppercase ${
                            active ? 'bg-theme-accent border-theme-accent font-bold' : 'bg-panel border-theme text-theme-secondary'
                          }`}
                        >
                          {p}
                        </button>
                      );
                    })}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {(catalog?.netexec_checks || Object.keys(CHECK_LABELS)).map((chk) => {
                      const active = nxcChecks.includes(chk);
                      return (
                        <button
                          key={chk}
                          type="button"
                          onClick={() => toggleItem(nxcChecks, chk, setNxcChecks)}
                          className={`px-2 py-0.5 rounded border text-[11px] ${
                            active ? 'row-selected-theme border-theme-accent text-theme-accent font-semibold' : 'bg-panel border-theme text-theme-secondary'
                          }`}
                        >
                          {L(CHECK_LABELS[chk]?.en || chk, CHECK_LABELS[chk]?.it || chk)}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* 2. Enum4linux-ng */}
            <div className={`p-3 rounded border transition ${enableEnum4linux ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'}`}>
              <label className="flex items-start justify-between gap-3 cursor-pointer">
                <div>
                  <div className="text-xs font-bold text-theme-primary">2. Enum4linux-ng (SMB / Shares / RID Cycling)</div>
                  <div className="text-[11px] text-theme-secondary mt-0.5">
                    {L(
                      'Enumerates open shares, null sessions, domain policy & users into JSON findings (full Samba execution on Linux).',
                      'Enumera share aperte, null session, utenti RID e policy con output JSON strutturato (esecuzione Samba completa su Linux).'
                    )}
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={enableEnum4linux}
                  onChange={(e) => setEnableEnum4linux(e.target.checked)}
                  className="mt-0.5 rounded"
                />
              </label>
            </div>

            {/* 3. BloodHound AD & AzureHound Entra ID */}
            <div className={`p-3 rounded border space-y-3 transition ${(enableBloodhound || enableAzurehound) ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'}`}>
              <div className="text-xs font-bold text-theme-primary">3. BloodHound (AD) &amp; AzureHound (Entra ID)</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <label className="flex items-center space-x-2 text-xs text-theme-secondary cursor-pointer p-2 rounded bg-panel border border-theme">
                  <input type="checkbox" checked={enableBloodhound} onChange={(e) => setEnableBloodhound(e.target.checked)} className="rounded" />
                  <span>{L('Live BloodHound AD Collector', 'Raccolta Live BloodHound AD')}</span>
                </label>
                <label className="flex items-center space-x-2 text-xs text-theme-secondary cursor-pointer p-2 rounded bg-panel border border-theme">
                  <input type="checkbox" checked={enableAzurehound} onChange={(e) => setEnableAzurehound(e.target.checked)} className="rounded" />
                  <span>{L('Live AzureHound Entra ID', 'Raccolta Live AzureHound Entra ID')}</span>
                </label>
              </div>

              {enableAzurehound && (
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
                  <input
                    type="text"
                    value={azTenantId}
                    onChange={(e) => setAzTenantId(e.target.value)}
                    placeholder="Entra Tenant ID"
                    className="input-industrial px-2 py-1 text-xs font-mono"
                  />
                  <input
                    type="text"
                    value={azClientId}
                    onChange={(e) => setAzClientId(e.target.value)}
                    placeholder="App Client ID"
                    className="input-industrial px-2 py-1 text-xs font-mono"
                  />
                  <input
                    type="password"
                    value={azClientSecret}
                    onChange={(e) => setAzClientSecret(e.target.value)}
                    placeholder="Client Secret"
                    className="input-industrial px-2 py-1 text-xs font-mono"
                  />
                </div>
              )}

              {/* Direct Upload (.zip / .json SharpHound / BloodHound / AzureHound) */}
              <div className="p-2.5 rounded bg-panel border border-theme flex flex-wrap items-center justify-between gap-2">
                <div className="text-[11px] text-theme-secondary flex items-center space-x-1.5">
                  <FolderUp className="w-3.5 h-3.5 text-theme-accent" />
                  <span>
                    {L(
                      'Offline Analysis: upload SharpHound/BloodHound (.zip/.json) or AzureHound (.json)',
                      'Analisi Offline: carica export SharpHound/BloodHound (.zip/.json) o AzureHound (.json)'
                    )}
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  <select
                    value={uploadKind}
                    onChange={(e) => setUploadKind(e.target.value as any)}
                    className="input-industrial px-2 py-1 text-[11px] font-mono"
                  >
                    <option value="auto">Auto</option>
                    <option value="bloodhound">BloodHound AD</option>
                    <option value="azurehound">AzureHound Entra ID</option>
                  </select>
                  <label className="btn-secondary px-2.5 py-1 text-[11px] font-semibold cursor-pointer inline-flex items-center space-x-1">
                    {uploading ? <RefreshCw className="w-3 h-3 animate-spin" /> : <UploadCloud className="w-3 h-3" />}
                    <span>{uploading ? L('Analyzing...', 'Analisi...') : L('Upload Export', 'Carica Export')}</span>
                    <input
                      type="file"
                      accept=".zip,.json"
                      disabled={uploading}
                      onChange={(e) => {
                        const f = e.target.files?.[0] || null;
                        handleUploadArchive(f);
                        e.target.value = '';
                      }}
                      className="hidden"
                    />
                  </label>
                </div>
              </div>
            </div>

            {/* 4. Responder / LAN Broadcast Audit */}
            <div className={`p-3 rounded border space-y-3 transition ${enableResponder ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'}`}>
              <label className="flex items-start justify-between gap-3 cursor-pointer">
                <div>
                  <div className="text-xs font-bold text-theme-primary flex items-center space-x-1.5">
                    <Radio className="w-3.5 h-3.5 text-theme-accent" />
                    <span>4. Responder / LLMNR &amp; NBT-NS Broadcast Audit</span>
                  </div>
                  <div className="text-[11px] text-theme-secondary mt-0.5">
                    {L(
                      'Passive zero-spoofing UDP listener by default; Active poisoning mode is strictly opt-in.',
                      'Modalità passiva zero-spoofing di default; modalità attiva strettamente opzionale su autorizzazione.'
                    )}
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={enableResponder}
                  onChange={(e) => setEnableResponder(e.target.checked)}
                  className="mt-0.5 rounded"
                />
              </label>

              {enableResponder && (
                <div className="space-y-3 pt-2 border-t border-theme-subtle">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    <div>
                      <label className="text-[10px] font-mono text-theme-muted block mb-1">{L('Mode', 'Modalità')}</label>
                      <select
                        value={responderMode}
                        onChange={(e) => {
                          const next = e.target.value as 'passive' | 'active';
                          setResponderMode(next);
                          if (next === 'passive') setResponderActiveAuthorized(false);
                        }}
                        className="input-industrial w-full px-2 py-1 text-xs"
                      >
                        <option value="passive">{L('Passive (Safe Sniff Only)', 'Passiva (Solo Ascolto Sicuro)')}</option>
                        <option value="active">{L('Active (Poisoning — Authorized Only)', 'Attiva (Poisoning — Solo Autorizzato)')}</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-[10px] font-mono text-theme-muted block mb-1">{L('Duration (sec)', 'Durata (sec)')}</label>
                      <input
                        type="number"
                        min={10}
                        max={120}
                        value={responderDuration}
                        onChange={(e) => setResponderDuration(Math.max(10, Math.min(120, Number(e.target.value) || 30)))}
                        className="input-industrial w-full px-2 py-1 text-xs font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono text-theme-muted block mb-1">{L('Interface (Active)', 'Interfaccia (Active)')}</label>
                      <input
                        type="text"
                        value={responderInterface}
                        disabled={responderMode === 'passive'}
                        onChange={(e) => setResponderInterface(e.target.value)}
                        className={`input-industrial w-full px-2 py-1 text-xs font-mono ${responderMode === 'passive' ? 'opacity-50' : ''}`}
                      />
                    </div>
                  </div>

                  {responderMode === 'active' && (
                    <div className="p-3 rounded bg-red-950/30 border border-red-600/60 space-y-2 text-xs">
                      <div className="flex items-start space-x-2 text-red-300 font-semibold">
                        <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
                        <span>
                          {L(
                            'WARNING: Responder Active Mode actively responds to LLMNR/NBT-NS/mDNS broadcasts on the LAN. This can disrupt printers/shares, trigger EDR/NDR alerts, and capture Net-NTLMv2 hashes.',
                            'ATTENZIONE: Responder Active Mode risponde attivamente ai broadcast LLMNR/NBT-NS/mDNS in LAN. Può causare disservizi su share/stampanti, generare allarmi EDR/NDR e intercettare hash Net-NTLMv2.'
                          )}
                        </span>
                      </div>
                      <label className="flex items-center space-x-2 cursor-pointer text-amber-300 font-mono text-[11px]">
                        <input
                          type="checkbox"
                          checked={responderActiveAuthorized}
                          onChange={(e) => setResponderActiveAuthorized(e.target.checked)}
                          className="rounded"
                        />
                        <span>
                          {L(
                            'I confirm written client authorization for Active LAN Poisoning testing.',
                            'Confermo di avere esplicita autorizzazione scritta del cliente per test attivi Responder.'
                          )}
                        </span>
                      </label>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex justify-end">
              <button
                type="button"
                disabled={launching}
                onClick={handleLaunchAudit}
                className="btn-primary px-4 py-2 text-xs font-bold flex items-center space-x-2"
              >
                {launching ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>{launching ? L('Launching...', 'Avvio...') : L('Launch Internal & AD Audit', 'Avvia Audit Internal & AD')}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Right: Recent Internal & AD Audits */}
        <div className="lg:col-span-5 space-y-3">
          <div className="card-industrial p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-theme-subtle pb-2">
              <div className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
                {L('Recent Internal & AD Audits', 'Audit Internal & AD Recenti')}
              </div>
              <span className="text-[11px] font-mono text-theme-muted">{internalScans.length}</span>
            </div>

            {internalScans.length === 0 ? (
              <div className="py-10 text-center text-xs text-theme-muted space-y-1.5">
                <Network className="w-7 h-7 mx-auto opacity-40" />
                <div>
                  {L(
                    'No Internal / Active Directory audits recorded yet for this organization.',
                    'Nessun audit Internal / Active Directory registrato finora per questa organizzazione.'
                  )}
                </div>
              </div>
            ) : (
              <div className="space-y-2.5 max-h-[600px] overflow-y-auto pr-1">
                {internalScans.map((s) => {
                  const ia = s.internal_ad;
                  return (
                    <div key={s.id} className="p-3 rounded bg-subtle border border-theme space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <button
                          type="button"
                          onClick={() => onNavigateToScan(s.id)}
                          className="text-xs font-bold text-theme-primary hover:text-theme-accent truncate flex items-center space-x-1.5 text-left"
                        >
                          <span className="truncate">{s.name}</span>
                          <ExternalLink className="w-3 h-3 shrink-0" />
                        </button>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-panel border border-theme text-theme-accent uppercase shrink-0">
                          {s.status}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-theme-muted truncate">{s.targets}</div>
                      {ia?.bloodhound && (
                        <div className="flex flex-wrap gap-1.5 text-[10px] font-mono">
                          <span className="px-1.5 py-0.5 rounded bg-red-950/40 border border-red-700/50 text-red-400">
                            ACLs: {ia.bloodhound.dangerous_acls}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-amber-950/40 border border-amber-700/50 text-amber-400">
                            Kerberoast: {ia.bloodhound.kerberoastable_admins}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-panel border border-theme text-theme-secondary">
                            AS-REP: {ia.bloodhound.asrep_roastable}
                          </span>
                        </div>
                      )}
                      {ia?.azurehound && (
                        <div className="flex flex-wrap gap-1.5 text-[10px] font-mono">
                          <span className="px-1.5 py-0.5 rounded bg-amber-950/40 border border-amber-700/50 text-amber-400">
                            Global Admins: {ia.azurehound.global_admins}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-red-950/40 border border-red-700/50 text-red-400">
                            Risky Graph Apps: {ia.azurehound.risky_graph_apps}
                          </span>
                        </div>
                      )}
                      {ia?.export_available && (
                        <button
                          type="button"
                          onClick={() => api.downloadInternalExport(s.id).catch((e) => showToast(e?.message || 'Error', 'error'))}
                          className="btn-secondary px-2 py-1 text-[10px] font-mono inline-flex items-center space-x-1"
                        >
                          <Download className="w-3 h-3" />
                          <span>{L('Download BloodHound/AzureHound .zip', 'Scarica .zip BloodHound/AzureHound')}</span>
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
