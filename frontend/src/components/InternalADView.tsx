import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Download,
  FolderUp,
  Network,
  Play,
  Radio,
  RefreshCw,
  ShieldAlert,
  Sliders,
  Square,
  Terminal,
  UploadCloud,
} from 'lucide-react';
import { InternalADCatalog, NetworkInterfaceItem, ResponderSessionStatus, Scan } from '../types';
import { api } from '../services/api';
import { useI18n } from '../i18n/LanguageContext';
import { useToast } from './UIFeedback';

export interface InternalADConfig {
  domain: string;
  username: string;
  password: string;
  enable_netexec: boolean;
  netexec_protocols: string[];
  netexec_checks: string[];
  enable_enum4linux: boolean;
  enable_bloodhound: boolean;
  enable_azurehound: boolean;
  azure_tenant_id: string;
  azure_client_id: string;
  azure_client_secret: string;
}

export const DEFAULT_INTERNAL_AD_CONFIG: InternalADConfig = {
  domain: '',
  username: '',
  password: '',
  enable_netexec: true,
  netexec_protocols: ['smb', 'ldap'],
  netexec_checks: ['smb_signing', 'smbv1', 'null_shares', 'ldap_anon'],
  enable_enum4linux: false,
  enable_bloodhound: false,
  enable_azurehound: false,
  azure_tenant_id: '',
  azure_client_id: '',
  azure_client_secret: '',
};

interface InternalADPanelProps {
  orgId: string;
  value: InternalADConfig;
  onChange: (next: InternalADConfig) => void;
  onScanCreated: (scan: Scan) => void;
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

export const InternalADPanel: React.FC<InternalADPanelProps> = ({
  orgId,
  value,
  onChange,
  onScanCreated,
}) => {
  const { L } = useI18n();
  const { showToast } = useToast();

  const [catalog, setCatalog] = useState<InternalADCatalog | null>(null);
  const [installingTool, setInstallingTool] = useState<string | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);
  const [uploadKind, setUploadKind] = useState<'auto' | 'bloodhound' | 'azurehound'>('auto');

  // Decoupled Standalone Responder (#1 panel inside Internal & AD)
  const [interfaces, setInterfaces] = useState<NetworkInterfaceItem[]>([
    { name: 'all', ip: '0.0.0.0', label: 'All Interfaces (0.0.0.0)' },
  ]);
  const [selectedIfaceIp, setSelectedIfaceIp] = useState<string>('0.0.0.0');
  const [responderMode, setResponderMode] = useState<'passive' | 'active'>('passive');
  const [responderActiveAuthorized, setResponderActiveAuthorized] = useState<boolean>(false);
  const [responderStatus, setResponderStatus] = useState<ResponderSessionStatus | null>(null);
  const [responderBusy, setResponderBusy] = useState<boolean>(false);
  const [showResponderConfig, setShowResponderConfig] = useState<boolean>(false);
  const [responderProtocols, setResponderProtocols] = useState<Record<string, boolean>>({
    llmnr: true,
    nbns: true,
    mdns: true,
    smb: true,
    http: true,
    https: true,
    ldap: true,
    sql: true,
    ftp: true,
    dns: true,
  });
  const [responderOptions, setResponderOptions] = useState<Record<string, boolean>>({
    wpad: false,
    force_wpad_auth: false,
    basic_auth: false,
    dhcp: false,
  });
  const consoleEndRef = useRef<HTMLDivElement | null>(null);

  const loadCatalogAndStatus = async () => {
    try {
      const [cat, ifaces, respSt] = await Promise.all([
        api.getInternalCatalog(),
        api.getInternalInterfaces().catch(() => []),
        api.getResponderStatus().catch(() => null),
      ]);
      setCatalog(cat);
      if (ifaces.length > 0) setInterfaces(ifaces);
      if (respSt) setResponderStatus(respSt);
    } catch {
      // ignore transient init error
    }
  };

  useEffect(() => {
    loadCatalogAndStatus();
  }, []);

  useEffect(() => {
    if (!responderStatus?.running) return;
    const tmr = window.setInterval(async () => {
      try {
        const st = await api.getResponderStatus();
        setResponderStatus(st);
      } catch {
        // ignore poll glitch
      }
    }, 1500);
    return () => window.clearInterval(tmr);
  }, [responderStatus?.running]);

  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [responderStatus?.logs?.length]);

  const patch = (partial: Partial<InternalADConfig>) => {
    onChange({ ...value, ...partial });
  };

  const toggleListItem = (field: 'netexec_protocols' | 'netexec_checks', item: string) => {
    const cur = value[field] || [];
    const next = cur.includes(item) ? cur.filter((x) => x !== item) : [...cur, item];
    patch({ [field]: next });
  };

  const handleInstall = async (tool: string) => {
    setInstallingTool(tool);
    try {
      const res = await api.installInternalTool(tool);
      showToast(res.message || `${tool} configurato.`, res.success ? 'success' : 'error');
      await loadCatalogAndStatus();
    } catch (err: any) {
      showToast(err?.message || `Errore installazione ${tool}`, 'error');
    } finally {
      setInstallingTool(null);
    }
  };

  const handleResponderToggle = async () => {
    if (responderStatus?.running) {
      setResponderBusy(true);
      try {
        const st = await api.stopResponder();
        setResponderStatus(st);
        showToast(L('Responder listener stopped.', 'Listener Responder arrestato.'), 'info');
      } catch (err: any) {
        showToast(err?.message || 'Errore stop Responder', 'error');
      } finally {
        setResponderBusy(false);
      }
      return;
    }

    if (responderMode === 'active' && !responderActiveAuthorized) {
      showToast(
        L(
          'Explicit client authorization checkbox is required to start Responder Active Mode.',
          'Devi confermare esplicitamente l’autorizzazione del cliente per avviare Responder Active Mode.'
        ),
        'error'
      );
      return;
    }

    const ifaceObj = interfaces.find((x) => x.ip === selectedIfaceIp) || interfaces[0] || {
      name: 'all',
      ip: '0.0.0.0',
      label: 'All Interfaces (0.0.0.0)',
    };
    setResponderBusy(true);
    try {
      const st = await api.startResponder({
        mode: responderMode,
        active_authorized: responderActiveAuthorized,
        interface: ifaceObj.name,
        bind_ip: ifaceObj.ip,
        protocols: responderProtocols,
        options: responderOptions,
      });
      setResponderStatus(st);
      showToast(L('Responder listener started.', 'Listener Responder avviato.'), 'success');
    } catch (err: any) {
      showToast(err?.message || 'Errore avvio Responder', 'error');
    } finally {
      setResponderBusy(false);
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
    <div className="card-industrial p-4 space-y-4 border-theme-accent/60">
      {/* Header + Provisioning Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-theme-subtle pb-3">
        <div className="flex items-center space-x-2.5">
          <Network className="w-4 h-4 text-theme-accent shrink-0" />
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-theme-primary">
              Internal &amp; AD Security Suite (LAN • Active Directory • Entra ID)
            </div>
            <div className="text-[11px] text-theme-secondary">
              {L(
                'Runs combined with Nmap & selected engines in this scan — Responder #1 runs independently.',
                'Eseguito insieme a Nmap e agli altri motori della scansione — Responder #1 è indipendente.'
              )}
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {toolBadges.map((tb) => {
            const info = catalog?.tools?.[tb.key];
            const ok = Boolean(info?.installed);
            return (
              <div
                key={tb.key}
                className={`px-2 py-0.5 rounded border text-[10px] font-mono flex items-center space-x-1 ${
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

      {/* 1. Decoupled Standalone Responder Card (Full Width Top) */}
      <div className="p-3.5 rounded border border-theme bg-panel space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <Radio className={`w-4 h-4 ${responderStatus?.running ? 'text-emerald-400 animate-pulse' : 'text-theme-accent'}`} />
            <div>
              <div className="text-xs font-bold text-theme-primary">
                1. Responder / LLMNR, NBT-NS &amp; mDNS Listener
              </div>
              <div className="text-[11px] text-theme-secondary">
                {L(
                  'Standalone LAN broadcast monitor (Passive zero-spoofing default). Start/Stop works independently of the scan launch.',
                  'Monitor broadcast LAN standalone (Passivo zero-spoofing di default). Start/Stop indipendente dall’avvio scansione.'
                )}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
            <span className="px-2 py-0.5 rounded bg-subtle border border-theme text-theme-secondary">
              {L('Hosts', 'Host')}: <strong className="text-theme-primary">{responderStatus?.hosts_seen?.length ?? 0}</strong>
            </span>
            <span className="px-2 py-0.5 rounded bg-subtle border border-theme text-theme-secondary">
              {L('Packets', 'Pacchetti')}: <strong className="text-theme-primary">{responderStatus?.packets_count ?? 0}</strong>
            </span>
            <span
              className={`px-2 py-0.5 rounded border font-bold uppercase ${
                responderStatus?.running
                  ? responderStatus.mode === 'active'
                    ? 'bg-red-950/50 border-red-600 text-red-400'
                    : 'bg-emerald-950/40 border-emerald-700 text-emerald-400'
                  : 'bg-subtle border-theme text-theme-muted'
              }`}
            >
              {responderStatus?.running
                ? `${L('RUNNING', 'ATTIVO')} (${responderStatus.mode.toUpperCase()}) • ${responderStatus.elapsed_sec}s`
                : 'IDLE'}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-5">
            <label className="text-[10px] font-mono uppercase text-theme-muted block mb-1">
              {L('Network Interface', 'Scheda di Rete')}
            </label>
            <select
              value={selectedIfaceIp}
              disabled={Boolean(responderStatus?.running)}
              onChange={(e) => setSelectedIfaceIp(e.target.value)}
              className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
            >
              {interfaces.map((iface) => (
                <option key={`${iface.name}-${iface.ip}`} value={iface.ip}>
                  {iface.label}
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-4">
            <label className="text-[10px] font-mono uppercase text-theme-muted block mb-1">
              {L('Listener Mode', 'Modalità Ascolto')}
            </label>
            <select
              value={responderMode}
              disabled={Boolean(responderStatus?.running)}
              onChange={(e) => {
                const next = e.target.value as 'passive' | 'active';
                setResponderMode(next);
                if (next === 'passive') setResponderActiveAuthorized(false);
              }}
              className="input-industrial w-full px-2.5 py-1.5 text-xs"
            >
              <option value="passive">{L('Passive (Safe Sniff Only)', 'Passiva (Solo Ascolto Sicuro)')}</option>
              <option value="active">{L('Active (Poisoning — Authorized Only)', 'Attiva (Poisoning — Solo Autorizzato)')}</option>
            </select>
          </div>

          <div className="md:col-span-3 flex justify-end">
            <button
              type="button"
              disabled={responderBusy}
              onClick={handleResponderToggle}
              className={`w-full px-4 py-1.5 text-xs font-bold flex items-center justify-center space-x-2 rounded border transition ${
                responderStatus?.running
                  ? 'bg-red-950/60 border-red-600 text-red-300 hover:bg-red-900/70'
                  : 'btn-primary'
              }`}
            >
              {responderBusy ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : responderStatus?.running ? (
                <Square className="w-3.5 h-3.5" />
              ) : (
                <Play className="w-3.5 h-3.5" />
              )}
              <span>{responderStatus?.running ? 'Stop' : 'Start'}</span>
            </button>
          </div>
        </div>

        {responderMode === 'active' && !responderStatus?.running && (
          <div className="p-3 rounded bg-red-950/30 border border-red-600/60 space-y-2 text-xs">
            <div className="flex items-start space-x-2 text-red-300 font-semibold">
              <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <span>
                {L(
                  'WARNING: Responder Active Mode actively answers LLMNR/NBT-NS/mDNS broadcasts on the LAN. It can disrupt network printers/shares, trigger EDR/NDR alerts, and capture Net-NTLMv2 hashes.',
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

        {/* Collapsible Protocol & Responder.conf Configuration Dropdown */}
        <div className="border-t border-theme-subtle pt-2.5">
          <button
            type="button"
            onClick={() => setShowResponderConfig((prev) => !prev)}
            className="w-full flex items-center justify-between px-2.5 py-1.5 rounded bg-subtle border border-theme text-[11px] font-mono text-theme-primary hover:border-theme-accent transition"
          >
            <span className="flex items-center space-x-2">
              <Sliders className="w-3.5 h-3.5 text-theme-accent" />
              <span>{L('Protocol & Responder.conf Settings', 'Configurazione Protocolli & Responder.conf')}</span>
              <span className="px-1.5 py-0.5 rounded bg-panel border border-theme text-[10px] text-theme-accent">
                {Object.values(responderProtocols).filter(Boolean).length}/{Object.keys(responderProtocols).length} ON
              </span>
            </span>
            <ChevronDown className={`w-3.5 h-3.5 text-theme-muted transition-transform ${showResponderConfig ? 'rotate-180' : ''}`} />
          </button>

          {showResponderConfig && (
            <div className={`mt-2 p-3 rounded bg-subtle border border-theme space-y-3 ${responderStatus?.running ? 'opacity-60 pointer-events-none' : ''}`}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[10px] font-mono uppercase text-theme-muted">
                  {L('Quick Presets:', 'Preset Rapidi:')}
                </span>
                <div className="flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => {
                      setResponderProtocols({ llmnr: true, nbns: true, mdns: true, smb: true, http: true, https: true, ldap: true, sql: true, ftp: true, dns: true });
                      setResponderOptions({ wpad: false, force_wpad_auth: false, basic_auth: false, dhcp: false });
                    }}
                    className="px-2 py-0.5 rounded border border-theme bg-panel text-[10px] font-mono text-theme-secondary hover:border-theme-accent"
                  >
                    {L('All Default', 'Tutti Attivi')}
                  </button>
                  <button
                    type="button"
                    onClick={() => setResponderProtocols({ llmnr: true, nbns: true, mdns: true, smb: false, http: false, https: true, ldap: true, sql: true, ftp: true, dns: true })}
                    className="px-2 py-0.5 rounded border border-theme bg-panel text-[10px] font-mono text-amber-300 hover:border-amber-500"
                  >
                    {L('Relay-Safe (SMB & HTTP Off)', 'Relay-Safe (SMB & HTTP Off)')}
                  </button>
                  <button
                    type="button"
                    onClick={() => setResponderProtocols({ llmnr: true, nbns: true, mdns: true, smb: false, http: false, https: false, ldap: false, sql: false, ftp: false, dns: false })}
                    className="px-2 py-0.5 rounded border border-theme bg-panel text-[10px] font-mono text-emerald-300 hover:border-emerald-500"
                  >
                    {L('Broadcast Only (LLMNR/NBT-NS/mDNS)', 'Solo Broadcast')}
                  </button>
                </div>
              </div>

              <div>
                <div className="text-[10px] font-mono uppercase text-theme-muted mb-1.5">
                  {L('Protocols & Poison Servers (toggle to disable selectively)', 'Protocolli & Server (deseleziona per disabilitare)')}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    { key: 'llmnr', label: 'LLMNR (:5355)' },
                    { key: 'nbns', label: 'NBT-NS (:137)' },
                    { key: 'mdns', label: 'mDNS (:5353)' },
                    { key: 'smb', label: 'SMB (:445)' },
                    { key: 'http', label: 'HTTP (:80)' },
                    { key: 'https', label: 'HTTPS (:443)' },
                    { key: 'ldap', label: 'LDAP (:389)' },
                    { key: 'sql', label: 'MSSQL (:1433)' },
                    { key: 'ftp', label: 'FTP (:21)' },
                    { key: 'dns', label: 'DNS (:53)' },
                  ].map((item) => {
                    const active = Boolean(responderProtocols[item.key]);
                    return (
                      <button
                        key={item.key}
                        type="button"
                        onClick={() =>
                          setResponderProtocols((prev) => ({ ...prev, [item.key]: !prev[item.key] }))
                        }
                        className={`px-2 py-1 rounded border text-[11px] font-mono transition ${
                          active
                            ? 'row-selected-theme border-theme-accent text-theme-accent font-semibold'
                            : 'bg-panel border-theme text-theme-muted line-through opacity-70'
                        }`}
                      >
                        {item.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div>
                <div className="text-[10px] font-mono uppercase text-theme-muted mb-1.5">
                  {L('Active Responder CLI / Conf Flags', 'Flag Responder Active / Conf')}
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {[
                    { key: 'wpad', label: 'WPAD Server (-w)' },
                    { key: 'force_wpad_auth', label: 'Force WPAD Auth (-F)' },
                    { key: 'basic_auth', label: 'Basic Auth (-b)' },
                    { key: 'dhcp', label: 'DHCP Spoof (-d)' },
                  ].map((opt) => (
                    <label
                      key={opt.key}
                      className="flex items-center space-x-2 text-[11px] font-mono text-theme-secondary cursor-pointer p-1.5 rounded bg-panel border border-theme"
                    >
                      <input
                        type="checkbox"
                        checked={Boolean(responderOptions[opt.key])}
                        onChange={(e) =>
                          setResponderOptions((prev) => ({ ...prev, [opt.key]: e.target.checked }))
                        }
                        className="rounded"
                      />
                      <span>{opt.label}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {(responderStatus?.running || (responderStatus?.logs?.length ?? 0) > 0) && (
          <div className="rounded bg-slate-950/90 border border-theme p-3 font-mono text-[11px] max-h-52 overflow-y-auto space-y-1">
            <div className="text-[10px] text-theme-muted border-b border-theme-subtle pb-1 mb-1 flex items-center justify-between">
              <span>RESPONDER LIVE CONSOLE — {responderStatus?.interface || 'all'} ({responderStatus?.bind_ip || '0.0.0.0'})</span>
              <span>{(responderStatus?.protocols_seen || []).join(', ') || 'LLMNR / NBT-NS / mDNS'}</span>
            </div>
            {(responderStatus?.logs || []).map((entry, idx) => (
              <div
                key={idx}
                className={
                  entry.level === 'ERROR'
                    ? 'text-red-400'
                    : entry.level === 'WARN'
                      ? 'text-amber-300'
                      : 'text-emerald-300'
                }
              >
                <span className="text-slate-500">[{entry.time}]</span> {entry.msg}
              </div>
            ))}
            <div ref={consoleEndRef} />
          </div>
        )}
      </div>

      {/* AD Domain & Audit Credentials (uses Scan Target(s) & Organization from Step 1) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div>
          <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
            {L('AD Domain (optional)', 'Dominio AD (opzionale)')}
          </label>
          <input
            type="text"
            value={value.domain}
            onChange={(e) => patch({ domain: e.target.value })}
            placeholder="corp.local"
            className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
          />
        </div>
        <div>
          <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
            {L('Audit AD Username (optional)', 'Utente AD Audit (opzionale)')}
          </label>
          <input
            type="text"
            value={value.username}
            onChange={(e) => patch({ username: e.target.value })}
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
            value={value.password}
            onChange={(e) => patch({ password: e.target.value })}
            placeholder="********"
            className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
          />
        </div>
      </div>

      {/* 2. NetExec Modular Flags */}
      <div className={`p-3 rounded border space-y-3 transition ${value.enable_netexec ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'}`}>
        <label className="flex items-start justify-between gap-3 cursor-pointer">
          <div>
            <div className="text-xs font-bold text-theme-primary flex items-center space-x-1.5">
              <Terminal className="w-3.5 h-3.5 text-theme-accent" />
              <span>2. NetExec (`nxc`) — {L('Protocol & Check Flags', 'Protocolli & Flag Selezionabili')}</span>
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
            checked={value.enable_netexec}
            onChange={(e) => patch({ enable_netexec: e.target.checked })}
            className="mt-0.5 rounded"
          />
        </label>

        {value.enable_netexec && (
          <div className="space-y-2.5 pt-2 border-t border-theme-subtle">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] font-mono uppercase text-theme-muted mr-1">{L('Protocols:', 'Protocolli:')}</span>
              {(catalog?.netexec_protocols || ['smb', 'ldap', 'winrm', 'rdp', 'mssql', 'ssh']).map((p) => {
                const active = value.netexec_protocols.includes(p);
                return (
                  <button
                    key={p}
                    type="button"
                    onClick={() => toggleListItem('netexec_protocols', p)}
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
                const active = value.netexec_checks.includes(chk);
                return (
                  <button
                    key={chk}
                    type="button"
                    onClick={() => toggleListItem('netexec_checks', chk)}
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

      {/* 3. Enum4linux-ng */}
      <div className={`p-3 rounded border transition ${value.enable_enum4linux ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'}`}>
        <label className="flex items-start justify-between gap-3 cursor-pointer">
          <div>
            <div className="text-xs font-bold text-theme-primary">3. Enum4linux-ng (SMB / Shares / RID Cycling)</div>
            <div className="text-[11px] text-theme-secondary mt-0.5">
              {L(
                'Enumerates open shares, null sessions, domain policy & users into JSON findings (full Samba execution on Linux).',
                'Enumera share aperte, null session, utenti RID e policy con output JSON strutturato (esecuzione Samba completa su Linux).'
              )}
            </div>
          </div>
          <input
            type="checkbox"
            checked={value.enable_enum4linux}
            onChange={(e) => patch({ enable_enum4linux: e.target.checked })}
            className="mt-0.5 rounded"
          />
        </label>
      </div>

      {/* 4. BloodHound AD & AzureHound Entra ID */}
      <div className={`p-3 rounded border space-y-3 transition ${(value.enable_bloodhound || value.enable_azurehound) ? 'border-theme-accent bg-subtle' : 'border-theme bg-panel'}`}>
        <div className="text-xs font-bold text-theme-primary">4. BloodHound (AD) &amp; AzureHound (Entra ID)</div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <label className="flex items-center space-x-2 text-xs text-theme-secondary cursor-pointer p-2 rounded bg-panel border border-theme">
            <input
              type="checkbox"
              checked={value.enable_bloodhound}
              onChange={(e) => patch({ enable_bloodhound: e.target.checked })}
              className="rounded"
            />
            <span>{L('Live BloodHound AD Collector', 'Raccolta Live BloodHound AD')}</span>
          </label>
          <label className="flex items-center space-x-2 text-xs text-theme-secondary cursor-pointer p-2 rounded bg-panel border border-theme">
            <input
              type="checkbox"
              checked={value.enable_azurehound}
              onChange={(e) => patch({ enable_azurehound: e.target.checked })}
              className="rounded"
            />
            <span>{L('Live AzureHound Entra ID', 'Raccolta Live AzureHound Entra ID')}</span>
          </label>
        </div>

        {value.enable_azurehound && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
            <input
              type="text"
              value={value.azure_tenant_id}
              onChange={(e) => patch({ azure_tenant_id: e.target.value })}
              placeholder="Entra Tenant ID"
              className="input-industrial px-2 py-1 text-xs font-mono"
            />
            <input
              type="text"
              value={value.azure_client_id}
              onChange={(e) => patch({ azure_client_id: e.target.value })}
              placeholder="App Client ID"
              className="input-industrial px-2 py-1 text-xs font-mono"
            />
            <input
              type="password"
              value={value.azure_client_secret}
              onChange={(e) => patch({ azure_client_secret: e.target.value })}
              placeholder="Client Secret"
              className="input-industrial px-2 py-1 text-xs font-mono"
            />
          </div>
        )}

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
    </div>
  );
};
