import React, { useEffect, useState } from 'react';
import {
  Cloud,
  Download,
  KeyRound,
  Play,
  Plus,
  ShieldCheck,
  Trash2,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import { CloudCatalog, CloudProfile, Organization, Scan } from '../types';
import { api } from '../services/api';
import { useI18n } from '../i18n/LanguageContext';
import { useToast } from './UIFeedback';

interface CloudSecurityViewProps {
  organizations: Organization[];
  selectedOrgId: string;
  scans: Scan[];
  onScanCreated: (scan: Scan) => void;
  onNavigateToScan: (scanId: string) => void;
  onRefreshData: () => void;
}

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low'];

export const CloudSecurityView: React.FC<CloudSecurityViewProps> = ({
  organizations,
  selectedOrgId,
  scans,
  onScanCreated,
  onNavigateToScan,
  onRefreshData,
}) => {
  const { L } = useI18n();
  const { showToast } = useToast();

  const [catalog, setCatalog] = useState<CloudCatalog | null>(null);
  const [profiles, setProfiles] = useState<CloudProfile[]>([]);
  const [installing, setInstalling] = useState<boolean>(false);
  const [launching, setLaunching] = useState<boolean>(false);
  const [savingProfile, setSavingProfile] = useState<boolean>(false);
  const [showSaveProfile, setShowSaveProfile] = useState<boolean>(false);
  const [profileName, setProfileName] = useState<string>('');

  const [orgId, setOrgId] = useState<string>(
    selectedOrgId && selectedOrgId !== 'ALL' ? selectedOrgId : organizations[0]?.id || ''
  );
  const [provider, setProvider] = useState<string>('aws');
  const [selectedProfileId, setSelectedProfileId] = useState<string>('');
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [region, setRegion] = useState<string>('eu-west-1');
  const [compliance, setCompliance] = useState<string>('');
  const [servicesInput, setServicesInput] = useState<string>('iam, s3, ec2, vpc');
  const [severities, setSeverities] = useState<string[]>(['critical', 'high', 'medium']);
  const [auditName, setAuditName] = useState<string>('Cloud Security Audit (AWS)');

  useEffect(() => {
    if (selectedOrgId && selectedOrgId !== 'ALL') {
      setOrgId(selectedOrgId);
    } else if (!orgId && organizations.length > 0) {
      setOrgId(organizations[0].id);
    }
  }, [selectedOrgId, organizations, orgId]);

  const loadCloudData = async () => {
    try {
      const [cat, profs] = await Promise.all([
        api.getCloudCatalog(),
        api.getCloudProfiles(orgId || undefined),
      ]);
      setCatalog(cat);
      setProfiles(profs);
    } catch (err: any) {
      showToast(err?.message || 'Errore caricamento Cloud Security', 'error');
    }
  };

  useEffect(() => {
    loadCloudData();
  }, [orgId]);

  const providerSpec = catalog?.providers?.[provider];
  const orgProfiles = profiles.filter((p) => p.provider === provider && (!orgId || p.org_id === orgId));
  const cloudScans = scans.filter(
    (s) => s.engines.includes('prowler') && (selectedOrgId === 'ALL' || s.org_id === selectedOrgId)
  );

  const handleProviderChange = (nextProv: string) => {
    setProvider(nextProv);
    setSelectedProfileId('');
    setCredentials({});
    const spec = catalog?.providers?.[nextProv];
    if (spec) {
      setRegion(spec.default_region || '');
      setServicesInput((spec.default_services || []).slice(0, 5).join(', '));
      setAuditName(`Cloud Security Audit (${spec.short})`);
      setCompliance('');
    }
  };

  const handleInstallProwler = async () => {
    setInstalling(true);
    try {
      const res = await api.installProwler();
      showToast(res.message || 'Prowler installato.', res.success ? 'success' : 'error');
      await loadCloudData();
      onRefreshData();
    } catch (err: any) {
      showToast(err?.message || 'Installazione Prowler fallita', 'error');
    } finally {
      setInstalling(false);
    }
  };

  const handleSaveProfile = async () => {
    if (!orgId) {
      showToast(L('Select an organization first.', 'Seleziona prima una organizzazione.'), 'error');
      return;
    }
    if (!profileName.trim()) {
      showToast(L('Enter a profile name.', 'Inserisci un nome per il profilo.'), 'error');
      return;
    }
    setSavingProfile(true);
    try {
      const created = await api.createCloudProfile({
        org_id: orgId,
        name: profileName.trim(),
        provider,
        credentials,
        region,
      });
      showToast(L('Encrypted cloud profile saved.', 'Profilo cloud cifrato salvato.'), 'success');
      setShowSaveProfile(false);
      setProfileName('');
      await loadCloudData();
      setSelectedProfileId(created.id);
      setCredentials({});
    } catch (err: any) {
      showToast(err?.message || 'Errore salvataggio profilo', 'error');
    } finally {
      setSavingProfile(false);
    }
  };

  const handleDeleteProfile = async (id: string) => {
    const ok = await api.deleteCloudProfile(id);
    if (ok) {
      if (selectedProfileId === id) setSelectedProfileId('');
      showToast(L('Cloud profile deleted.', 'Profilo cloud eliminato.'), 'info');
      await loadCloudData();
    }
  };

  const handleLaunchAudit = async () => {
    if (!orgId) {
      showToast(L('Select a target organization.', 'Seleziona organizzazione target.'), 'error');
      return;
    }
    setLaunching(true);
    try {
      const cleanServices = servicesInput
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const created = await api.launchCloudScan({
        org_id: orgId,
        name: auditName.trim() || `Cloud Security Audit (${provider.toUpperCase()})`,
        provider,
        profile_id: selectedProfileId || undefined,
        credentials: Object.keys(credentials).length > 0 ? credentials : undefined,
        region,
        compliance,
        services: cleanServices.length > 0 ? cleanServices : undefined,
        severities,
      });
      showToast(L('Cloud Security audit launched.', 'Audit Cloud Security avviato.'), 'success');
      onScanCreated(created);
    } catch (err: any) {
      showToast(err?.message || 'Errore avvio audit Cloud Security', 'error');
    } finally {
      setLaunching(false);
    }
  };

  const prowlerInstalled = Boolean(catalog?.engine?.installed);

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="card-industrial p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded bg-subtle border border-theme flex items-center justify-center text-theme-accent">
            <Cloud className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-theme-primary flex items-center space-x-2">
              <span>Cloud Security</span>
              <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-subtle border border-theme text-theme-accent">
                PROWLER CSPM
              </span>
            </h1>
            <p className="text-xs text-theme-secondary">
              {L(
                'Multi-cloud posture auditing & compliance checks (AWS, Azure, GCP, M365, Kubernetes, GitHub).',
                'Audit di postura multi-cloud e compliance (AWS, Azure, GCP, M365, Kubernetes, GitHub).'
              )}
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <div
            className={`px-2.5 py-1 rounded border text-xs font-mono flex items-center space-x-1.5 ${
              prowlerInstalled
                ? 'bg-emerald-950/30 border-emerald-700/60 text-emerald-400'
                : 'bg-amber-950/30 border-amber-700/60 text-amber-400'
            }`}
          >
            {prowlerInstalled ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
            <span>
              {prowlerInstalled
                ? `${L('Prowler Ready', 'Prowler Pronto')} (${catalog?.engine?.version || 'CLI'})`
                : L('Prowler Not Installed', 'Prowler Non Installato')}
            </span>
          </div>

          {!prowlerInstalled && (
            <button
              type="button"
              disabled={installing}
              onClick={handleInstallProwler}
              className="btn-primary px-3 py-1.5 text-xs font-semibold flex items-center space-x-1.5"
            >
              {installing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
              <span>{installing ? L('Installing...', 'Installazione...') : L('Install Prowler', 'Installa Prowler')}</span>
            </button>
          )}
        </div>
      </div>

      {/* Main 2-Column Studio */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left: Audit Configuration */}
        <div className="lg:col-span-7 space-y-4">
          <div className="card-industrial p-4 space-y-4">
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
            </div>

            {/* Cloud Provider Cards */}
            <div>
              <label className="text-[11px] font-semibold text-theme-secondary block mb-1.5">
                {L('Cloud Provider / Target Platform', 'Provider Cloud / Piattaforma')}
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {Object.values(catalog?.providers || {}).map((p) => {
                  const active = provider === p.id;
                  return (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => handleProviderChange(p.id)}
                      className={`p-2.5 rounded border text-left transition ${
                        active
                          ? 'row-selected-theme border-theme-accent text-theme-accent font-bold'
                          : 'bg-subtle border-theme text-theme-secondary hover:text-theme-primary'
                      }`}
                    >
                      <div className="text-xs font-mono font-bold">{p.short}</div>
                      <div className="text-[10px] opacity-80 truncate">{p.label}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Saved Cloud Profile Selector */}
            <div className="p-3 rounded bg-subtle border border-theme space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-bold text-theme-primary flex items-center space-x-1.5">
                  <KeyRound className="w-3.5 h-3.5 text-theme-accent" />
                  <span>{L('Credentials & Encrypted Profiles', 'Credenziali & Profili Cifrati')}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setShowSaveProfile((prev) => !prev)}
                  className="btn-secondary px-2 py-1 text-[11px] flex items-center space-x-1"
                >
                  <Plus className="w-3 h-3" />
                  <span>{L('Save Current Profile', 'Salva Profilo')}</span>
                </button>
              </div>

              {orgProfiles.length > 0 && (
                <div className="flex items-center space-x-2">
                  <select
                    value={selectedProfileId}
                    onChange={(e) => setSelectedProfileId(e.target.value)}
                    className="input-industrial flex-1 px-2.5 py-1.5 text-xs"
                  >
                    <option value="">
                      {L('-- Enter ephemeral credentials manually --', '-- Inserisci credenziali temporanee manuali --')}
                    </option>
                    {orgProfiles.map((prof) => (
                      <option key={prof.id} value={prof.id}>
                        {prof.name} ({prof.provider.toUpperCase()})
                      </option>
                    ))}
                  </select>
                  {selectedProfileId && (
                    <button
                      type="button"
                      onClick={() => handleDeleteProfile(selectedProfileId)}
                      className="btn-secondary p-1.5 text-red-400 hover:border-red-500/60"
                      title={L('Delete Profile', 'Elimina Profilo')}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              )}

              {showSaveProfile && (
                <div className="p-2.5 rounded bg-panel border border-theme flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={profileName}
                    onChange={(e) => setProfileName(e.target.value)}
                    placeholder={L('Profile name (e.g. Prod AWS ReadOnly)', 'Nome profilo (es. Prod AWS ReadOnly)')}
                    className="input-industrial flex-1 min-w-[180px] px-2.5 py-1 text-xs"
                  />
                  <button
                    type="button"
                    disabled={savingProfile}
                    onClick={handleSaveProfile}
                    className="btn-primary px-3 py-1 text-xs font-semibold"
                  >
                    {savingProfile ? L('Saving...', 'Salvataggio...') : L('Save Encrypted', 'Salva Cifrato')}
                  </button>
                </div>
              )}

              {!selectedProfileId && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                  {(providerSpec?.fields || []).map((f) => (
                    <div key={f.key} className={f.multiline ? 'sm:col-span-2' : ''}>
                      <label className="text-[10px] font-mono text-theme-muted block mb-1">{f.label}</label>
                      {f.multiline ? (
                        <textarea
                          rows={3}
                          value={credentials[f.key] || ''}
                          onChange={(e) => setCredentials((prev) => ({ ...prev, [f.key]: e.target.value }))}
                          placeholder={f.placeholder || ''}
                          className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                        />
                      ) : (
                        <input
                          type={f.secret ? 'password' : 'text'}
                          value={credentials[f.key] || ''}
                          onChange={(e) => setCredentials((prev) => ({ ...prev, [f.key]: e.target.value }))}
                          placeholder={f.placeholder || ''}
                          className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                        />
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Scope, Compliance, Severities */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                  {L('Compliance Framework', 'Framework Compliance')}
                </label>
                <select
                  value={compliance}
                  onChange={(e) => setCompliance(e.target.value)}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs"
                >
                  {(catalog?.compliances || [])
                    .filter((c) => !providerSpec || providerSpec.compliances.includes(c.id))
                    .map((c) => (
                      <option key={c.id || 'default'} value={c.id}>
                        {c.label}
                      </option>
                    ))}
                </select>
              </div>
              <div>
                <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                  {L('Region (AWS / optional)', 'Region (AWS / opzionale)')}
                </label>
                <input
                  type="text"
                  value={region}
                  onChange={(e) => setRegion(e.target.value)}
                  placeholder={provider === 'aws' ? 'eu-west-1' : L('Optional', 'Opzionale')}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                />
              </div>
            </div>

            <div>
              <label className="text-[11px] font-semibold text-theme-secondary block mb-1">
                {L('Services Filter (comma-separated, blank = all)', 'Filtro Servizi (separati da virgola, vuoto = tutti)')}
              </label>
              <input
                type="text"
                value={servicesInput}
                onChange={(e) => setServicesInput(e.target.value)}
                placeholder="iam, s3, ec2, vpc"
                className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
              />
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-[11px] font-semibold text-theme-secondary mr-1">
                  {L('Severities:', 'Severità:')}
                </span>
                {SEVERITY_OPTIONS.map((sev) => (
                  <label key={sev} className="inline-flex items-center space-x-1 cursor-pointer text-[11px] font-mono">
                    <input
                      type="checkbox"
                      checked={severities.includes(sev)}
                      onChange={(e) => {
                        setSeverities((prev) =>
                          e.target.checked ? [...prev, sev] : prev.filter((x) => x !== sev)
                        );
                      }}
                      className="rounded"
                    />
                    <span className="uppercase">{sev}</span>
                  </label>
                ))}
              </div>

              <button
                type="button"
                disabled={launching}
                onClick={handleLaunchAudit}
                className="btn-primary px-4 py-2 text-xs font-bold flex items-center space-x-2"
              >
                {launching ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>{launching ? L('Launching...', 'Avvio...') : L('Launch Cloud Audit', 'Avvia Cloud Audit')}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Right: Recent Cloud Security Audits */}
        <div className="lg:col-span-5 space-y-3">
          <div className="card-industrial p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-theme-subtle pb-2">
              <div className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-1.5">
                <ShieldCheck className="w-4 h-4 text-theme-accent" />
                <span>{L('Recent Cloud Security Audits', 'Audit Cloud Security Recenti')}</span>
              </div>
              <span className="text-[11px] font-mono text-theme-muted">{cloudScans.length}</span>
            </div>

            {cloudScans.length === 0 ? (
              <div className="py-10 text-center text-xs text-theme-muted space-y-1.5">
                <Cloud className="w-7 h-7 mx-auto opacity-40" />
                <div>
                  {L(
                    'No Cloud Security audits recorded yet for this organization.',
                    'Nessun audit Cloud Security registrato finora per questa organizzazione.'
                  )}
                </div>
              </div>
            ) : (
              <div className="space-y-2.5 max-h-[540px] overflow-y-auto pr-1">
                {cloudScans.map((s) => {
                  const cp = s.cloud_posture;
                  return (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => onNavigateToScan(s.id)}
                      className="w-full p-3 rounded bg-subtle border border-theme hover:border-theme-accent text-left transition space-y-1.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-theme-primary truncate">{s.name}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-panel border border-theme text-theme-accent uppercase shrink-0 flex items-center space-x-1">
                          <span>{s.status}</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-theme-muted truncate">{s.targets}</div>
                      {cp ? (
                        <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono pt-1">
                          <span className="px-1.5 py-0.5 rounded bg-emerald-950/40 border border-emerald-700/50 text-emerald-400">
                            PASS: {cp.passed}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-red-950/40 border border-red-700/50 text-red-400">
                            FAIL: {cp.failed}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-panel border border-theme text-theme-primary font-bold">
                            {cp.pass_rate.toFixed(1)}%
                          </span>
                        </div>
                      ) : (
                        <div className="text-[10px] font-mono text-theme-muted">
                          {L('Progress:', 'Avanzamento:')} {s.progress}%
                        </div>
                      )}
                    </button>
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
