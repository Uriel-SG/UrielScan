import React, { useState, useEffect } from 'react';
import { 
  Building2, 
  Settings, 
  Sparkles, 
  Cpu, 
  Upload, 
  Check, 
  Plus, 
  Trash2, 
  Edit3, 
  DownloadCloud, 
  Globe, 
  Mail, 
  CheckCircle2, 
  AlertCircle,
  RefreshCw,
  ShieldCheck,
  Lock,
  KeyRound,
  Copy,
  Loader2,
  Database,
  Radio,
  Server,
  Activity
} from 'lucide-react';
import { Organization, ScannerProfile, EngineStatus, AuthUser, RemoteAgent } from '../types';
import { api } from '../services/api';
import { useToast, ConfirmModal } from './UIFeedback';
import { useI18n } from '../i18n/LanguageContext';

interface SettingsAndOrgsProps {
  organizations: Organization[];
  scannerProfile: ScannerProfile;
  engineStatus: EngineStatus;
  onRefreshData: () => void;
  currentUser?: AuthUser | null;
  onUserUpdated?: (user: AuthUser) => void;
}

export const SettingsAndOrgs: React.FC<SettingsAndOrgsProps> = ({
  organizations,
  scannerProfile,
  engineStatus,
  onRefreshData,
  currentUser,
  onUserUpdated,
}) => {
  const { lang, locale, L } = useI18n();
  const { showToast } = useToast();
  const [activeSection, setActiveSection] = useState<'orgs' | 'branding' | 'ai' | 'engines' | 'security' | 'database' | 'probes'>('orgs');

  // Remote Probes state
  const [agents, setAgents] = useState<RemoteAgent[]>([]);
  const [isLoadingAgents, setIsLoadingAgents] = useState<boolean>(false);
  const [probeOrgId, setProbeOrgId] = useState<string>('');
  const [probeName, setProbeName] = useState<string>('');
  const [isCreatingProbe, setIsCreatingProbe] = useState<boolean>(false);
  const [newlyCreatedProbe, setNewlyCreatedProbe] = useState<RemoteAgent | null>(null);
  const [isDownloadingScript, setIsDownloadingScript] = useState<boolean>(false);
  const [copiedToken, setCopiedToken] = useState<boolean>(false);
  const [copiedCommand, setCopiedCommand] = useState<boolean>(false);

  // Client Org Form state
  const [editingOrg, setEditingOrg] = useState<Organization | null>(null);
  const [isCreatingOrg, setIsCreatingOrg] = useState<boolean>(false);
  const [orgName, setOrgName] = useState<string>('');
  const [orgEmail, setOrgEmail] = useState<string>('');
  const [orgIndustry, setOrgIndustry] = useState<string>('');
  const [orgScope, setOrgScope] = useState<string>('');
  const [orgNotes, setOrgNotes] = useState<string>('');
  const [orgLogoBase64, setOrgLogoBase64] = useState<string>('');

  // Scanner Profile state
  const [scannerName, setScannerName] = useState<string>(scannerProfile.company_name);
  const [scannerEmail, setScannerEmail] = useState<string>(scannerProfile.contact_email);
  const [scannerWebsite, setScannerWebsite] = useState<string>(scannerProfile.website);
  const [scannerFooter, setScannerFooter] = useState<string>(scannerProfile.report_footer);
  const [scannerLogoBase64, setScannerLogoBase64] = useState<string>(scannerProfile.logo_url || '');
  const [brandingSaved, setBrandingSaved] = useState<boolean>(false);

  // AI Configuration state
  const [aiProvider, setAiProvider] = useState<string>(scannerProfile.ai_provider);
  const [aiApiKey, setAiApiKey] = useState<string>(scannerProfile.ai_api_key || '');
  const [aiModel, setAiModel] = useState<string>(scannerProfile.ai_model);
  const [aiBaseUrl, setAiBaseUrl] = useState<string>(scannerProfile.ai_base_url || '');
  const [isTestingAI, setIsTestingAI] = useState<boolean>(false);
  const [aiTestResult, setAiTestResult] = useState<{ success: boolean; message: string } | null>(null);

  // Nuclei auto-installer state
  const [isInstallingNuclei, setIsInstallingNuclei] = useState<boolean>(false);
  const [nucleiInstallResult, setNucleiInstallResult] = useState<string | null>(null);

  // Security & 2FA State
  const [twoFactorEnabled, setTwoFactorEnabled] = useState<boolean>(Boolean(currentUser?.two_factor_enabled));
  const [setupData, setSetupData] = useState<{ secret: string; otpauth_uri: string; qr_svg: string } | null>(null);
  const [totpVerifyCode, setTotpVerifyCode] = useState<string>('');
  const [isSettingUp2FA, setIsSettingUp2FA] = useState<boolean>(false);
  const [disablePassword, setDisablePassword] = useState<string>('');
  const [currentPassword, setCurrentPassword] = useState<string>('');
  const [newPassword, setNewPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [isChangingPassword, setIsChangingPassword] = useState<boolean>(false);
  const [isCopiedSecret, setIsCopiedSecret] = useState<boolean>(false);

  // Modal confirm states
  const [confirmModal, setConfirmModal] = useState<{
    isOpen: boolean;
    title: string;
    description: string;
    confirmText: string;
    isDestructive: boolean;
    action: () => Promise<void>;
  }>({
    isOpen: false,
    title: '',
    description: '',
    confirmText: L('Confirm', 'Conferma'),
    isDestructive: true,
    action: async () => {},
  });
  const [isModalLoading, setIsModalLoading] = useState<boolean>(false);

  // Fetch current user 2FA status on mount & probes
  useEffect(() => {
    api.getAuthMe().then((res) => {
      setTwoFactorEnabled(res.user.two_factor_enabled);
      if (onUserUpdated) onUserUpdated(res.user);
    }).catch(() => {});
  }, [onUserUpdated]);

  const fetchAgents = async () => {
    setIsLoadingAgents(true);
    try {
      const data = await api.getAgents();
      setAgents(data);
    } catch (err) {
      console.warn('Errore recupero sonde remote:', err);
    } finally {
      setIsLoadingAgents(false);
    }
  };

  useEffect(() => {
    fetchAgents();
  }, []);

  const handleCreateProbe = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!probeName.trim()) {
      showToast(L('Please enter a probe name.', 'Inserisci un nome per la sonda.'), 'warning');
      return;
    }
    const targetOrgId = probeOrgId || organizations[0]?.id;
    if (!targetOrgId) {
      showToast(L('Please select an organization first.', 'Seleziona prima un\'organizzazione.'), 'warning');
      return;
    }
    setIsCreatingProbe(true);
    try {
      const created = await api.createAgent({ org_id: targetOrgId, name: probeName.trim() });
      setNewlyCreatedProbe(created);
      setProbeName('');
      showToast(L(`Probe "${created.name}" created successfully.`, `Sonda "${created.name}" creata con successo.`), 'success');
      await fetchAgents();
    } catch (err: any) {
      showToast(err.message || L('Failed to create probe.', 'Creazione sonda fallita.'), 'error');
    } finally {
      setIsCreatingProbe(false);
    }
  };

  const handleDownloadProbeScript = async () => {
    setIsDownloadingScript(true);
    try {
      await api.downloadProbeScript();
      showToast(L('urielscan_probe.py downloaded successfully.', 'urielscan_probe.py scaricato con successo.'), 'success');
    } catch (err: any) {
      showToast(err.message || L('Failed to download probe script.', 'Impossibile scaricare urielscan_probe.py.'), 'error');
    } finally {
      setIsDownloadingScript(false);
    }
  };

  const promptDeleteProbe = (agent: RemoteAgent) => {
    setConfirmModal({
      isOpen: true,
      title: L(`Revoke Probe "${agent.name}"`, `Revoca Sonda "${agent.name}"`),
      description: L(
        `Are you sure you want to revoke and delete probe "${agent.name}"? It will no longer be able to poll or execute scans.`,
        `Sei sicuro di voler revocare ed eliminare la sonda "${agent.name}"? Non potrà più eseguire il polling né ricevere scansioni.`
      ),
      confirmText: L('Revoke Probe', 'Revoca Sonda'),
      isDestructive: true,
      action: async () => {
        await api.deleteAgent(agent.id);
        showToast(L(`Probe "${agent.name}" revoked.`, `Sonda "${agent.name}" revocata.`), 'info');
        await fetchAgents();
      },
    });
  };

  // Logo upload helper (converts to base64 Data URI)
  const handleLogoUpload = (e: React.ChangeEvent<HTMLInputElement>, target: 'org' | 'scanner') => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        const base64 = reader.result as string;
        if (target === 'org') {
          setOrgLogoBase64(base64);
        } else {
          setScannerLogoBase64(base64);
        }
      };
      reader.readAsDataURL(file);
    }
  };

  // Save Org
  const handleSaveOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (editingOrg) {
        await api.updateOrganization(editingOrg.id, {
          name: orgName,
          contact_email: orgEmail,
          industry: orgIndustry,
          target_scope: orgScope,
          notes: orgNotes,
          logo_url: orgLogoBase64 || editingOrg.logo_url,
        });
        showToast(L(`Organization "${orgName}" updated.`, `Organizzazione "${orgName}" aggiornata.`), 'success');
        setEditingOrg(null);
      } else {
        await api.createOrganization({
          name: orgName,
          contact_email: orgEmail,
          industry: orgIndustry,
          target_scope: orgScope,
          notes: orgNotes,
          logo_url: orgLogoBase64,
        });
        showToast(L(`New organization "${orgName}" registered.`, `Nuova organizzazione "${orgName}" registrata.`), 'success');
        setIsCreatingOrg(false);
      }
      setOrgName('');
      setOrgEmail('');
      setOrgIndustry('');
      setOrgScope('');
      setOrgNotes('');
      setOrgLogoBase64('');
      onRefreshData();
    } catch (err: any) {
      showToast(err.message || L('Error saving organization.', 'Errore salvataggio organizzazione.'), 'error');
    }
  };

  // Delete Org with custom modal
  const promptDeleteOrg = (org: Organization) => {
    setConfirmModal({
      isOpen: true,
      title: L(`Delete Organization "${org.name}"`, `Elimina Organizzazione "${org.name}"`),
      description: L(
        'WARNING: This action will remove the client organization and all associated scans, findings, and reports.',
        "ATTENZIONE: Questa azione rimuoverà l'organizzazione cliente e tutte le scansioni, i finding e i report ad essa collegati."
      ),
      confirmText: L('Delete Organization', 'Elimina Organizzazione'),
      isDestructive: true,
      action: async () => {
        await api.deleteOrganization(org.id);
        showToast(L(`Organization "${org.name}" deleted.`, `Organizzazione "${org.name}" eliminata.`), 'info');
        onRefreshData();
      },
    });
  };

  const startEditOrg = (org: Organization) => {
    setEditingOrg(org);
    setOrgName(org.name);
    setOrgEmail(org.contact_email);
    setOrgIndustry(org.industry);
    setOrgScope(org.target_scope);
    setOrgNotes(org.notes || '');
    setOrgLogoBase64(org.logo_url || '');
    setIsCreatingOrg(true);
  };

  // Save Branding
  const handleSaveBranding = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.updateScannerProfile({
        company_name: scannerName,
        contact_email: scannerEmail,
        website: scannerWebsite,
        report_footer: scannerFooter,
        logo_url: scannerLogoBase64,
      });
      setBrandingSaved(true);
      showToast(L('Company profile saved.', 'Profilo aziendale salvato.'), 'success');
      setTimeout(() => setBrandingSaved(false), 2500);
      onRefreshData();
    } catch (err: any) {
      showToast(err.message || L('Error saving branding.', 'Errore salvataggio branding.'), 'error');
    }
  };

  // Save AI Config & Test
  const handleSaveAIConfig = async () => {
    try {
      await api.updateScannerProfile({
        ai_provider: aiProvider as any,
        ai_api_key: aiApiKey,
        ai_model: aiModel,
        ai_base_url: aiBaseUrl,
      });
      showToast(L('AI engine configuration saved.', 'Configurazione motore AI salvata.'), 'success');
      onRefreshData();
    } catch (err: any) {
      showToast(err.message || L('Error saving AI config.', 'Errore salvataggio AI.'), 'error');
    }
  };

  const handleTestAI = async () => {
    setIsTestingAI(true);
    setAiTestResult(null);
    try {
      const result = await api.testAIConnection({
        provider: aiProvider,
        api_key: aiApiKey,
        model: aiModel,
        base_url: aiBaseUrl,
      });
      setAiTestResult(result);
      if (result.success) {
        showToast(L('AI connection verified successfully.', 'Connessione AI verificata con successo.'), 'success');
      } else {
        showToast(result.message || L('AI test failed.', 'Test AI non riuscito.'), 'warning');
      }
    } catch (err: any) {
      const msg = err.message || L('Connection error to AI provider.', 'Errore di connessione al provider AI.');
      setAiTestResult({ success: false, message: msg });
      showToast(msg, 'error');
    } finally {
      setIsTestingAI(false);
    }
  };

  // Auto-install Nuclei
  const handleInstallNuclei = async () => {
    setIsInstallingNuclei(true);
    setNucleiInstallResult(null);
    try {
      const res = await api.installNuclei();
      setNucleiInstallResult(res.message);
      showToast(res.message, 'success');
      onRefreshData();
    } catch (err: any) {
      setNucleiInstallResult(L('Installation failed.', 'Installazione fallita.'));
      showToast(err.message || L('Error installing Nuclei.', 'Errore installazione Nuclei.'), 'error');
    } finally {
      setIsInstallingNuclei(false);
    }
  };

  // 2FA Setup Flow
  const handleStart2FASetup = async () => {
    setIsSettingUp2FA(true);
    try {
      const res = await api.setup2FA();
      setSetupData(res);
      showToast(L('2FA QR Code generated. Scan it with your authenticator app.', 'QR Code 2FA generato. Scansionalo con la tua app.'), 'info');
    } catch (err: any) {
      showToast(err.message || L('Unable to configure 2FA.', 'Impossibile configurare 2FA.'), 'error');
    } finally {
      setIsSettingUp2FA(false);
    }
  };

  const handleConfirm2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpVerifyCode || totpVerifyCode.trim().length !== 6) {
      showToast(L('Enter the 6-digit code.', 'Inserisci il codice a 6 cifre.'), 'warning');
      return;
    }
    try {
      await api.enable2FA(totpVerifyCode.trim());
      setTwoFactorEnabled(true);
      setSetupData(null);
      setTotpVerifyCode('');
      showToast(L('Two-factor authentication successfully enabled!', 'Autenticazione a due fattori attivata con successo!'), 'success', L('2FA Protected', '2FA Protetto'));
      const updated = await api.getAuthMe();
      if (onUserUpdated) onUserUpdated(updated.user);
    } catch (err: any) {
      showToast(err.message || L('Incorrect code. Please try again.', 'Codice errato. Riprova.'), 'error');
    }
  };

  const handleDisable2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!disablePassword) {
      showToast(L('Enter administrator password to disable 2FA.', 'Inserisci la password amministratore per disattivare il 2FA.'), 'warning');
      return;
    }
    try {
      await api.disable2FA(disablePassword);
      setTwoFactorEnabled(false);
      setDisablePassword('');
      showToast(L('Two-factor authentication disabled.', 'Autenticazione a due fattori disabilitata.'), 'info');
      const updated = await api.getAuthMe();
      if (onUserUpdated) onUserUpdated(updated.user);
    } catch (err: any) {
      showToast(err.message || L('Incorrect password.', 'Password non corretta.'), 'error');
    }
  };

  // Change Password
  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentPassword || !newPassword) {
      showToast(L('Please fill in all password fields.', 'Compila tutti i campi password.'), 'warning');
      return;
    }
    if (newPassword !== confirmPassword) {
      showToast(L('Passwords do not match.', 'Le due password non corrispondono.'), 'warning');
      return;
    }
    setIsChangingPassword(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      showToast(L('Password updated successfully.', 'Password aggiornata con successo.'), 'success');
    } catch (err: any) {
      showToast(err.message || L('Error changing password.', 'Errore cambio password.'), 'error');
    } finally {
      setIsChangingPassword(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="card-industrial p-4 flex flex-col md:flex-row md:items-center justify-between gap-2">
        <div>
          <div className="flex items-center space-x-2 text-[11px] uppercase font-bold tracking-wider text-theme-accent">
            <Settings className="w-3.5 h-3.5" />
            <span>{L('Platform & Administration', 'Piattaforma & Amministrazione')}</span>
          </div>
          <h1 className="text-base font-bold text-theme-primary mt-0.5 tracking-tight">
            {L('Global Settings, Security & Tenants', 'Impostazioni Globali, Sicurezza & Tenant')}
          </h1>
          <p className="text-xs text-theme-secondary mt-0.5">
            {L(
              'Manage client perimeters, MSSP white-labeling, 2FA TOTP authentication, and database maintenance.',
              'Gestisci perimetri clienti, white-label MSSP, autenticazione 2FA TOTP e manutenzione del database.'
            )}
          </p>
        </div>
      </div>

      {/* Navigation tabs */}
      <div className="flex items-center space-x-1.5 border-b border-theme pb-2 overflow-x-auto text-xs">
        {[
          { id: 'orgs', label: L('Client Organizations', 'Organizzazioni Clienti'), icon: Building2 },
          { id: 'probes', label: L('Remote Probes', 'Sonde Remote'), icon: Radio },
          { id: 'branding', label: L('MSSP Branding', 'Branding MSSP'), icon: Globe },
          { id: 'ai', label: L('AI Configuration', 'Configurazione AI'), icon: Sparkles },
          { id: 'engines', label: L('Engines & Nuclei', 'Motori & Nuclei'), icon: Cpu },
          { id: 'security', label: L('Admin Security & 2FA', 'Sicurezza & 2FA Admin'), icon: Lock },
          { id: 'database', label: L('Data Management & Reset', 'Gestione Dati & Reset'), icon: Database },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSection === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSection(tab.id as any)}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs font-semibold border transition ${
                isActive
                  ? 'border-theme-accent bg-subtle text-theme-primary'
                  : 'border-transparent text-theme-muted hover:text-theme-primary'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* SECTION 1: ORGANIZATIONS */}
      {activeSection === 'orgs' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
              {L(`Client Tenant Portfolio (${organizations.length})`, `Portafoglio Tenant Clienti (${organizations.length})`)}
            </h2>
            <button
              onClick={() => {
                setEditingOrg(null);
                setOrgName('');
                setOrgEmail('');
                setOrgIndustry('');
                setOrgScope('');
                setOrgNotes('');
                setOrgLogoBase64('');
                setIsCreatingOrg(!isCreatingOrg);
              }}
              className="btn-primary flex items-center space-x-1 px-3 py-1.5 text-xs font-semibold"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{isCreatingOrg ? L('Close Form', 'Chiudi Form') : L('Add Organization', 'Aggiungi Organizzazione')}</span>
            </button>
          </div>

          {isCreatingOrg && (
            <form onSubmit={handleSaveOrg} className="card-industrial p-4 space-y-3">
              <h3 className="text-xs font-bold text-theme-primary">
                {editingOrg ? L(`Edit Organization #${editingOrg.id}`, `Modifica Organizzazione #${editingOrg.id}`) : L('New Client Organization', 'Nuova Organizzazione Cliente')}
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-theme-secondary mb-1">
                    {L('Company Name / Client Name *', 'Ragione Sociale / Nome Cliente *')}
                  </label>
                  <input
                    type="text"
                    required
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                    placeholder={L('e.g. Acme Corporation LLC', 'es. Acme Corporation S.r.l.')}
                    className="input-industrial w-full px-2.5 py-1.5 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-theme-secondary mb-1">
                    {L('Contact Email / CISO *', 'Email Contatto / CISO *')}
                  </label>
                  <input
                    type="email"
                    required
                    value={orgEmail}
                    onChange={(e) => setOrgEmail(e.target.value)}
                    placeholder="security@acme.it"
                    className="input-industrial w-full px-2.5 py-1.5 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-theme-secondary mb-1">
                    {L('Industry Sector', 'Settore Industriale')}
                  </label>
                  <input
                    type="text"
                    value={orgIndustry}
                    onChange={(e) => setOrgIndustry(e.target.value)}
                    placeholder={L('Fintech, Healthcare, Industry 4.0...', 'Fintech, Sanità, Industria 4.0...')}
                    className="input-industrial w-full px-2.5 py-1.5 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-theme-secondary mb-1">
                    {L('Default Target Scope (CIDR / Domains)', 'Target Scope Predefinito (CIDR / Domini)')}
                  </label>
                  <input
                    type="text"
                    value={orgScope}
                    onChange={(e) => setOrgScope(e.target.value)}
                    placeholder="192.168.0.0/24, api.acme.it"
                    className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-xs font-medium text-theme-secondary mb-1">
                    {L('Operational Notes / Compliance', 'Note Operative / Conformità')}
                  </label>
                  <textarea
                    rows={2}
                    value={orgNotes}
                    onChange={(e) => setOrgNotes(e.target.value)}
                    placeholder={L('PCI-DSS, authorized scope, SOC escalation contacts...', 'PCI-DSS, perimetro autorizzato, contatti SOC di escalation...')}
                    className="input-industrial w-full px-2.5 py-1.5 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-theme-secondary mb-1">
                    {L('Company Logo (File or SVG)', 'Logo Aziendale (File o SVG)')}
                  </label>
                  <input
                    type="file"
                    accept="image/*"
                    onChange={(e) => handleLogoUpload(e, 'org')}
                    className="text-xs text-theme-secondary file:mr-2 file:py-1 file:px-2 file:rounded file:border file:border-theme file:text-xs file:bg-subtle file:text-theme-primary cursor-pointer"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-2 border-t border-theme-subtle">
                <button
                  type="button"
                  onClick={() => setIsCreatingOrg(false)}
                  className="btn-secondary px-3 py-1.5 text-xs"
                >
                  {L('Cancel', 'Annulla')}
                </button>
                <button
                  type="submit"
                  className="btn-primary px-3 py-1.5 text-xs font-semibold"
                >
                  {editingOrg ? L('Save Changes', 'Salva Modifiche') : L('Register Organization', 'Registra Organizzazione')}
                </button>
              </div>
            </form>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {organizations.map((org) => (
              <div key={org.id} className="card-industrial p-3.5 flex flex-col justify-between">
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div className="flex items-center space-x-2">
                      {org.logo_url ? (
                        <img src={org.logo_url} alt="" className="w-7 h-7 object-contain rounded border border-theme bg-subtle" />
                      ) : (
                        <div className="w-7 h-7 rounded border border-theme bg-subtle flex items-center justify-center text-theme-accent">
                          <Building2 className="w-4 h-4" />
                        </div>
                      )}
                      <div>
                        <div className="font-bold text-xs text-theme-primary tracking-tight">{org.name}</div>
                        <div className="text-[10px] text-theme-muted font-mono">{org.industry}</div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-1">
                      <button
                        onClick={() => startEditOrg(org)}
                        className="btn-secondary p-1 text-theme-secondary hover:text-theme-primary"
                        title={L('Edit', 'Modifica')}
                      >
                        <Edit3 className="w-3 h-3" />
                      </button>
                      <button
                        onClick={() => promptDeleteOrg(org)}
                        className="btn-secondary p-1 text-red-400 hover:text-red-300"
                        title={L('Delete', 'Elimina')}
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                  <div className="text-[11px] text-theme-secondary space-y-1 pt-1">
                    <div className="font-mono text-[10px] text-theme-muted truncate">Scope: {org.target_scope}</div>
                    <div className="text-[10px] text-theme-muted truncate">Email: {org.contact_email}</div>
                  </div>
                </div>
                <div className="flex items-center justify-between pt-2.5 mt-2 border-t border-theme-subtle text-[10px] font-mono text-theme-secondary">
                  <span>{org.scans_count || 0} {L('scans', 'scansioni')}</span>
                  <span className="text-red-400 font-bold">{org.open_vulns_count || 0} {L('vulns', 'vulns')}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SECTION 2: BRANDING */}
      {activeSection === 'branding' && (
        <form onSubmit={handleSaveBranding} className="card-industrial p-4 space-y-4 max-w-2xl">
          <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
            {L('MSSP White-Label Customization', 'Personalizzazione White-Label MSSP')}
          </h2>
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('Cybersecurity Firm / MSSP Name', 'Nome Società di Cybersecurity / MSSP')}
              </label>
              <input
                type="text"
                value={scannerName}
                onChange={(e) => setScannerName(e.target.value)}
                className="input-industrial w-full px-2.5 py-1.5 text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('SOC Operations Email', 'Email Operazioni SOC')}
              </label>
              <input
                type="email"
                value={scannerEmail}
                onChange={(e) => setScannerEmail(e.target.value)}
                className="input-industrial w-full px-2.5 py-1.5 text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('Corporate Website', 'Sito Web Istituzionale')}
              </label>
              <input
                type="text"
                value={scannerWebsite}
                onChange={(e) => setScannerWebsite(e.target.value)}
                className="input-industrial w-full px-2.5 py-1.5 text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('Confidential Report Footer', 'Footer Report Riservati')}
              </label>
              <textarea
                rows={2}
                value={scannerFooter}
                onChange={(e) => setScannerFooter(e.target.value)}
                className="input-industrial w-full px-2.5 py-1.5 text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('MSSP Logo', 'Logo MSSP')}
              </label>
              <input
                type="file"
                accept="image/*"
                onChange={(e) => handleLogoUpload(e, 'scanner')}
                className="text-xs text-theme-secondary file:mr-2 file:py-1 file:px-2 file:rounded file:border file:border-theme file:text-xs file:bg-subtle file:text-theme-primary cursor-pointer"
              />
            </div>
          </div>
          <div className="flex justify-end pt-2 border-t border-theme-subtle">
            <button type="submit" className="btn-primary px-4 py-1.5 text-xs font-semibold">
              {brandingSaved ? L('Saved!', 'Salvato!') : L('Save Branding Settings', 'Salva Impostazioni Branding')}
            </button>
          </div>
        </form>
      )}

      {/* SECTION 3: AI CONFIG */}
      {activeSection === 'ai' && (
        <div className="card-industrial p-4 space-y-4 max-w-2xl">
          <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
            {L('AI Purple Team Engine Configuration', 'Configurazione Motore AI Purple Team')}
          </h2>
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('AI Provider', 'Provider AI')}
              </label>
              <select
                value={aiProvider}
                onChange={(e) => setAiProvider(e.target.value)}
                className="input-industrial w-full px-2.5 py-1.5 text-xs"
              >
                <option value="gemini" className="bg-panel text-theme-primary">{L('Google Gemini (Recommended)', 'Google Gemini (Consigliato)')}</option>
                <option value="openai" className="bg-panel text-theme-primary">OpenAI</option>
                <option value="anthropic" className="bg-panel text-theme-primary">Anthropic Claude</option>
                <option value="ollama" className="bg-panel text-theme-primary">{L('Ollama (Local Offline)', 'Ollama (Locale Offline)')}</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                API Key
              </label>
              <input
                type="password"
                value={aiApiKey}
                onChange={(e) => setAiApiKey(e.target.value)}
                placeholder="sk-..."
                className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-theme-secondary mb-1">
                {L('Model', 'Modello')}
              </label>
              <input
                type="text"
                value={aiModel}
                onChange={(e) => setAiModel(e.target.value)}
                placeholder="gemini-2.5-flash / gpt-4o / claude-3-7-sonnet"
                className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
              />
            </div>
            {aiProvider === 'ollama' && (
              <div>
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  Base URL Ollama
                </label>
                <input
                  type="text"
                  value={aiBaseUrl}
                  onChange={(e) => setAiBaseUrl(e.target.value)}
                  placeholder="http://localhost:11434/v1"
                  className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                />
              </div>
            )}
          </div>

          {aiTestResult && (
            <div className={`p-2.5 rounded border text-xs flex items-center gap-2 ${aiTestResult.success ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-400' : 'bg-red-950/20 border-red-500/40 text-red-400'}`}>
              {aiTestResult.success ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <AlertCircle className="w-4 h-4 shrink-0" />}
              <span>{aiTestResult.message}</span>
            </div>
          )}

          <div className="flex justify-between items-center pt-2 border-t border-theme-subtle">
            <button
              type="button"
              onClick={handleTestAI}
              disabled={isTestingAI}
              className="btn-secondary px-3 py-1.5 text-xs font-medium flex items-center space-x-1.5"
            >
              {isTestingAI && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              <span>{isTestingAI ? L('Testing...', 'Test in corso...') : L('Test Connection', 'Testa Connessione')}</span>
            </button>
            <button
              type="button"
              onClick={handleSaveAIConfig}
              className="btn-primary px-4 py-1.5 text-xs font-semibold"
            >
              {L('Save Configuration', 'Salva Configurazione')}
            </button>
          </div>
        </div>
      )}

      {/* SECTION 4: ENGINES */}
      {activeSection === 'engines' && (
        <div className="space-y-4 max-w-2xl">
          <div className="card-industrial p-4 space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
              {L('Scanning Engines Status', 'Stato Motori di Scansione')}
            </h2>
            <div className="space-y-2">
              <div className="p-3 rounded border border-theme bg-subtle flex items-center justify-between">
                <div>
                  <div className="text-xs font-bold text-theme-primary">Nmap Engine</div>
                  <div className="text-[11px] text-theme-secondary">
                    {L('Version:', 'Versione:')} {engineStatus.nmap.version || L('Detected', 'Rilevato')} • {engineStatus.nmap.scripts_count} {L('NSE scripts', 'script NSE')}
                  </div>
                </div>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${engineStatus.nmap.available ? 'bg-emerald-950/30 border-emerald-600 text-emerald-400' : 'bg-red-950/30 border-red-600 text-red-400'}`}>
                  {engineStatus.nmap.available ? L('AVAILABLE', 'DISPONIBILE') : L('NOT FOUND', 'NON TROVATO')}
                </span>
              </div>

              <div className="p-3 rounded border border-theme bg-subtle flex items-center justify-between">
                <div>
                  <div className="text-xs font-bold text-theme-primary">Nuclei Template Engine</div>
                  <div className="text-[11px] text-theme-secondary">
                    {L('Version:', 'Versione:')} {engineStatus.nuclei.version || L('Not installed', 'Non installato')}
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${engineStatus.nuclei.available ? 'bg-emerald-950/30 border-emerald-600 text-emerald-400' : 'bg-amber-950/30 border-amber-600 text-amber-400'}`}>
                    {engineStatus.nuclei.available ? L('ACTIVE', 'ATTIVO') : L('NOT CONFIGURED', 'NON CONFIGURATO')}
                  </span>
                  {!engineStatus.nuclei.available && (
                    <button
                      onClick={handleInstallNuclei}
                      disabled={isInstallingNuclei}
                      className="btn-primary px-2.5 py-1 text-xs"
                    >
                      {isInstallingNuclei ? L('Installing...', 'Installazione...') : L('Download Nuclei', 'Scarica Nuclei')}
                    </button>
                  )}
                </div>
              </div>
            </div>
            {nucleiInstallResult && (
              <div className="p-2 rounded bg-subtle text-xs font-mono text-theme-secondary border border-theme">
                {nucleiInstallResult}
              </div>
            )}
          </div>
        </div>
      )}

      {/* SECTION 5: SECURITY & 2FA ADMIN */}
      {activeSection === 'security' && (
        <div className="space-y-4 max-w-2xl">
          {/* 2FA Card */}
          <div className="card-industrial p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-theme-subtle pb-2">
              <div>
                <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-2">
                  <Lock className="w-3.5 h-3.5 text-theme-accent" />
                  <span>{L('Two-Factor Authentication (2FA TOTP RFC 6238)', 'Autenticazione a Due Fattori (2FA TOTP RFC 6238)')}</span>
                </h2>
                <p className="text-xs text-theme-muted mt-0.5">
                  {L(
                    'Protect administrator access by requiring a time-based code generated in Google Authenticator, Authy, or Microsoft Authenticator.',
                    "Proteggi l'accesso amministratore richiedendo un codice temporaneo generato su Google Authenticator, Authy o Microsoft Authenticator."
                  )}
                </p>
              </div>
              <div>
                <span className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${twoFactorEnabled ? 'bg-emerald-950/30 border-emerald-600 text-emerald-400' : 'bg-subtle border-theme text-theme-muted'}`}>
                  {twoFactorEnabled ? L('2FA ACTIVE', '2FA ATTIVO') : L('DISABLED', 'DISATTIVATO')}
                </span>
              </div>
            </div>

            {!twoFactorEnabled ? (
              <div className="space-y-4 pt-1">
                {!setupData ? (
                  <div>
                    <button
                      type="button"
                      onClick={handleStart2FASetup}
                      disabled={isSettingUp2FA}
                      className="btn-primary flex items-center space-x-2 px-3.5 py-2 text-xs font-semibold"
                    >
                      {isSettingUp2FA ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
                      <span>{L('Configure Authenticator App (2FA TOTP)', 'Configura App di Autenticazione (2FA TOTP)')}</span>
                    </button>
                  </div>
                ) : (
                  <div className="p-4 rounded border border-theme bg-subtle space-y-4">
                    <div className="text-xs font-bold text-theme-primary">
                      {L('1. Scan the QR Code with your authenticator app:', '1. Scansiona il QR Code con la tua app di autenticazione:')}
                    </div>

                    <div className="flex flex-col sm:flex-row items-center gap-4">
                      {/* SVG or Data-URI QR Code */}
                      <div className="w-44 h-44 p-2 bg-white rounded border border-theme shrink-0 flex items-center justify-center">
                        {setupData.qr_svg.startsWith('data:') ? (
                          <img src={setupData.qr_svg} alt="QR Code 2FA" className="w-full h-full object-contain" />
                        ) : (
                          <div 
                            dangerouslySetInnerHTML={{ __html: setupData.qr_svg }} 
                            className="w-full h-full flex items-center justify-center [&>svg]:w-full [&>svg]:h-full"
                          />
                        )}
                      </div>

                      <div className="space-y-2 text-xs">
                        <p className="text-theme-secondary leading-relaxed">
                          {L(
                            'If you cannot scan the QR code, enter the secret Base32 key manually:',
                            'Se non puoi scansionare il codice QR, inserisci manualmente la chiave Base32 segreta:'
                          )}
                        </p>
                        <div className="flex items-center space-x-2">
                          <code className="p-1.5 rounded bg-panel border border-theme text-theme-primary font-mono text-xs select-all">
                            {setupData.secret}
                          </code>
                          <button
                            type="button"
                            onClick={() => {
                              navigator.clipboard.writeText(setupData.secret);
                              setIsCopiedSecret(true);
                              setTimeout(() => setIsCopiedSecret(false), 2000);
                              showToast(L('Base32 key copied.', 'Chiave Base32 copiata.'), 'info');
                            }}
                            className="btn-secondary p-1.5"
                            title={L('Copy key', 'Copia chiave')}
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        {isCopiedSecret && <span className="text-[10px] text-emerald-400 font-mono">{L('Copied!', 'Copiata!')}</span>}
                      </div>
                    </div>

                    <form onSubmit={handleConfirm2FA} className="pt-2 border-t border-theme-subtle space-y-2">
                      <label className="block text-xs font-semibold text-theme-primary">
                        {L("2. Enter the 6-digit code to confirm activation:", "2. Inserisci il codice a 6 cifre per confermare l'attivazione:")}
                      </label>
                      <div className="flex items-center space-x-2 max-w-xs">
                        <input
                          type="text"
                          maxLength={6}
                          value={totpVerifyCode}
                          onChange={(e) => setTotpVerifyCode(e.target.value.replace(/\D/g, ''))}
                          placeholder="000000"
                          className="input-industrial px-3 py-1.5 text-center font-mono text-sm tracking-wider w-36"
                          required
                        />
                        <button type="submit" className="btn-primary px-3 py-1.5 text-xs font-semibold">
                          {L('Enable 2FA', 'Attiva 2FA')}
                        </button>
                      </div>
                    </form>
                  </div>
                )}
              </div>
            ) : (
              <form onSubmit={handleDisable2FA} className="space-y-3 pt-2">
                <p className="text-xs text-theme-secondary">
                  {L(
                    "Your account is currently protected with 2FA TOTP. To disable it, enter the current administrator password:",
                    "Il tuo account è attualmente protetto con 2FA TOTP. Per disattivarlo, inserisci la password corrente dell'amministratore:"
                  )}
                </p>
                <div className="flex items-center space-x-2 max-w-sm">
                  <input
                    type="password"
                    value={disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    placeholder={L('Administrator Password', 'Password Amministratore')}
                    className="input-industrial px-3 py-1.5 text-xs flex-1"
                    required
                  />
                  <button
                    type="submit"
                    className="px-3 py-1.5 text-xs font-semibold bg-red-600 hover:bg-red-700 text-white rounded"
                  >
                    {L('Disable 2FA', 'Disabilita 2FA')}
                  </button>
                </div>
              </form>
            )}
          </div>

          {/* Change Password Card */}
          <form onSubmit={handleChangePassword} className="card-industrial p-4 space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-2">
              <KeyRound className="w-3.5 h-3.5 text-theme-accent" />
              <span>{L('Change Operator Account Password', 'Cambio Password Account Operatore')}</span>
            </h2>

            <div className="space-y-2.5 max-w-sm">
              <div>
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  {L('Current Password', 'Password Attuale')}
                </label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="••••••••"
                  className="input-industrial w-full px-2.5 py-1.5 text-xs"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  {L('New Password', 'Nuova Password')}
                </label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder={L('New secure password', 'Nuova password sicura')}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  {L('Confirm New Password', 'Conferma Nuova Password')}
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder={L('Repeat new password', 'Ripeti nuova password')}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs"
                  required
                />
              </div>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={isChangingPassword}
                className="btn-primary px-4 py-1.5 text-xs font-semibold"
              >
                {isChangingPassword ? L('Saving...', 'Salvataggio...') : L('Update Password', 'Aggiorna Password')}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* SECTION 6: DATABASE & RESET */}
      {activeSection === 'database' && (
        <div className="card-industrial p-4 space-y-4 max-w-2xl">
          <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-2">
            <Database className="w-3.5 h-3.5 text-theme-accent" />
            <span>{L('Data Management, Maintenance & Reset', 'Gestione Dati, Manutenzione & Reset')}</span>
          </h2>

          <p className="text-xs text-theme-secondary leading-relaxed">
            {L(
              'These options allow you to clear operational scan data or restore demo sample datasets without native browser dialogs.',
              'Queste opzioni consentono di azzerare i dati operativi di scansione o ripristinare il set di dati dimostrativi senza dialoghi nativi del browser.'
            )}
          </p>

          <div className="space-y-3 pt-1">
            <div className="p-3 rounded border border-theme bg-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <div className="text-xs font-bold text-theme-primary">{L('Restore Demo Data', 'Ripristina Dati Demo')}</div>
                <div className="text-[11px] text-theme-secondary">
                  {L(
                    'Regenerates demo client organizations, sample scans, and typical Purple Team findings.',
                    'Rigenera le organizzazioni cliente demo, le scansioni di esempio e i finding tipici Purple Team.'
                  )}
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setConfirmModal({
                    isOpen: true,
                    title: L('Restore Demo Data', 'Ripristina Dati Demo'),
                    description: L(
                      'Do you want to reinitialize the database with UrielScan demo clients and sample scans?',
                      'Vuoi reinizializzare il database inserendo i clienti e le scansioni dimostrative di UrielScan?'
                    ),
                    confirmText: L('Restore Demo', 'Ripristina Demo'),
                    isDestructive: false,
                    action: async () => {
                      await api.seedDemoData();
                      await onRefreshData();
                      showToast(L('Demo data restored successfully.', 'Dati demo ripristinati con successo.'), 'success');
                    },
                  });
                }}
                className="btn-secondary px-3 py-1.5 text-xs font-semibold shrink-0"
              >
                {L('Restore Demo', 'Ripristina Demo')}
              </button>
            </div>

            <div className="p-3 rounded border border-red-500/30 bg-red-950/10 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <div className="text-xs font-bold text-theme-primary">{L('Clear Scans & Results', 'Svuota Scansioni & Risultati')}</div>
                <div className="text-[11px] text-theme-secondary">
                  {L(
                    'Deletes all scans, findings, logs, and reports, keeping client organizations and profiles intact.',
                    'Elimina tutte le scansioni, i finding, i log e i report, mantenendo intatte le organizzazioni clienti e i profili.'
                  )}
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setConfirmModal({
                    isOpen: true,
                    title: L('Delete Scans & Operational Data', 'Elimina Scansioni & Dati Operativi'),
                    description: L(
                      'All completed scans and their discovered vulnerabilities will be permanently removed.',
                      'Tutte le scansioni eseguite e le relative vulnerabilità scoperte verranno rimosse in modo irreversibile.'
                    ),
                    confirmText: L('Clear Scans', 'Svuota Scansioni'),
                    isDestructive: true,
                    action: async () => {
                      await api.resetAllData(false);
                      await onRefreshData();
                      showToast(L('All scans and findings have been deleted.', 'Tutte le scansioni e i finding sono stati eliminati.'), 'info');
                    },
                  });
                }}
                className="px-3 py-1.5 text-xs font-semibold rounded bg-red-950/60 hover:bg-red-900 border border-red-800 text-red-300 shrink-0"
              >
                {L('Clear Scans', 'Svuota Scansioni')}
              </button>
            </div>

            <div className="p-3 rounded border border-red-500/50 bg-red-950/20 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <div className="text-xs font-bold text-red-400">{L('Total Database Reset', 'Reset Totale Database')}</div>
                <div className="text-[11px] text-theme-secondary">
                  {L(
                    'Completely wipes the entire database (Organizations, Scans, Findings, Reports, and Schedules).',
                    "Azzera completamente l'intero archivio (Organizzazioni, Scansioni, Finding, Report e Schedulazioni)."
                  )}
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setConfirmModal({
                    isOpen: true,
                    title: L('WARNING: Complete Database Reset', 'ATTENZIONE: Reset Completo del Database'),
                    description: L(
                      'You are about to delete ALL organizations, scans, reports, and schedules. This operation cannot be undone.',
                      'Stai per eliminare TUTTE le organizzazioni, scansioni, report e pianificazioni. Questa operazione non può essere annullata.'
                    ),
                    confirmText: L('Reset All', 'Azzera Tutto'),
                    isDestructive: true,
                    action: async () => {
                      await api.resetAllData(true);
                      await onRefreshData();
                      showToast(L('Database completely emptied.', 'Database completamente svuotato.'), 'info');
                    },
                  });
                }}
                className="px-3 py-1.5 text-xs font-semibold rounded bg-red-600 hover:bg-red-700 text-white shrink-0"
              >
                {L('Full Reset', 'Reset Completo')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 7: REMOTE PROBES */}
      {activeSection === 'probes' && (
        <div className="space-y-4">
          {/* Outbound Pull Architecture Info Card */}
          <div className="card-industrial p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 border-l-4 border-l-theme-accent">
            <div className="space-y-1 max-w-3xl">
              <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-theme-accent">
                <Radio className="w-4 h-4" />
                <span>{L('Outbound Pull Remote Probes Architecture', 'Architettura Sonde Remote Outbound Pull')}</span>
              </div>
              <h2 className="text-sm font-bold text-theme-primary">
                {L('Zero-Trust Network Scanning Behind Client Firewalls & NAT', 'Scansione Zero-Trust Dietro Firewall e NAT Aziendali')}
              </h2>
              <p className="text-xs text-theme-secondary leading-relaxed">
                {L(
                  'Remote probes run lightweight Python daemons inside customer perimeter networks. They make strictly outbound HTTPS pull requests to poll for pending scan jobs and stream execution logs and findings back in real time. No incoming ports, port-forwarding, or site-to-site VPNs are required.',
                  "Le sonde remote eseguono un demone Python leggero all'interno delle reti dei clienti. Effettuano richieste HTTPS esclusivamente in uscita (outbound pull) per prelevare i job di scansione e inviare log e finding in tempo reale. Non è richiesta l'apertura di porte firewall, port-forwarding o VPN site-to-site."
                )}
              </p>
            </div>
            <div className="shrink-0">
              <button
                type="button"
                onClick={handleDownloadProbeScript}
                disabled={isDownloadingScript}
                className="btn-primary flex items-center space-x-2 px-3.5 py-2 text-xs font-semibold shadow-sm"
              >
                {isDownloadingScript ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <DownloadCloud className="w-4 h-4" />
                )}
                <span>{L('Download urielscan_probe.py', 'Scarica urielscan_probe.py')}</span>
              </button>
            </div>
          </div>

          {/* Form to register a new probe */}
          <form onSubmit={handleCreateProbe} className="card-industrial p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-theme-subtle pb-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-theme-primary flex items-center space-x-2">
                <Plus className="w-3.5 h-3.5 text-theme-accent" />
                <span>{L('Enroll New Remote Probe', 'Registra Nuova Sonda Remota')}</span>
              </h3>
              <span className="text-[10px] font-mono text-theme-muted">
                {L('Generates a cryptographically secure token', 'Genera un token crittografico sicuro')}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  {L('Assign to Organization *', 'Assegna a Organizzazione *')}
                </label>
                <select
                  value={probeOrgId || organizations[0]?.id || ''}
                  onChange={(e) => setProbeOrgId(e.target.value)}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs"
                >
                  {organizations.map((org) => (
                    <option key={org.id} value={org.id} className="bg-panel text-theme-primary">
                      {org.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="md:col-span-2">
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  {L('Probe Name / Location Identifier *', 'Nome Sonda / Identificatore Sede *')}
                </label>
                <div className="flex items-center space-x-2">
                  <input
                    type="text"
                    required
                    value={probeName}
                    onChange={(e) => setProbeName(e.target.value)}
                    placeholder={L('e.g. Milan HQ Internal Core, AWS VPC Probe, DMZ Agent', 'es. HQ Milano Core Interno, AWS VPC Probe, DMZ Agent')}
                    className="input-industrial w-full px-2.5 py-1.5 text-xs"
                  />
                  <button
                    type="submit"
                    disabled={isCreatingProbe}
                    className="btn-primary px-4 py-1.5 text-xs font-semibold whitespace-nowrap flex items-center space-x-1.5 shrink-0"
                  >
                    {isCreatingProbe ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                    <span>{isCreatingProbe ? L('Generating...', 'Generazione...') : L('Generate Probe Token', 'Genera Token Sonda')}</span>
                  </button>
                </div>
              </div>
            </div>
          </form>

          {/* One-time Token Banner / Card */}
          {newlyCreatedProbe && newlyCreatedProbe.token && (
            <div className="p-4 rounded border-2 border-emerald-500/60 bg-emerald-950/20 space-y-3 animate-in fade-in duration-200">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center space-x-2 text-emerald-400 font-bold text-xs uppercase tracking-wider">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>{L('One-Time Probe Token Generated Successfully', 'Token Sonda Monouso Generato con Successo')}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setNewlyCreatedProbe(null)}
                  className="text-theme-muted hover:text-theme-primary text-xs font-semibold px-2 py-0.5 rounded bg-subtle border border-theme"
                >
                  {L('Dismiss Banner', 'Chiudi Banner')}
                </button>
              </div>

              <p className="text-xs text-theme-secondary">
                {L(
                  'Copy this registration token now. For security, raw tokens cannot be retrieved again after leaving this view.',
                  'Copia questo token ora. Per motivi di sicurezza, il token in chiaro non potrà più essere visualizzato dopo la chiusura.'
                )}
              </p>

              <div className="space-y-2">
                <div>
                  <label className="block text-[11px] font-bold text-theme-primary uppercase tracking-wide mb-1">
                    {L('Probe Auth Token:', 'Token di Autenticazione Sonda:')}
                  </label>
                  <div className="flex items-center space-x-2">
                    <code className="p-2 rounded bg-canvas border border-theme text-emerald-400 font-mono text-xs select-all flex-1 break-all">
                      {newlyCreatedProbe.token}
                    </code>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(newlyCreatedProbe.token!);
                        setCopiedToken(true);
                        setTimeout(() => setCopiedToken(false), 2000);
                        showToast(L('Token copied to clipboard.', 'Token copiato negli appunti.'), 'info');
                      }}
                      className="btn-secondary px-2.5 py-1.5 text-xs flex items-center space-x-1 shrink-0"
                    >
                      {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedToken ? L('Copied!', 'Copiato!') : L('Copy Token', 'Copia Token')}</span>
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-[11px] font-bold text-theme-primary uppercase tracking-wide mb-1">
                    {L('Ready-to-Run Launch Command:', 'Comando Pronto per l\'Esecuzione:')}
                  </label>
                  <div className="flex items-center space-x-2">
                    <pre className="p-2 rounded bg-canvas border border-theme text-theme-accent font-mono text-xs select-all flex-1 overflow-x-auto">
                      {`python urielscan_probe.py --server ${window.location.origin} --token ${newlyCreatedProbe.token}`}
                    </pre>
                    <button
                      type="button"
                      onClick={() => {
                        const cmd = `python urielscan_probe.py --server ${window.location.origin} --token ${newlyCreatedProbe.token}`;
                        navigator.clipboard.writeText(cmd);
                        setCopiedCommand(true);
                        setTimeout(() => setCopiedCommand(false), 2000);
                        showToast(L('Command copied to clipboard.', 'Comando copiato negli appunti.'), 'info');
                      }}
                      className="btn-secondary px-2.5 py-1.5 text-xs flex items-center space-x-1 shrink-0"
                    >
                      {copiedCommand ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedCommand ? L('Copied!', 'Copiato!') : L('Copy Command', 'Copia Comando')}</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* List/Table of registered probes */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
                {L(`Enrolled Remote Probes (${agents.length})`, `Sonde Remote Attive (${agents.length})`)}
              </h3>
              <button
                type="button"
                onClick={fetchAgents}
                disabled={isLoadingAgents}
                className="btn-secondary p-1 text-theme-secondary hover:text-theme-primary"
                title={L('Refresh Probes', 'Aggiorna Sonde')}
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoadingAgents ? 'animate-spin' : ''}`} />
              </button>
            </div>

            {agents.length === 0 ? (
              <div className="card-industrial p-8 text-center text-xs text-theme-muted font-mono space-y-2">
                <Radio className="w-8 h-8 mx-auto text-theme-muted/50" />
                <p>
                  {L(
                    'No remote probes registered yet. Generate a probe token above to deploy your first probe.',
                    'Nessuna sonda remota registrata. Genera un token per distribuire la prima sonda.'
                  )}
                </p>
              </div>
            ) : (
              <div className="card-industrial overflow-x-auto">
                <table className="w-full text-left border-collapse table-industrial text-xs">
                  <thead>
                    <tr>
                      <th className="p-2.5">{L('Status', 'Stato')}</th>
                      <th className="p-2.5">{L('Probe Name / Token', 'Nome Sonda / Token')}</th>
                      <th className="p-2.5">{L('Organization', 'Organizzazione')}</th>
                      <th className="p-2.5">{L('Host & Environment', 'Host & Ambiente')}</th>
                      <th className="p-2.5">{L('Detected Engines', 'Motori Rilevati')}</th>
                      <th className="p-2.5">{L('Last Seen', 'Ultima Connessione')}</th>
                      <th className="p-2.5 text-right">{L('Actions', 'Azioni')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-theme-subtle">
                    {agents.map((agent) => {
                      const isOnline = agent.status === 'online';
                      const orgName = agent.org_name || organizations.find((o) => o.id === agent.org_id)?.name || `Org #${agent.org_id}`;
                      const eng = agent.engines || {};

                      return (
                        <tr key={agent.id} className="hover:bg-subtle/50 transition-colors">
                          <td className="p-2.5 whitespace-nowrap">
                            <span
                              className={`inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                                isOnline
                                  ? 'bg-emerald-950/40 border-emerald-500/60 text-emerald-400'
                                  : 'bg-subtle border-theme text-theme-muted'
                              }`}
                            >
                              <span
                                className={`w-1.5 h-1.5 rounded-full ${
                                  isOnline ? 'bg-emerald-400 animate-pulse' : 'bg-theme-muted'
                                }`}
                              />
                              <span>{isOnline ? L('ONLINE', 'ONLINE') : L('OFFLINE', 'OFFLINE')}</span>
                            </span>
                          </td>

                          <td className="p-2.5">
                            <div className="font-bold text-theme-primary">{agent.name}</div>
                            <div className="text-[10px] font-mono text-theme-muted mt-0.5">
                              Prefix: <span className="text-theme-secondary">{agent.token_prefix || '—'}...</span>
                              {agent.version && <span className="ml-2">v{agent.version}</span>}
                            </div>
                          </td>

                          <td className="p-2.5 whitespace-nowrap">
                            <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-subtle border border-theme text-[11px] font-mono font-semibold text-theme-accent">
                              <Building2 className="w-3 h-3 shrink-0" />
                              <span>{orgName}</span>
                            </span>
                          </td>

                          <td className="p-2.5 font-mono text-[11px]">
                            <div className="text-theme-primary">
                              {agent.hostname || agent.ip_address || L('Unreported', 'Non comunicato')}
                            </div>
                            <div className="text-[10px] text-theme-muted truncate">
                              {agent.ip_address && agent.hostname ? `${agent.ip_address} • ` : ''}
                              {agent.os_info || L('Unknown OS', 'OS Sconosciuto')}
                            </div>
                          </td>

                          <td className="p-2.5 whitespace-nowrap">
                            <div className="flex items-center space-x-1 font-mono text-[10px]">
                              <span
                                className={`px-1.5 py-0.5 rounded border ${
                                  eng.nmap
                                    ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-400'
                                    : 'bg-subtle border-theme text-theme-muted line-through opacity-60'
                                }`}
                              >
                                Nmap
                              </span>
                              <span
                                className={`px-1.5 py-0.5 rounded border ${
                                  eng.nuclei
                                    ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-400'
                                    : 'bg-subtle border-theme text-theme-muted line-through opacity-60'
                                }`}
                              >
                                Nuclei
                              </span>
                              <span
                                className={`px-1.5 py-0.5 rounded border ${
                                  eng.native !== false
                                    ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-400'
                                    : 'bg-subtle border-theme text-theme-muted line-through opacity-60'
                                }`}
                              >
                                Native
                              </span>
                            </div>
                          </td>

                          <td className="p-2.5 whitespace-nowrap font-mono text-[11px] text-theme-secondary">
                            {agent.last_seen ? new Date(agent.last_seen).toLocaleString(locale) : L('Never', 'Mai')}
                          </td>

                          <td className="p-2.5 text-right whitespace-nowrap">
                            <button
                              type="button"
                              onClick={() => promptDeleteProbe(agent)}
                              className="btn-secondary p-1 text-red-400 hover:text-red-300"
                              title={L('Revoke Probe', 'Revoca Sonda')}
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Global Confirm Modal */}
      <ConfirmModal
        isOpen={confirmModal.isOpen}
        title={confirmModal.title}
        description={confirmModal.description}
        confirmText={confirmModal.confirmText}
        isDestructive={confirmModal.isDestructive}
        isLoading={isModalLoading}
        onCancel={() => setConfirmModal((prev) => ({ ...prev, isOpen: false }))}
        onConfirm={async () => {
          setIsModalLoading(true);
          try {
            await confirmModal.action();
            setConfirmModal((prev) => ({ ...prev, isOpen: false }));
          } catch (err: any) {
            showToast(err.message || L('Operation failed.', 'Operazione fallita.'), 'error');
          } finally {
            setIsModalLoading(false);
          }
        }}
      />
    </div>
  );
};
