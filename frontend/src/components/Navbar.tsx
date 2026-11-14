import React from 'react';
import { 
  ShieldCheck, 
  Building2, 
  ChevronDown, 
  PlusCircle, 
  LogOut, 
  User, 
  Palette, 
  Terminal, 
  Sun, 
  Moon,
  Languages 
} from 'lucide-react';
import { Organization, ScannerProfile, EngineStatus, AuthUser } from '../types';
import { useI18n } from '../i18n/LanguageContext';

export type PortalTheme = 'uriel-ops' | 'foundry-dark' | 'swiss-light' | 'phosphor-ops';

interface NavbarProps {
  selectedOrgId: string;
  onSelectOrg: (id: string) => void;
  organizations: Organization[];
  scannerProfile: ScannerProfile;
  engineStatus: EngineStatus;
  onNewScanClick: () => void;
  currentUser?: AuthUser | null;
  onLogout?: () => void;
  currentTheme: PortalTheme;
  onThemeChange: (theme: PortalTheme) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  selectedOrgId,
  onSelectOrg,
  organizations,
  scannerProfile,
  engineStatus,
  onNewScanClick,
  currentUser,
  onLogout,
  currentTheme,
  onThemeChange,
}) => {
  const { lang, setLang, L } = useI18n();
  const selectedOrg = organizations.find((o) => o.id === selectedOrgId);

  return (
    <header className="sticky top-0 z-40 w-full h-14 bg-panel border-b border-theme px-4 lg:px-6 flex items-center justify-between gap-2">
      {/* Left: Branding & Organization Selector */}
      <div className="flex items-center space-x-3 min-w-0">
        <div className="flex items-center space-x-2.5 shrink-0">
          <img
            src={`/urielscan-header-${currentTheme}.png`}
            alt="UrielScan"
            className="h-9 w-auto object-contain select-none transition-all duration-200 shrink-0"
          />
          <div className="hidden sm:flex flex-col justify-center border-l border-theme-subtle pl-2.5 shrink-0">
            <div className="flex items-center space-x-1.5">
              <span className="text-[9px] font-mono font-semibold px-1.5 py-0.5 rounded border border-theme-subtle bg-subtle text-theme-accent uppercase tracking-wider whitespace-nowrap">
                Console Ops
              </span>
            </div>
            <p className="text-[10px] text-theme-muted truncate max-w-[150px] leading-tight mt-0.5">
              {scannerProfile.company_name || 'Purple Team MSSP'}
            </p>
          </div>
        </div>

        {/* Divider */}
        <div className="hidden md:block h-5 w-px bg-theme-subtle shrink-0" />

        {/* Organization Tenant Selector */}
        <div className="relative group min-w-0">
          <div className="flex items-center space-x-2 bg-subtle hover:bg-hover border border-theme rounded px-2.5 py-1 text-xs text-theme-primary transition cursor-pointer">
            <Building2 className="w-3.5 h-3.5 text-theme-secondary shrink-0" />
            <select
              value={selectedOrgId}
              onChange={(e) => onSelectOrg(e.target.value)}
              className="bg-transparent text-theme-primary text-xs font-medium focus:outline-none cursor-pointer pr-4 appearance-none max-w-[175px] xl:max-w-[230px] truncate"
            >
              <option value="ALL" className="bg-panel text-theme-primary">
                {L('All Organizations (Global MSP)', 'Tutte le Organizzazioni (Global MSP)')}
              </option>
              {organizations.map((org) => (
                <option key={org.id} value={org.id} className="bg-panel text-theme-primary">
                  {org.name} ({org.industry})
                </option>
              ))}
            </select>
            <ChevronDown className="w-3 h-3 text-theme-muted pointer-events-none absolute right-2" />
          </div>
          {selectedOrg && (
            <div className="absolute left-0 top-full mt-1 hidden group-hover:flex items-center space-x-2 px-2.5 py-1 card-industrial text-[11px] text-theme-secondary shadow-lg whitespace-nowrap z-50">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              <span>Scope: {selectedOrg.target_scope}</span>
            </div>
          )}
        </div>
      </div>

      {/* Center: Live Engine Indicators */}
      <div className="hidden xl:flex items-center space-x-2 text-[11px] font-mono shrink-0">
        {/* Nmap Engine */}
        <div 
          className="flex items-center space-x-1.5 px-2 py-0.5 rounded border border-theme bg-subtle whitespace-nowrap"
          title={`Nmap Engine: ${engineStatus.nmap.scripts_count} ${L('scripts', 'script')}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${engineStatus.nmap.available ? 'bg-emerald-500' : 'bg-red-500'}`} />
          <span className="text-theme-muted">NMAP:</span>
          <span className="text-theme-primary font-semibold">
            {engineStatus.nmap.available ? L('ACTIVE', 'ATTIVO') : L('MISSING', 'ASSENTE')}
          </span>
          <span className="text-[10px] px-1 rounded bg-panel border border-theme-subtle text-theme-secondary whitespace-nowrap">
            {engineStatus.nmap.scripts_count} NSE
          </span>
        </div>

        {/* Nuclei Engine */}
        <div 
          className="flex items-center space-x-1.5 px-2 py-0.5 rounded border border-theme bg-subtle whitespace-nowrap"
          title={L('Nuclei Vulnerability Engine', 'Motore Vulnerabilità Nuclei')}
        >
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${engineStatus.nuclei.available ? 'bg-emerald-500' : 'bg-amber-500'}`} />
          <span className="text-theme-muted">NUCLEI:</span>
          <span className="text-theme-primary font-semibold">
            {engineStatus.nuclei.available ? L('ACTIVE', 'ATTIVO') : L('UNAVAILABLE', 'NON DISP.')}
          </span>
        </div>

        {/* Native Engine */}
        <div 
          className="flex items-center space-x-1.5 px-2 py-0.5 rounded border border-theme bg-subtle whitespace-nowrap"
          title={L('Uriel Native Asynchronous Probe', 'Sonda Asincrona Nativa Uriel')}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
          <span className="text-theme-muted">NATIVE:</span>
          <span className="text-theme-primary font-semibold">NET+WEB</span>
        </div>
      </div>

      {/* Right: Actions, Theme Switcher, Language Toggle & User Profile */}
      <div className="flex items-center space-x-2.5 shrink-0">
        {/* New Scan Action Button */}
        <button
          onClick={onNewScanClick}
          className="btn-primary flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold shadow-sm whitespace-nowrap shrink-0"
        >
          <PlusCircle className="w-3.5 h-3.5 shrink-0" />
          <span>{L('New Scan', 'Nuova Scansione')}</span>
        </button>

        {/* Language Toggle */}
        <div className="flex items-center bg-subtle border border-theme rounded px-1.5 py-1 text-xs whitespace-nowrap shrink-0">
          <Languages className="w-3.5 h-3.5 text-theme-secondary mr-1 shrink-0" />
          <button
            type="button"
            onClick={() => setLang('en')}
            className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase transition-colors ${
              lang === 'en'
                ? 'bg-theme-accent text-white'
                : 'text-theme-muted hover:text-theme-primary'
            }`}
            title={L('Switch to English', 'Passa all\'Inglese')}
          >
            EN
          </button>
          <span className="text-theme-muted px-0.5 select-none text-[10px]">|</span>
          <button
            type="button"
            onClick={() => setLang('it')}
            className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase transition-colors ${
              lang === 'it'
                ? 'bg-theme-accent text-white'
                : 'text-theme-muted hover:text-theme-primary'
            }`}
            title={L('Switch to Italian', 'Passa all\'Italiano')}
          >
            IT
          </button>
        </div>

        {/* Theme Selector */}
        <div className="relative flex items-center bg-subtle border border-theme rounded px-2 py-1 text-xs whitespace-nowrap shrink-0">
          <Palette className="w-3.5 h-3.5 text-theme-secondary mr-1.5 shrink-0" />
          <select
            value={currentTheme}
            onChange={(e) => onThemeChange(e.target.value as PortalTheme)}
            className="bg-transparent text-theme-primary text-xs font-medium focus:outline-none cursor-pointer appearance-none pr-3"
            title={L('Select Industrial Theme', 'Seleziona Tema Industriale')}
          >
            <option value="uriel-ops" className="bg-panel text-theme-primary">
              Uriel Ops
            </option>
            <option value="phosphor-ops" className="bg-panel text-theme-primary">
              Phosphor Ops
            </option>
            <option value="foundry-dark" className="bg-panel text-theme-primary">
              Carbon Tactical
            </option>
            <option value="swiss-light" className="bg-panel text-theme-primary">
              Swiss Editorial
            </option>
          </select>
          <ChevronDown className="w-3 h-3 text-theme-muted pointer-events-none absolute right-1.5" />
        </div>

        {/* Current User Badge & Logout */}
        {currentUser && (
          <div className="flex items-center space-x-1.5 pl-1 border-l border-theme-subtle">
            <div 
              className="flex items-center space-x-1.5 px-2 py-1 rounded bg-subtle border border-theme text-xs"
              title={`${L('Authenticated user', 'Utente autenticato')}: ${currentUser.username} (2FA: ${currentUser.two_factor_enabled ? L('Active', 'Attivo') : L('Disabled', 'Disattivato')})`}
            >
              <User className="w-3.5 h-3.5 text-theme-secondary" />
              <span className="font-mono text-theme-primary font-medium">{currentUser.username}</span>
              {currentUser.two_factor_enabled && (
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" title={L('2FA TOTP active', '2FA TOTP attivo')} />
              )}
            </div>

            {onLogout && (
              <button
                onClick={onLogout}
                className="btn-secondary p-1.5 text-theme-muted hover:text-red-400 rounded transition-colors"
                title={L('Disconnect session', 'Disconnetti sessione')}
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        )}
      </div>
    </header>
  );
};
