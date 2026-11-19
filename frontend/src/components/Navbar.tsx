import React, { useEffect, useRef, useState } from 'react';
import {
  Building2,
  ChevronDown,
  PlusCircle,
  LogOut,
  User,
  Palette,
  Cpu,
  Check,
  Languages,
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

const THEME_OPTIONS: Array<{ id: PortalTheme; label: string; swatch: string }> = [
  { id: 'uriel-ops', label: 'Uriel Ops', swatch: 'bg-violet-500' },
  { id: 'phosphor-ops', label: 'Phosphor Ops', swatch: 'bg-emerald-400' },
  { id: 'foundry-dark', label: 'Carbon Tactical', swatch: 'bg-sky-500' },
  { id: 'swiss-light', label: 'Swiss Editorial', swatch: 'bg-zinc-200 border border-zinc-400' },
];

export const Navbar: React.FC<NavbarProps> = ({
  selectedOrgId,
  onSelectOrg,
  organizations,
  engineStatus,
  onNewScanClick,
  currentUser,
  onLogout,
  currentTheme,
  onThemeChange,
}) => {
  const { lang, setLang, L } = useI18n();
  const [openMenu, setOpenMenu] = useState<'org' | 'engines' | 'theme' | null>(null);
  const headerRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (headerRef.current && !headerRef.current.contains(e.target as Node)) {
        setOpenMenu(null);
      }
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpenMenu(null);
    };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, []);

  const selectedOrg = organizations.find((o) => String(o.id) === String(selectedOrgId));
  const currentThemeObj = THEME_OPTIONS.find((t) => t.id === currentTheme) || THEME_OPTIONS[0];

  const enginesList = [
    {
      id: 'nmap',
      name: 'Nmap',
      active: Boolean(engineStatus.nmap?.available),
      meta: `${engineStatus.nmap?.scripts_count ?? 0} NSE`,
    },
    {
      id: 'nuclei',
      name: 'Nuclei',
      active: Boolean(engineStatus.nuclei?.available),
      meta: engineStatus.nuclei?.version || 'Templates',
    },
    {
      id: 'zap',
      name: 'OWASP ZAP',
      active: Boolean(engineStatus.zap?.available),
      meta: engineStatus.zap?.version || 'Web App',
    },
    {
      id: 'native',
      name: 'Native',
      active: Boolean(engineStatus.native?.available),
      meta: 'NET+WEB',
    },
  ];

  const activeEnginesCount = enginesList.filter((e) => e.active).length;
  const aggregateLedClass =
    activeEnginesCount === enginesList.length
      ? 'bg-emerald-500'
      : activeEnginesCount > 0
      ? 'bg-amber-500'
      : 'bg-red-500';

  return (
    <header
      ref={headerRef}
      className="sticky top-0 z-40 w-full h-14 shrink-0 bg-panel border-b border-theme px-4 lg:px-6 flex items-center justify-between gap-2"
    >
      {/* Left: Logo + Organization Dropdown (directly after logo) */}
      <div className="flex items-center space-x-3 min-w-0">
        <img
          src={`/urielscan-header-${currentTheme}.png`}
          alt="UrielScan"
          className="h-9 w-auto object-contain select-none transition-all duration-200 shrink-0"
        />

        {/* Custom Themed Organization Tenant Dropdown */}
        <div className="relative min-w-0">
          <button
            type="button"
            onClick={() => setOpenMenu((m) => (m === 'org' ? null : 'org'))}
            className="flex items-center space-x-2 bg-subtle hover:bg-hover border border-theme rounded px-2.5 py-1.5 text-xs text-theme-primary transition cursor-pointer max-w-[230px]"
            title={
              selectedOrg
                ? `${selectedOrg.name} — Scope: ${selectedOrg.target_scope || 'N/A'}`
                : L('All Organizations (Global MSP)', 'Tutte le Organizzazioni (Global MSP)')
            }
          >
            <Building2 className="w-3.5 h-3.5 text-theme-secondary shrink-0" />
            <span className="font-medium truncate">
              {selectedOrg
                ? `${selectedOrg.name} (${selectedOrg.industry})`
                : L('All Organizations', 'Tutte le Organizzazioni')}
            </span>
            <ChevronDown
              className={`w-3 h-3 text-theme-muted shrink-0 transition-transform ${
                openMenu === 'org' ? 'rotate-180' : ''
              }`}
            />
          </button>

          {openMenu === 'org' && (
            <div className="absolute left-0 top-full mt-1.5 w-72 bg-panel border border-theme rounded shadow-xl z-50 py-1 text-xs max-h-80 overflow-y-auto">
              <button
                type="button"
                onClick={() => {
                  onSelectOrg('ALL');
                  setOpenMenu(null);
                }}
                className={`w-full px-3 py-2 text-left flex items-center justify-between hover:bg-hover transition cursor-pointer ${
                  selectedOrgId === 'ALL'
                    ? 'bg-subtle text-theme-accent font-semibold'
                    : 'text-theme-primary'
                }`}
              >
                <span className="truncate">
                  {L('All Organizations (Global MSP)', 'Tutte le Organizzazioni (Global MSP)')}
                </span>
                {selectedOrgId === 'ALL' && <Check className="w-3.5 h-3.5 shrink-0 ml-2" />}
              </button>

              {organizations.length > 0 && <div className="border-t border-theme-subtle my-1" />}

              {organizations.map((org) => {
                const isSelected = String(org.id) === String(selectedOrgId);
                return (
                  <button
                    key={org.id}
                    type="button"
                    onClick={() => {
                      onSelectOrg(String(org.id));
                      setOpenMenu(null);
                    }}
                    className={`w-full px-3 py-2 text-left flex items-center justify-between hover:bg-hover transition cursor-pointer ${
                      isSelected
                        ? 'bg-subtle text-theme-accent font-semibold'
                        : 'text-theme-primary'
                    }`}
                  >
                    <div className="min-w-0 pr-2">
                      <div className="truncate">
                        {org.name}{' '}
                        <span className="text-theme-muted font-normal">({org.industry})</span>
                      </div>
                      {org.target_scope && (
                        <div className="text-[10px] font-mono text-theme-muted truncate">
                          {org.target_scope}
                        </div>
                      )}
                    </div>
                    {isSelected && <Check className="w-3.5 h-3.5 shrink-0" />}
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Center: Unified Engines Dropdown with 3-Color Aggregate LED */}
      <div className="hidden md:flex items-center relative shrink-0">
        <button
          type="button"
          onClick={() => setOpenMenu((m) => (m === 'engines' ? null : 'engines'))}
          className="flex items-center space-x-2 px-2.5 py-1.5 rounded border border-theme bg-subtle hover:bg-hover text-xs font-mono text-theme-primary transition cursor-pointer whitespace-nowrap"
          title={L('Click to view scanner engine status', 'Clicca per vedere lo stato dei motori di scansione')}
        >
          <span className={`w-2 h-2 rounded-full shrink-0 ${aggregateLedClass}`} />
          <Cpu className="w-3.5 h-3.5 text-theme-secondary shrink-0" />
          <span className="font-semibold tracking-tight">{L('Engines', 'Motori')}</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-panel border border-theme-subtle text-theme-secondary">
            {activeEnginesCount}/{enginesList.length}
          </span>
          <ChevronDown
            className={`w-3 h-3 text-theme-muted shrink-0 transition-transform ${
              openMenu === 'engines' ? 'rotate-180' : ''
            }`}
          />
        </button>

        {openMenu === 'engines' && (
          <div className="absolute left-1/2 -translate-x-1/2 top-full mt-1.5 w-72 bg-panel border border-theme rounded shadow-xl z-50 p-1.5 space-y-1 text-xs">
            <div className="px-2 py-1 text-[10px] font-mono font-bold uppercase tracking-wider text-theme-muted border-b border-theme-subtle flex items-center justify-between">
              <span>{L('Scanner Engines', 'Motori di Scansione')}</span>
              <span className="text-theme-secondary">
                {activeEnginesCount}/{enginesList.length} {L('ONLINE', 'ATTIVI')}
              </span>
            </div>
            {enginesList.map((eng) => (
              <div
                key={eng.id}
                className="flex items-center justify-between px-2.5 py-1.5 rounded bg-subtle/60 border border-theme-subtle"
              >
                <div className="flex items-center space-x-2 min-w-0">
                  <span
                    className={`w-2 h-2 rounded-full shrink-0 ${
                      eng.active ? 'bg-emerald-500' : 'bg-red-500'
                    }`}
                  />
                  <div className="min-w-0">
                    <div className="font-semibold text-theme-primary truncate">{eng.name}</div>
                    <div className="text-[10px] font-mono text-theme-muted truncate">{eng.meta}</div>
                  </div>
                </div>
                <span
                  className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                    eng.active
                      ? 'bg-emerald-950/30 border-emerald-600/50 text-emerald-400'
                      : 'bg-red-950/30 border-red-600/50 text-red-400'
                  }`}
                >
                  {eng.active ? L('ACTIVE', 'ATTIVO') : L('MISSING', 'ASSENTE')}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Right: Actions, Language Toggle, Custom Theme Popover & User Profile */}
      <div className="flex items-center space-x-2 shrink-0">
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
            title={L('Switch to English', "Passa all'Inglese")}
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
            title={L('Switch to Italian', "Passa all'Italiano")}
          >
            IT
          </button>
        </div>

        {/* Custom Themed Portal Theme Selector */}
        <div className="relative shrink-0">
          <button
            type="button"
            onClick={() => setOpenMenu((m) => (m === 'theme' ? null : 'theme'))}
            className="flex items-center space-x-1.5 bg-subtle hover:bg-hover border border-theme rounded px-2.5 py-1.5 text-xs text-theme-primary transition cursor-pointer whitespace-nowrap"
            title={L('Select Industrial Theme', 'Seleziona Tema Industriale')}
          >
            <Palette className="w-3.5 h-3.5 text-theme-secondary shrink-0" />
            <span className="font-medium hidden sm:inline">{currentThemeObj.label}</span>
            <ChevronDown
              className={`w-3 h-3 text-theme-muted shrink-0 transition-transform ${
                openMenu === 'theme' ? 'rotate-180' : ''
              }`}
            />
          </button>

          {openMenu === 'theme' && (
            <div className="absolute right-0 top-full mt-1.5 w-48 bg-panel border border-theme rounded shadow-xl z-50 py-1 text-xs">
              {THEME_OPTIONS.map((t) => {
                const active = t.id === currentTheme;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => {
                      onThemeChange(t.id);
                      setOpenMenu(null);
                    }}
                    className={`w-full px-3 py-2 text-left flex items-center justify-between hover:bg-hover transition cursor-pointer ${
                      active ? 'bg-subtle text-theme-accent font-semibold' : 'text-theme-primary'
                    }`}
                  >
                    <span className="flex items-center space-x-2">
                      <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${t.swatch}`} />
                      <span>{t.label}</span>
                    </span>
                    {active && <Check className="w-3.5 h-3.5 shrink-0" />}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Current User Badge & Logout */}
        {currentUser && (
          <div className="flex items-center space-x-1.5 pl-1 border-l border-theme-subtle">
            <div
              className="flex items-center space-x-1.5 px-2 py-1 rounded bg-subtle border border-theme text-xs"
              title={`${L('Authenticated user', 'Utente autenticato')}: ${currentUser.username} (2FA: ${
                currentUser.two_factor_enabled ? L('Active', 'Attivo') : L('Disabled', 'Disattivato')
              })`}
            >
              <User className="w-3.5 h-3.5 text-theme-secondary" />
              <span className="font-mono text-theme-primary font-medium">{currentUser.username}</span>
              {currentUser.two_factor_enabled && (
                <span
                  className="w-1.5 h-1.5 rounded-full bg-emerald-500"
                  title={L('2FA TOTP active', '2FA TOTP attivo')}
                />
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
