import React from 'react';
import { 
  LayoutDashboard, 
  Crosshair, 
  Radar, 
  Sparkles, 
  FileText, 
  Clock, 
  Settings, 
  ShieldCheck, 
  Server
} from 'lucide-react';
import { useI18n } from '../i18n/LanguageContext';

export type ViewType = 
  | 'dashboard' 
  | 'new-scan' 
  | 'scans' 
  | 'ai-hub' 
  | 'reports' 
  | 'scheduler' 
  | 'settings';

interface SidebarProps {
  currentView: ViewType;
  onNavigate: (view: ViewType) => void;
  runningScansCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onNavigate,
  runningScansCount,
}) => {
  const { L } = useI18n();

  const navItems = [
    {
      id: 'dashboard' as ViewType,
      label: L('Command Center', 'Command Center'),
      sublabel: L('Dashboard & Posture', 'Dashboard & Postura'),
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'new-scan' as ViewType,
      label: L('New Scan', 'Nuova Scansione'),
      sublabel: L('ZenMap++ NSE Studio', 'ZenMap++ NSE Studio'),
      icon: Crosshair,
      badge: 'Studio',
    },
    {
      id: 'scans' as ViewType,
      label: L('Scans & Results', 'Scansioni & Risultati'),
      sublabel: L('Hosts, Ports & Findings', 'Host, Porte & Findings'),
      icon: Radar,
      badge: runningScansCount > 0 ? `${runningScansCount} Live` : null,
      badgeColor: 'border-amber-600 bg-amber-950/30 text-amber-400 animate-pulse',
    },
    {
      id: 'ai-hub' as ViewType,
      label: L('AI Purple Analyst', 'AI Purple Analyst'),
      sublabel: L('Red Attack + Blue Fix', 'Red Attack + Blue Fix'),
      icon: Sparkles,
      badge: 'AI',
    },
    {
      id: 'reports' as ViewType,
      label: L('Report Center', 'Report Center'),
      sublabel: L('White-Label MSP / PDF', 'White-Label MSP / PDF'),
      icon: FileText,
      badge: null,
    },
    {
      id: 'scheduler' as ViewType,
      label: L('Scheduler', 'Pianificazione'),
      sublabel: L('Cron & Background Scans', 'Scansioni Cron & Background'),
      icon: Clock,
      badge: null,
    },
    {
      id: 'settings' as ViewType,
      label: L('Setup & Security', 'Setup & Sicurezza'),
      sublabel: L('Tenants, 2FA & Engines', 'Tenant, 2FA & Motori'),
      icon: Settings,
      badge: null,
    },
  ];

  return (
    <aside className="w-60 shrink-0 bg-panel border-r border-theme min-h-[calc(100vh-3.5rem)] flex flex-col justify-between p-3 select-none">
      {/* Navigation list */}
      <div className="space-y-1">
        <div className="px-2.5 py-1.5 text-[10px] font-mono font-bold tracking-wider uppercase text-theme-muted">
          {L('Operational Navigation', 'Navigazione Operativa')}
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={`w-full flex items-center justify-between px-2.5 py-2 rounded transition text-left cursor-pointer ${
                isActive
                  ? 'bg-subtle border-l-2 border-theme-accent text-theme-primary'
                  : 'text-theme-secondary hover:text-theme-primary hover:bg-subtle'
              }`}
            >
              <div className="flex items-center space-x-2.5 truncate">
                <div
                  className={`p-1 rounded shrink-0 transition ${
                    isActive ? 'text-theme-accent' : 'text-theme-muted'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                </div>
                <div className="truncate">
                  <div className={`text-xs font-semibold ${isActive ? 'text-theme-primary font-bold' : 'text-theme-secondary'}`}>
                    {item.label}
                  </div>
                  <div className="text-[10px] text-theme-muted truncate">
                    {item.sublabel}
                  </div>
                </div>
              </div>

              {item.badge && (
                <span
                  className={`text-[9px] font-mono font-bold px-1 py-0.2 rounded border uppercase tracking-wider ${
                    item.badgeColor || 'border-theme-subtle bg-subtle text-theme-muted'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Purple Core status widget */}
      <div className="p-3 rounded border border-theme bg-subtle space-y-1.5">
        <div className="flex items-center justify-between text-xs">
          <span className="flex items-center space-x-1.5 text-theme-primary font-semibold">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
            <span>Purple Core</span>
          </span>
          <span className="text-[9px] font-mono text-emerald-500 font-bold">
            ONLINE
          </span>
        </div>
        <p className="text-[10px] text-theme-muted leading-tight">
          {L('Correlation of offensive vectors and Blue Team remediation.', 'Correlazione vettori offensivi e contromisure Blue Team.')}
        </p>
        <div className="pt-1.5 border-t border-theme-subtle flex items-center justify-between text-[10px] font-mono text-theme-muted">
          <span>UrielScan MSSP</span>
          <span className="flex items-center space-x-1 text-theme-accent">
            <Server className="w-2.5 h-2.5" />
            <span>FastAPI:8000</span>
          </span>
        </div>
      </div>
    </aside>
  );
};
