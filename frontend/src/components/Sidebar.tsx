import React, { useState } from 'react';
import {
  LayoutDashboard,
  Crosshair,
  Cloud,
  Radar,
  Sparkles,
  FileText,
  Clock,
  Settings,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react';
import { useI18n } from '../i18n/LanguageContext';

export type ViewType = 
  | 'dashboard' 
  | 'new-scan' 
  | 'cloud-security'
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
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem('uriel_sidebar_collapsed') === '1';
    } catch {
      return false;
    }
  });

  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem('uriel_sidebar_collapsed', next ? '1' : '0');
      } catch {
        // ignore storage restrictions
      }
      return next;
    });
  };

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
      id: 'cloud-security' as ViewType,
      label: L('Cloud Security', 'Cloud Security'),
      sublabel: L('Prowler CSPM & Compliance', 'Prowler CSPM & Compliance'),
      icon: Cloud,
      badge: 'Prowler',
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
    <aside
      className={`${
        collapsed ? 'w-16 px-2' : 'w-60 p-3'
      } shrink-0 bg-panel border-r border-theme h-full overflow-hidden flex flex-col justify-between py-3 select-none transition-all duration-200`}
    >
      {/* Navigation list */}
      <div className="space-y-1 flex-1 min-h-0 overflow-y-auto">
        {!collapsed && (
          <div className="px-2.5 py-1.5 text-[10px] font-mono font-bold tracking-wider uppercase text-theme-muted">
            {L('Operational Navigation', 'Navigazione Operativa')}
          </div>
        )}
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              title={collapsed ? `${item.label} — ${item.sublabel}` : undefined}
              className={`relative w-full flex items-center ${
                collapsed ? 'justify-center px-0 py-2' : 'justify-between px-2.5 py-2 text-left'
              } rounded transition cursor-pointer ${
                isActive
                  ? collapsed
                    ? 'bg-subtle border border-theme-accent text-theme-primary'
                    : 'bg-subtle border-l-2 border-theme-accent text-theme-primary'
                  : 'text-theme-secondary hover:text-theme-primary hover:bg-subtle'
              }`}
            >
              <div className={`flex items-center ${collapsed ? '' : 'space-x-2.5 truncate'}`}>
                <div
                  className={`p-1 rounded shrink-0 transition ${
                    isActive ? 'text-theme-accent' : 'text-theme-muted'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                </div>
                {!collapsed && (
                  <div className="truncate">
                    <div className={`text-xs font-semibold ${isActive ? 'text-theme-primary font-bold' : 'text-theme-secondary'}`}>
                      {item.label}
                    </div>
                    <div className="text-[10px] text-theme-muted truncate">
                      {item.sublabel}
                    </div>
                  </div>
                )}
              </div>

              {collapsed && item.id === 'scans' && runningScansCount > 0 && (
                <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
              )}

              {!collapsed && item.badge && (
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

      {/* Collapse / Expand Sidebar Toggle */}
      <button
        type="button"
        onClick={toggleCollapsed}
        title={collapsed ? L('Expand Sidebar', 'Espandi Barra') : L('Collapse Sidebar', 'Comprimi Barra')}
        className={`shrink-0 mt-2 w-full flex items-center ${
          collapsed ? 'justify-center px-0 py-2' : 'justify-between px-2.5 py-2'
        } rounded border border-theme bg-subtle hover:bg-hover text-theme-secondary hover:text-theme-primary transition cursor-pointer`}
      >
        <div className={`flex items-center ${collapsed ? '' : 'space-x-2'}`}>
          {collapsed ? (
            <PanelLeftOpen className="w-4 h-4 text-theme-accent shrink-0" />
          ) : (
            <PanelLeftClose className="w-4 h-4 text-theme-accent shrink-0" />
          )}
          {!collapsed && (
            <span className="text-xs font-semibold">
              {L('Collapse Sidebar', 'Comprimi Barra')}
            </span>
          )}
        </div>
      </button>
    </aside>
  );
};
