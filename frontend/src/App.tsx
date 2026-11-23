import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Navbar, PortalTheme } from './components/Navbar';
import { Sidebar, ViewType } from './components/Sidebar';
import { CommandCenter } from './components/CommandCenter';
import { NewScanStudio } from './components/NewScanStudio';
import { CloudSecurityView } from './components/CloudSecurityView';
import { ScansExplorer } from './components/ScansExplorer';
import { AIPurpleHub } from './components/AIPurpleHub';
import { ReportCenter } from './components/ReportCenter';
import { SchedulerView } from './components/SchedulerView';
import { SettingsAndOrgs } from './components/SettingsAndOrgs';
import { LoginView } from './components/LoginView';
import { ToastProvider, useToast } from './components/UIFeedback';
import { useI18n } from './i18n/LanguageContext';

import { 
  Organization, 
  ScannerProfile, 
  EngineStatus, 
  Scan, 
  Finding, 
  NSEScript, 
  Schedule,
  AuthUser 
} from './types';
import { api } from './services/api';

const AppContent: React.FC = () => {
  const { showToast } = useToast();
  const { L } = useI18n();

  // Authentication State
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [isAuthChecking, setIsAuthChecking] = useState<boolean>(true);

  // Theme State (Persisted in localStorage, defaults to 'uriel-ops')
  const [currentTheme, setCurrentTheme] = useState<PortalTheme>(() => {
    return (localStorage.getItem('uriel_portal_theme') as PortalTheme) || 'uriel-ops';
  });

  // Apply theme to document root & dynamically sync Chrome tab favicon to active theme
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', currentTheme);
    localStorage.setItem('uriel_portal_theme', currentTheme);
    const favLink = document.querySelector("link[rel='icon']") as HTMLLinkElement | null;
    if (favLink) {
      favLink.href = `/favicon-${currentTheme}.png`;
    }
  }, [currentTheme]);

  // Check auth session on startup
  useEffect(() => {
    const token = localStorage.getItem('uriel_token');
    if (!token) {
      setIsAuthenticated(false);
      setIsAuthChecking(false);
      return;
    }

    api.getAuthMe()
      .then((res) => {
        setIsAuthenticated(true);
        setCurrentUser(res.user);
      })
      .catch(() => {
        localStorage.removeItem('uriel_token');
        setIsAuthenticated(false);
      })
      .finally(() => {
        setIsAuthChecking(false);
      });
  }, []);

  // Navigation & Global Scope
  const [currentView, setCurrentView] = useState<ViewType>('dashboard');
  const [selectedOrgId, setSelectedOrgId] = useState<string>('ALL');

  // Core Data State
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [scannerProfile, setScannerProfile] = useState<ScannerProfile>({
    company_name: 'UrielScan Purple Team MSSP',
    contact_email: 'secops@urielscan.io',
    website: 'https://urielscan.io',
    report_footer: 'Documento Riservato - Valutazione Vulnerabilità Purple Team',
    ai_provider: 'gemini',
    ai_model: 'gemini-2.5-flash',
  });
  const [engineStatus, setEngineStatus] = useState<EngineStatus>({
    nmap: { available: true, version: '7.95', scripts_count: 614 },
    nuclei: { available: true, version: 'v3.3.7' },
    native: { available: true },
    ai: { configured: true, provider: 'Google Gemini', model: 'gemini-2.5-flash' },
  });
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [nseScripts, setNseScripts] = useState<NSEScript[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);

  // Selection states
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [explorerTab, setExplorerTab] = useState<'findings' | 'hosts' | 'logs'>('findings');
  const [explorerSeverityFilter, setExplorerSeverityFilter] = useState<string>('all');
  const [explorerEngineFilter, setExplorerEngineFilter] = useState<string>('all');

  const prevScansRef = useRef<Scan[]>([]);
  useEffect(() => {
    prevScansRef.current = scans;
  }, [scans]);

  // Initial Load
  const loadInitialData = useCallback(async () => {
    try {
      const [orgs, profile, eng, scs, fnds, nse, scheds] = await Promise.all([
        api.getOrganizations(),
        api.getScannerProfile(),
        api.getEngineStatus(),
        api.getScans(),
        api.getFindings(),
        api.getNSEScripts(),
        api.getSchedules(),
      ]);

      setOrganizations(orgs);
      setScannerProfile(profile);
      setEngineStatus(eng);
      setScans(scs);
      setFindings(fnds);
      setNseScripts(nse);
      setSchedules(scheds);

      if (scs.length === 0) {
        setSelectedScanId(null);
        setSelectedFinding(null);
      } else {
        setSelectedScanId((prev) => {
          if (prev === 'ALL') return 'ALL';
          if (prev && scs.some((s) => s.id === prev)) return prev;
          return scs[0].id;
        });
      }
    } catch (e) {
      console.warn('Errore nel caricamento iniziale dei dati:', e);
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      loadInitialData();
    }
  }, [isAuthenticated, loadInitialData]);

  // Live polling while background engine bootstrap (Nmap/Nuclei/ZAP) installs missing tools
  useEffect(() => {
    if (!isAuthenticated || !engineStatus.bootstrap?.running) return;
    const timer = setInterval(async () => {
      try {
        const updated = await api.getEngineStatus();
        setEngineStatus((prev) => {
          if (!prev.nmap.available && updated.nmap.available) {
            api.getNSEScripts().then(setNseScripts).catch(() => {});
          }
          return updated;
        });
        if (!updated.bootstrap?.running) {
          api.getNSEScripts().then(setNseScripts).catch(() => {});
        }
      } catch {
        // ignore transient poll error
      }
    }, 5000);
    return () => clearInterval(timer);
  }, [isAuthenticated, engineStatus.bootstrap?.running]);

  // REAL Polling for running scans (NO artificial local increments!)
  useEffect(() => {
    if (!isAuthenticated) return;
    const hasRunning = scans.some((s) => s.status === 'running' || s.status === 'queued');
    if (!hasRunning) return;

    const interval = setInterval(async () => {
      try {
        const updatedScans = await api.getScans();
        
        // Detect transitions from 'running'/'queued' to 'completed'
        const newlyCompleted = updatedScans.filter((us) => {
          const prev = prevScansRef.current.find((ps) => ps.id === us.id);
          return prev && (prev.status === 'running' || prev.status === 'queued') && us.status === 'completed';
        });

        if (newlyCompleted.length > 0) {
          for (const cs of newlyCompleted) {
            const count = cs.findings_count;
            const total =
              (count.critical || 0) +
              (count.high || 0) +
              (count.medium || 0) +
              (count.low || 0) +
              (count.info || 0);
            showToast(
              L(
                `Scan "${cs.name}" completed. Detected ${total} finding(s) and ${(cs.hosts || []).length} host(s).`,
                `Scansione "${cs.name}" completata. Rilevati ${total} finding(s) e ${(cs.hosts || []).length} host.`
              ),
              'success',
              L('Scan Finished', 'Scansione Terminata')
            );
          }
          // Refresh findings and org stats
          const [updatedFindings, updatedOrgs] = await Promise.all([
            api.getFindings(),
            api.getOrganizations(),
          ]);
          setFindings(updatedFindings);
          setOrganizations(updatedOrgs);
        }

        setScans(updatedScans);
      } catch (err) {
        console.warn('Errore durante il polling delle scansioni:', err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [isAuthenticated, scans, showToast, L]);

  // Navigation handlers
  const handleNavigateToScan = (scanId: string) => {
    setSelectedScanId(scanId);
    setSelectedFinding(null);
    setExplorerTab('findings');
    setExplorerSeverityFilter('all');
    setExplorerEngineFilter('all');
    setCurrentView('scans');
  };

  const handleNavigateToScansWithFilter = (options: {
    tab?: 'findings' | 'hosts' | 'logs';
    severity?: string;
    engine?: string;
    scanId?: string;
  }) => {
    if (options.scanId) {
      setSelectedScanId(options.scanId);
    } else if (!selectedScanId && scans.length > 0) {
      setSelectedScanId(scans[0].id);
    }
    setSelectedFinding(null);
    setExplorerTab(options.tab || 'findings');
    setExplorerSeverityFilter(options.severity || 'all');
    setExplorerEngineFilter(options.engine || 'all');
    setCurrentView('scans');
  };

  const handleSelectFinding = (finding: Finding) => {
    setSelectedScanId(finding.scan_id);
    setSelectedFinding(finding);
    setExplorerTab('findings');
    setCurrentView('scans');
  };

  const handleScanCreated = (newScan: Scan) => {
    setScans((prev) => [newScan, ...prev]);
    setSelectedScanId(newScan.id);
    if (selectedOrgId !== 'ALL' && selectedOrgId !== newScan.org_id) {
      setSelectedOrgId(newScan.org_id);
    }
    setExplorerTab('findings');
    setExplorerSeverityFilter('all');
    setExplorerEngineFilter('all');
    setCurrentView('scans');
  };

  const handleStartScan = async (payload: any) => {
    return await api.createScan(payload);
  };

  const handleStopScan = async (scanId: string) => {
    try {
      await api.stopScan(scanId);
      setScans((prev) =>
        prev.map((s) => (s.id === scanId ? { ...s, status: 'stopped' } : s))
      );
      showToast(L(`Scan #${scanId} stopped.`, `Scansione #${scanId} interrotta.`), 'info');
    } catch (err: any) {
      showToast(err.message || L('Error stopping scan.', 'Errore interruzione scansione.'), 'error');
    }
  };

  const handleDeleteScan = async (scanId: string) => {
    try {
      await api.deleteScan(scanId);
      setScans((prev) => {
        const remaining = prev.filter((s) => s.id !== scanId);
        if (selectedScanId === scanId) {
          setSelectedScanId(remaining[0]?.id || null);
        }
        return remaining;
      });
      setFindings((prev) => prev.filter((f) => f.scan_id !== scanId));
      showToast(L(`Scan #${scanId} successfully deleted.`, `Scansione #${scanId} eliminata con successo.`), 'info');
    } catch (err: any) {
      showToast(err.message || L('Error deleting scan.', 'Errore eliminazione scansione.'), 'error');
    }
  };

  const handleAnalyzeWithAI = (scanId: string) => {
    setSelectedScanId(scanId);
    setCurrentView('ai-hub');
  };

  const handleLogout = async () => {
    await api.logout();
    setIsAuthenticated(false);
    setCurrentUser(null);
    showToast(L('Session disconnected.', 'Sessione disconnessa.'), 'info');
  };

  const runningScansCount = scans.filter((s) => s.status === 'running' || s.status === 'queued').length;

  if (isAuthChecking) {
    return (
      <div className="min-h-screen w-full flex items-center justify-center bg-canvas">
        <div className="flex items-center space-x-2 text-xs font-mono text-theme-muted">
          <span className="w-2 h-2 rounded-full bg-theme-accent animate-pulse" />
          <span>{L('Verifying security session...', 'Verifica sessione di sicurezza...')}</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <LoginView
        currentTheme={currentTheme}
        onLoginSuccess={(user) => {
          setIsAuthenticated(true);
          setCurrentUser(user);
          showToast(
            L(`Welcome operator ${user.username}.`, `Benvenuto operatore ${user.username}.`),
            'success',
            L('Authentication Successful', 'Accesso Effettuato')
          );
        }}
      />
    );
  }

  return (
    <div className="h-screen overflow-hidden bg-canvas text-theme-primary flex flex-col font-sans">
      {/* Topbar */}
      <Navbar
        selectedOrgId={selectedOrgId}
        onSelectOrg={setSelectedOrgId}
        organizations={organizations}
        scannerProfile={scannerProfile}
        engineStatus={engineStatus}
        onNewScanClick={() => setCurrentView('new-scan')}
        currentUser={currentUser}
        onLogout={handleLogout}
        currentTheme={currentTheme}
        onThemeChange={setCurrentTheme}
      />

      {/* Main Container */}
      <div className="flex-1 min-h-0 flex overflow-hidden">
        {/* Sidebar */}
        <Sidebar
          currentView={currentView}
          onNavigate={(view) => {
            setCurrentView(view);
            if (view !== 'scans') setSelectedFinding(null);
          }}
          runningScansCount={runningScansCount}
        />

        {/* Content Area */}
        {currentView === 'new-scan' ? (
          <main className="flex-1 min-h-0 overflow-hidden bg-canvas flex flex-col">
            <NewScanStudio
              organizations={organizations}
              selectedOrgId={selectedOrgId}
              nseScripts={nseScripts}
              onScanCreated={handleScanCreated}
              onStartScan={handleStartScan}
              scans={scans}
              onRefreshData={loadInitialData}
            />
          </main>
        ) : (
          <main className="flex-1 min-h-0 overflow-y-auto p-4 lg:p-6 bg-canvas">
            <div className="max-w-7xl mx-auto pb-16">
              {currentView === 'dashboard' && (
                <CommandCenter
                  scans={scans}
                  findings={findings}
                  selectedOrgId={selectedOrgId}
                  organizations={organizations}
                  onNavigateToScan={handleNavigateToScan}
                  onNavigateToNewScan={() => setCurrentView('new-scan')}
                  onSelectFinding={handleSelectFinding}
                  onDeleteScan={handleDeleteScan}
                  onNavigateToScansWithFilter={handleNavigateToScansWithFilter}
                />
              )}

              {currentView === 'cloud-security' && (
                <CloudSecurityView
                  organizations={organizations}
                  selectedOrgId={selectedOrgId}
                  scans={scans}
                  onScanCreated={handleScanCreated}
                  onNavigateToScan={handleNavigateToScan}
                  onRefreshData={loadInitialData}
                />
              )}

              {currentView === 'scans' && (
              <ScansExplorer
                scans={selectedOrgId === 'ALL' ? scans : scans.filter((s) => s.org_id === selectedOrgId)}
                organizations={organizations}
                selectedScanId={selectedScanId}
                onSelectScan={setSelectedScanId}
                onStopScan={handleStopScan}
                onDeleteScan={handleDeleteScan}
                onAnalyzeWithAI={handleAnalyzeWithAI}
                onNavigateToNewScan={() => setCurrentView('new-scan')}
                initialSelectedFinding={selectedFinding}
                initialTab={explorerTab}
                initialSeverityFilter={explorerSeverityFilter}
                initialEngineFilter={explorerEngineFilter}
              />
            )}

            {currentView === 'ai-hub' && (
              <AIPurpleHub
                scans={scans}
                findings={findings}
                selectedScanId={selectedScanId}
                onNavigateToReport={() => setCurrentView('reports')}
              />
            )}

            {currentView === 'reports' && (
              <ReportCenter
                scans={scans}
                findings={findings}
                organizations={organizations}
                scannerProfile={scannerProfile}
                selectedScanId={selectedScanId}
              />
            )}

            {currentView === 'scheduler' && (
              <SchedulerView
                schedules={schedules}
                organizations={organizations}
                selectedOrgId={selectedOrgId}
                onRefreshSchedules={loadInitialData}
                onScanLaunched={(scanId) => {
                  setSelectedScanId(scanId);
                  setCurrentView('scans');
                }}
              />
            )}

            {currentView === 'settings' && (
              <SettingsAndOrgs
                organizations={organizations}
                scannerProfile={scannerProfile}
                engineStatus={engineStatus}
                onRefreshData={loadInitialData}
                currentUser={currentUser}
                onUserUpdated={(u) => setCurrentUser(u)}
              />
            )}
            </div>
          </main>
        )}
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ToastProvider>
      <AppContent />
    </ToastProvider>
  );
};

export default App;
