import React, { useState, useEffect, useRef } from 'react';
import { 
  Radar, 
  Search, 
  Filter, 
  Terminal, 
  Server, 
  Sparkles, 
  CheckCircle2, 
  AlertTriangle, 
  X, 
  StopCircle, 
  Trash2, 
  Layers, 
  Copy, 
  Check, 
  Clock, 
  PlusCircle,
  Loader2,
  ExternalLink,
  Building2,
  Download,
  ChevronDown,
  MoreVertical,
  ArrowLeft,
  Calendar,
  Radio
} from 'lucide-react';
import { Scan, Finding, HostInfo, FindingStatus, SeverityLevel, Organization } from '../types';
import { api } from '../services/api';
import { useToast, ConfirmModal } from './UIFeedback';
import { useI18n } from '../i18n/LanguageContext';

interface ScansExplorerProps {
  scans: Scan[];
  organizations?: Organization[];
  selectedScanId: string | null;
  onSelectScan: (scanId: string) => void;
  onStopScan: (scanId: string) => void;
  onDeleteScan: (scanId: string) => void;
  onAnalyzeWithAI: (scanId: string, findingIds?: string[]) => void;
  onNavigateToNewScan?: () => void;
  initialSelectedFinding?: Finding | null;
  initialTab?: 'findings' | 'hosts' | 'logs';
  initialSeverityFilter?: string;
  initialEngineFilter?: string;
}

export const ScansExplorer: React.FC<ScansExplorerProps> = ({
  scans,
  organizations = [],
  selectedScanId,
  onSelectScan,
  onStopScan,
  onDeleteScan,
  onAnalyzeWithAI,
  onNavigateToNewScan,
  initialSelectedFinding,
  initialTab,
  initialSeverityFilter,
  initialEngineFilter,
}) => {
  const { lang, locale, L } = useI18n();
  const { showToast } = useToast();
  const [activeTab, setActiveTab] = useState<'findings' | 'hosts' | 'recon' | 'logs'>((initialTab as any) || 'findings');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [hosts, setHosts] = useState<(HostInfo & { org_id?: string; scan_name?: string })[]>([]);
  const [isLoadingDetails, setIsLoadingDetails] = useState<boolean>(false);
  const [exportingFormat, setExportingFormat] = useState<'csv' | 'txt' | 'pdf' | null>(null);
  const [isScanDropdownOpen, setIsScanDropdownOpen] = useState<boolean>(false);
  const [showAllScansHistory, setShowAllScansHistory] = useState<boolean>(false);
  const [historySearch, setHistorySearch] = useState<string>('');
  const [openRowMenu, setOpenRowMenu] = useState<{ scan: Scan; top: number; right: number } | null>(null);
  const [scanToDelete, setScanToDelete] = useState<Scan | null>(null);
  const scanDropdownRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (scanDropdownRef.current && !scanDropdownRef.current.contains(e.target as Node)) {
        setIsScanDropdownOpen(false);
      }
      setOpenRowMenu(null);
    };
    const handleScroll = () => setOpenRowMenu(null);
    document.addEventListener('mousedown', handleClickOutside);
    window.addEventListener('scroll', handleScroll, true);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      window.removeEventListener('scroll', handleScroll, true);
    };
  }, []);

  const formatScanDateTime = (iso?: string) => {
    if (!iso) return L('N/A', 'N/D');
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return L('N/A', 'N/D');
    return `${d.toLocaleDateString(locale)} • ${d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
  };

  const formatScanDuration = (startedAt?: string, completedAt?: string, status?: string) => {
    if (status === 'queued') return L('Queued on probe...', 'In coda sulla sonda...');
    if (status === 'running') return L('In progress...', 'In corso...');
    if (!startedAt || !completedAt) return L('N/A', 'N/D');
    const start = new Date(startedAt).getTime();
    const end = new Date(completedAt).getTime();
    if (Number.isNaN(start) || Number.isNaN(end) || end < start) return L('N/A', 'N/D');
    const sec = Math.round((end - start) / 1000);
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
    return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
  };

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedOrgFilter, setSelectedOrgFilter] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>(initialSeverityFilter || 'all');
  const [selectedEngine, setSelectedEngine] = useState<string>(initialEngineFilter || 'all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');

  const getOrgName = (orgId?: string) => {
    if (!orgId) return L('Organization', 'Organizzazione');
    const found = organizations.find((o) => String(o.id) === String(orgId));
    return found ? found.name : `Org #${orgId}`;
  };

  const getScanName = (scanId?: string) => {
    if (!scanId) return '';
    const found = scans.find((s) => String(s.id) === String(scanId));
    return found ? found.name : `Scan #${scanId}`;
  };

  const handleExportScan = async (format: 'csv' | 'txt' | 'pdf') => {
    const targetId = isAllScansMode ? 'ALL' : currentScan?.id;
    if (!targetId) return;
    setExportingFormat(format);
    try {
      await api.downloadScanExport(targetId, format, lang);
      showToast(L(`${format.toUpperCase()} export completed.`, `Esportazione ${format.toUpperCase()} completata.`), 'success');
    } catch (err: any) {
      showToast(err?.message || L(`${format.toUpperCase()} export error`, `Errore esportazione ${format.toUpperCase()}`), 'error');
    } finally {
      setExportingFormat(null);
    }
  };

  // Sync deep-link filters when navigating from Command Center
  useEffect(() => {
    if (initialTab) setActiveTab(initialTab);
  }, [initialTab]);

  useEffect(() => {
    if (initialSeverityFilter) setSelectedSeverity(initialSeverityFilter);
  }, [initialSeverityFilter]);

  useEffect(() => {
    if (initialEngineFilter) setSelectedEngine(initialEngineFilter);
  }, [initialEngineFilter]);

  // Checkbox multi-select for AI Analysis
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);

  // Drawer detail for single finding
  const [inspectingFinding, setInspectingFinding] = useState<Finding | null>(initialSelectedFinding || null);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);
  const [copiedEvidence, setCopiedEvidence] = useState<boolean>(false);

  // Confirm delete modal state
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState<boolean>(false);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);

  // Current scan (or null if viewing ALL scans in aggregated MSP mode)
  const isAllScansMode = selectedScanId === 'ALL';
  const currentScan = isAllScansMode
    ? undefined
    : scans.find((s) => s.id === selectedScanId) || scans[0];
  const lastFetchedIdRef = React.useRef<string | null>(null);

  // Load findings and hosts when currentScan ID changes, or in ALL scans mode, or when scan transitions running -> completed
  useEffect(() => {
    if (isAllScansMode) {
      const isNewSelection = lastFetchedIdRef.current !== 'ALL';
      if (isNewSelection) {
        setIsLoadingDetails(true);
        lastFetchedIdRef.current = 'ALL';
      }
      const allowedScanIds = new Set(scans.map((s) => String(s.id)));
      api.getFindings()
        .then((allF) => {
          const scopedF = allF.filter((f) => allowedScanIds.has(String(f.scan_id)));
          setFindings(scopedF);
          const aggHosts: (HostInfo & { org_id?: string; scan_name?: string })[] = [];
          for (const sc of scans) {
            for (const h of sc.hosts || []) {
              aggHosts.push({ ...h, org_id: sc.org_id, scan_name: sc.name });
            }
          }
          setHosts(aggHosts);
          setIsLoadingDetails(false);
        })
        .catch((e) => {
          console.warn('Errore caricamento aggregato MSP:', e);
          setIsLoadingDetails(false);
        });
    } else if (currentScan) {
      const isNewScanSelection = lastFetchedIdRef.current !== currentScan.id;
      if (isNewScanSelection) {
        setIsLoadingDetails(true);
        lastFetchedIdRef.current = currentScan.id;
      }
      Promise.all([
        api.getFindings(currentScan.id),
        api.getHosts(currentScan.id)
      ]).then(([fList, hList]) => {
        setFindings(fList);
        const rawHosts = hList.length > 0 ? hList : (currentScan.hosts || []);
        setHosts(rawHosts.map((h) => ({ ...h, org_id: currentScan.org_id, scan_name: currentScan.name })));
        setIsLoadingDetails(false);
      }).catch((e) => {
        console.warn('Errore caricamento dettagli scansione:', e);
        setIsLoadingDetails(false);
      });
    } else {
      setFindings([]);
      setHosts([]);
      lastFetchedIdRef.current = null;
    }
  }, [
    isAllScansMode,
    scans.length,
    currentScan?.id,
    currentScan?.status,
    currentScan?.findings_count?.critical,
    currentScan?.findings_count?.high,
    currentScan?.findings_count?.medium,
    currentScan?.findings_count?.low,
    currentScan?.findings_count?.info,
  ]);

  useEffect(() => {
    if (initialSelectedFinding) {
      setInspectingFinding(initialSelectedFinding);
    }
  }, [initialSelectedFinding]);

  // Handle Finding status update
  const handleUpdateStatus = async (id: string, newStatus: FindingStatus) => {
    try {
      const updated = await api.updateFindingStatus(id, newStatus);
      setFindings((prev) => prev.map((f) => (f.id === id ? updated : f)));
      if (inspectingFinding && inspectingFinding.id === id) {
        setInspectingFinding(updated);
      }
      showToast(L(`Vulnerability status set to "${newStatus}".`, `Stato vulnerabilità impostato su "${newStatus}".`), 'info');
    } catch (err: any) {
      showToast(err.message || L('Error updating vulnerability.', 'Errore aggiornamento vulnerabilità.'), 'error');
    }
  };

  // Run AI Purple analysis on single finding
  const handleSingleFindingAI = async (finding: Finding) => {
    setIsAiLoading(true);
    try {
      const result = await api.analyzeWithAI({
        scan_id: finding.scan_id,
        finding_ids: [finding.id],
        mode: 'purple',
        lang: lang,
      });

      const enrichedFinding: Finding = {
        ...finding,
        ai_insight: {
          red_team_scenario: result.red_team_paths[0] || L('Attack vector identified by AI model.', 'Vettore di attacco identificato dal modello AI.'),
          blue_team_fix: result.blue_team_priorities[0] || L('Apply recommended countermeasures.', 'Applica le contromisure consigliate.'),
          code_snippet: result.remediation_script,
          mitre_attack_id: result.mitre_techniques[0]?.id || 'T1190'
        }
      };

      setFindings((prev) => prev.map((f) => (f.id === finding.id ? enrichedFinding : f)));
      setInspectingFinding(enrichedFinding);
      showToast(L('Purple Team AI insight completed.', 'Approfondimento Purple Team AI completato.'), 'success');
    } catch (err: any) {
      showToast(err.message || L('AI analysis failed.', 'Analisi AI fallita.'), 'error');
    } finally {
      setIsAiLoading(false);
    }
  };

  const toggleSelectFinding = (id: string) => {
    setSelectedFindingIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedEvidence(true);
    setTimeout(() => setCopiedEvidence(false), 2000);
    showToast(L('Evidence copied to clipboard.', 'Evidenza copiata negli appunti.'), 'info');
  };

  // EMPTY STATE WHEN NO SCANS EXIST
  if (scans.length === 0) {
    return (
      <div className="card-industrial p-12 text-center max-w-md mx-auto my-12 space-y-4">
        <div className="w-12 h-12 rounded border border-theme bg-subtle flex items-center justify-center mx-auto text-theme-muted">
          <Radar className="w-6 h-6" />
        </div>
        <div>
          <h2 className="text-sm font-bold text-theme-primary">{L('No Scans Recorded', 'Nessuna Scansione Registrata')}</h2>
          <p className="text-xs text-theme-secondary mt-1 leading-relaxed">
            {L('The selected perimeter or organization has no scans recorded in the database yet.', "Il perimetro o l'organizzazione selezionata non ha ancora scansioni registrate nel database.")}
          </p>
        </div>
        {onNavigateToNewScan && (
          <div className="pt-2">
            <button
              onClick={onNavigateToNewScan}
              className="btn-primary inline-flex items-center space-x-1.5 px-4 py-2 text-xs font-semibold"
            >
              <PlusCircle className="w-4 h-4" />
              <span>{L('Launch New Scan', 'Avvia Nuova Scansione')}</span>
            </button>
          </div>
        )}
      </div>
    );
  }

  // Filtered findings list
  const filteredFindings = findings.filter((f) => {
    const orgName = getOrgName(f.org_id);
    const matchSearch =
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      orgName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.service && f.service.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchOrg =
      selectedOrgFilter === 'all' || String(f.org_id) === String(selectedOrgFilter);

    const sevLower = f.severity.toLowerCase();
    const matchSeverity =
      selectedSeverity === 'all' ||
      (selectedSeverity === 'critical_high' && (sevLower === 'critical' || sevLower === 'high')) ||
      sevLower === selectedSeverity.toLowerCase();

    const matchEngine =
      selectedEngine === 'all' ||
      f.source_engine.toLowerCase().split('+').includes(selectedEngine.toLowerCase());

    const matchStatus =
      selectedStatus === 'all' || f.status.toLowerCase() === selectedStatus.toLowerCase();

    return matchSearch && matchOrg && matchSeverity && matchEngine && matchStatus;
  });

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case 'Critical':
        return 'bg-red-950/40 border-red-600/70 text-red-400';
      case 'High':
        return 'bg-orange-950/40 border-orange-600/70 text-orange-400';
      case 'Medium':
        return 'bg-amber-950/40 border-amber-600/70 text-amber-400';
      case 'Low':
        return 'bg-sky-950/40 border-sky-600/70 text-sky-400';
      default:
        return 'bg-subtle border-theme text-theme-secondary';
    }
  };

  const displayLogs = isAllScansMode
    ? scans.flatMap((s) => (s.logs || []).map((l) => `[${getOrgName(s.org_id)} — ${s.name}] ${l}`))
    : (currentScan?.logs || []);

  const orderedScans = [...scans].sort((a, b) => {
    const ta = new Date(a.started_at || 0).getTime();
    const tb = new Date(b.started_at || 0).getTime();
    return tb - ta;
  });

  if (showAllScansHistory) {
    const filteredHistory = orderedScans.filter((s) => {
      if (!historySearch.trim()) return true;
      const q = historySearch.toLowerCase();
      return (
        s.name.toLowerCase().includes(q) ||
        s.targets.toLowerCase().includes(q) ||
        getOrgName(s.org_id).toLowerCase().includes(q)
      );
    });

    return (
      <div className="space-y-4">
        <div className="card-industrial p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center space-x-2 text-[10px] font-mono uppercase font-bold tracking-wider text-theme-accent">
              <Calendar className="w-3.5 h-3.5" />
              <span>{L('Complete Session History', 'Storico Completo Sessioni')}</span>
            </div>
            <h1 className="text-base font-bold text-theme-primary tracking-tight mt-0.5">
              {L('All Scans', 'Tutte le Scansioni')} ({scans.length})
            </h1>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-theme-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={historySearch}
                onChange={(e) => setHistorySearch(e.target.value)}
                placeholder={L('Filter by name, IP, org...', 'Filtra per nome, IP, org...')}
                className="input-industrial pl-8 pr-3 py-1.5 text-xs w-56"
              />
            </div>
            <button
              onClick={() => setShowAllScansHistory(false)}
              className="btn-secondary px-3 py-1.5 text-xs font-semibold flex items-center space-x-1.5"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>{L('Back to scan', 'Torna alla scansione')}</span>
            </button>
          </div>
        </div>

        <div className="card-industrial overflow-visible">
          {filteredHistory.length === 0 ? (
            <div className="p-8 text-center text-xs text-theme-muted font-mono">
              {L('No scans found matching the criteria.', 'Nessuna scansione trovata per i criteri inseriti.')}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-theme bg-subtle/60 text-[10px] font-mono uppercase tracking-wider text-theme-muted">
                    <th className="py-2.5 px-4">{L('Scan / Organization', 'Scansione / Organizzazione')}</th>
                    <th className="py-2.5 px-4">{L('Target / IP', 'Target / IP')}</th>
                    <th className="py-2.5 px-4">{L('Findings (C / H / M)', 'Risultati (C / H / M)')}</th>
                    <th className="py-2.5 px-4">{L('Date, Time & Duration', 'Data, Ora & Durata')}</th>
                    <th className="py-2.5 px-4 text-right">{L('Actions', 'Azioni')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-theme/50 text-xs">
                  {filteredHistory.map((s) => {
                    const counts = s.findings_count || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                    const isSelected = !isAllScansMode && currentScan?.id === s.id;
                    return (
                      <tr
                        key={s.id}
                        onClick={() => {
                          onSelectScan(s.id);
                          setShowAllScansHistory(false);
                        }}
                        className={`cursor-pointer transition-colors hover:bg-subtle/60 ${isSelected ? 'row-selected-theme' : ''}`}
                      >
                        <td className="py-3 px-4">
                          <div className="font-semibold flex items-center gap-2">
                            <span className={isSelected ? 'text-theme-accent font-bold' : 'text-theme-primary'}>{s.name}</span>
                            {isSelected && (
                              <span className="bg-theme-accent text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase shrink-0">
                                {L('SELECTED', 'SELEZIONATA')}
                              </span>
                            )}
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-subtle border border-theme text-theme-secondary">
                              {s.status.toUpperCase()}
                            </span>
                          </div>
                          <div className="text-[11px] font-mono text-theme-accent mt-0.5 flex items-center space-x-1">
                            <Building2 className="w-3 h-3" />
                            <span>{getOrgName(s.org_id)}</span>
                          </div>
                        </td>
                        <td className="py-3 px-4 font-mono text-theme-secondary">
                          {s.targets}
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-1.5 font-mono text-[11px]">
                            <span className="px-1.5 py-0.5 rounded bg-red-950/50 border border-red-700/60 text-red-400 font-bold" title="Critical">
                              C: {counts.critical || 0}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-orange-950/50 border border-orange-700/60 text-orange-400 font-bold" title="High">
                              H: {counts.high || 0}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-amber-950/40 border border-amber-700/60 text-amber-400 font-bold" title="Medium">
                              M: {counts.medium || 0}
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-4 font-mono">
                          <div className="text-theme-primary text-[11px]">{formatScanDateTime(s.started_at)}</div>
                          <div className="text-theme-muted text-[10px] mt-0.5">
                            {L('Duration:', 'Durata:')} {formatScanDuration(s.started_at, s.completed_at, s.status)}
                          </div>
                        </td>
                        <td
                          className="py-3 px-4 text-right"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <button
                            onMouseDown={(e) => e.stopPropagation()}
                            onClick={(e) => {
                              e.stopPropagation();
                              if (openRowMenu?.scan.id === s.id) {
                                setOpenRowMenu(null);
                              } else {
                                const rect = e.currentTarget.getBoundingClientRect();
                                const openUp = window.innerHeight - rect.bottom < 105;
                                setOpenRowMenu({
                                  scan: s,
                                  top: openUp ? Math.max(8, rect.top - 78) : rect.bottom + 4,
                                  right: Math.max(12, window.innerWidth - rect.right),
                                });
                              }
                            }}
                            className="p-1.5 rounded hover:bg-subtle text-theme-secondary hover:text-theme-primary transition-colors"
                            title={L('Scan actions menu', 'Menu azioni scansione')}
                          >
                            <MoreVertical className="w-4 h-4" />
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

        {/* Fixed-position Row Action Menu (escapes table overflow clipping) */}
        {openRowMenu && (
          <div
            onMouseDown={(e) => e.stopPropagation()}
            style={{ top: openRowMenu.top, right: openRowMenu.right }}
            className="fixed z-50 w-44 bg-panel border border-theme rounded shadow-xl py-1 text-left"
          >
            <button
              onClick={() => {
                const targetScan = openRowMenu.scan;
                setOpenRowMenu(null);
                onSelectScan(targetScan.id);
                setShowAllScansHistory(false);
              }}
              className="w-full px-3 py-1.5 text-xs text-theme-primary hover:bg-hover flex items-center space-x-2 cursor-pointer"
            >
              <ExternalLink className="w-3.5 h-3.5 text-theme-accent" />
              <span>{L('Open details', 'Apri dettagli')}</span>
            </button>
            <button
              onClick={() => {
                const targetScan = openRowMenu.scan;
                setOpenRowMenu(null);
                setScanToDelete(targetScan);
                setIsDeleteModalOpen(true);
              }}
              className="w-full px-3 py-1.5 text-xs text-red-400 hover:bg-red-950/40 flex items-center space-x-2 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>{L('Delete scan', 'Elimina scansione')}</span>
            </button>
          </div>
        )}

        {/* Delete Scan Confirm Modal (History View) */}
        {(scanToDelete || currentScan) && (
          <ConfirmModal
            isOpen={isDeleteModalOpen}
            title={`${L('Delete Scan', 'Elimina Scansione')} #${(scanToDelete || currentScan)!.id}`}
            description={L(`Are you sure you want to permanently delete scan "${(scanToDelete || currentScan)!.name}"? All associated findings, logs and discovered hosts will be deleted from the database.`, `Sei sicuro di voler eliminare definitivamente la scansione "${(scanToDelete || currentScan)!.name}"? Tutti i risultati, i log e gli host rilevati verranno cancellati dal database.`)}
            confirmText={L('Delete Scan', 'Elimina Scansione')}
            isDestructive={true}
            isLoading={isDeleting}
            onCancel={() => {
              setIsDeleteModalOpen(false);
              setScanToDelete(null);
            }}
            onConfirm={async () => {
              const target = scanToDelete || currentScan;
              if (!target) return;
              setIsDeleting(true);
              try {
                await onDeleteScan(target.id);
                setIsDeleteModalOpen(false);
                setScanToDelete(null);
              } finally {
                setIsDeleting(false);
              }
            }}
          />
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Scan Selector & Summary Header */}
      <div className="card-industrial p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono uppercase font-bold tracking-wider text-theme-accent">
              {L('Scan Session', 'Sessione di Scansione')}
            </span>
            <span className="text-theme-muted">•</span>

            {/* Custom 2-line Scan Dropdown */}
            <div className="relative" ref={scanDropdownRef}>
              <button
                type="button"
                onClick={() => setIsScanDropdownOpen((prev) => !prev)}
                className="input-industrial px-2.5 py-1 text-left flex items-center justify-between gap-3 min-w-[260px] max-w-[430px]"
              >
                <div className="min-w-0">
                  {isAllScansMode ? (
                    <>
                      <div className="text-xs font-bold text-theme-accent truncate">
                        {L('ALL SCANS', 'TUTTE LE SCANSIONI')} ({scans.length} {L('sessions — MSP Aggregated View', 'sessioni — Vista Aggregata MSP')})
                      </div>
                      <div className="text-[10px] font-mono text-theme-muted truncate">
                        {L('Consolidated multi-organization view', 'Vista consolidata multi-organizzazione')}
                      </div>
                    </>
                  ) : currentScan ? (
                    <>
                      <div className="text-xs font-semibold text-theme-primary truncate">
                        [{getOrgName(currentScan.org_id)}] {currentScan.name} ({currentScan.status.toUpperCase()})
                      </div>
                      <div className="text-[10px] font-mono text-theme-muted truncate">
                        {formatScanDateTime(currentScan.started_at)}
                      </div>
                    </>
                  ) : (
                    <div className="text-xs text-theme-muted">{L('Select scan...', 'Seleziona scansione...')}</div>
                  )}
                </div>
                <ChevronDown className={`w-3.5 h-3.5 text-theme-muted shrink-0 transition-transform ${isScanDropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {isScanDropdownOpen && (
                <div className="absolute left-0 top-full mt-1 z-40 w-[340px] sm:w-[430px] max-h-80 overflow-y-auto card-industrial border border-theme shadow-xl divide-y divide-theme/40">
                  {scans.length > 1 && (
                    <button
                      type="button"
                      onClick={() => {
                        onSelectScan('ALL');
                        setIsScanDropdownOpen(false);
                      }}
                      className={`w-full px-3 py-2 text-left hover:bg-subtle transition-colors ${isAllScansMode ? 'row-selected-theme' : ''}`}
                    >
                      <div className="text-xs font-bold text-theme-accent flex items-center justify-between gap-2">
                        <span>{L('ALL SCANS', 'TUTTE LE SCANSIONI')} ({scans.length} {L('sessions — MSP Aggregated View', 'sessioni — Vista Aggregata MSP')})</span>
                        {isAllScansMode && (
                          <span className="bg-theme-accent text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase shrink-0">
                            {L('ACTIVE', 'ATTIVA')}
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] font-mono text-theme-muted mt-0.5">
                        {L('Full aggregation of all recorded sessions', 'Aggregazione completa di tutte le sessioni registrate')}
                      </div>
                    </button>
                  )}
                  {orderedScans.map((s) => {
                    const active = !isAllScansMode && currentScan?.id === s.id;
                    return (
                      <button
                        key={s.id}
                        type="button"
                        onClick={() => {
                          onSelectScan(s.id);
                          setIsScanDropdownOpen(false);
                        }}
                        className={`w-full px-3 py-2 text-left hover:bg-subtle transition-colors ${active ? 'row-selected-theme' : ''}`}
                      >
                        <div className="text-xs flex items-center justify-between gap-2">
                          <span className={`truncate ${active ? 'text-theme-accent font-bold' : 'text-theme-primary font-semibold'}`}>
                            [{getOrgName(s.org_id)}] {s.name}
                          </span>
                          <div className="flex items-center gap-1.5 shrink-0">
                            {active && (
                              <span className="bg-theme-accent text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase shrink-0">
                                {L('ACTIVE', 'ATTIVA')}
                              </span>
                            )}
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-subtle border border-theme text-theme-secondary shrink-0">
                              {s.status.toUpperCase()}
                            </span>
                          </div>
                        </div>
                        <div className="text-[10px] font-mono text-theme-muted mt-0.5 truncate">
                          {formatScanDateTime(s.started_at)} • {s.targets}
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {currentScan && (
              <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-subtle border border-theme text-[11px] font-mono font-semibold text-theme-accent">
                <Building2 className="w-3 h-3" />
                <span>{getOrgName(currentScan.org_id)}</span>
              </span>
            )}

            {currentScan?.agent_name && (
              <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-800 text-[11px] font-mono font-semibold text-cyan-300">
                <Radio className="w-3 h-3 text-cyan-400 animate-pulse" />
                <span>Probe: {currentScan.agent_name}</span>
              </span>
            )}

            <button
              type="button"
              onClick={() => setShowAllScansHistory(true)}
              className="text-xs font-semibold text-theme-accent hover:underline ml-1 cursor-pointer"
            >
              {L('View all', 'Vedi tutte')}
            </button>
          </div>

          <h1 className="text-base font-bold text-theme-primary tracking-tight">
            {isAllScansMode
              ? L('MSP Aggregated View — All Scans & Organizations', 'Vista Aggregata MSP — Tutte le Scansioni & Organizzazioni')
              : currentScan?.name}
          </h1>

          {isAllScansMode ? (
            <div className="flex flex-wrap items-center gap-2 text-xs text-theme-secondary font-mono">
              <span>{L('Sessions included:', 'Sessioni incluse:')} <strong className="text-theme-primary">{scans.length}</strong></span>
              <span>•</span>
              <span>{L('Total findings:', 'Finding totali:')} <strong className="text-theme-primary">{findings.length}</strong></span>
              <span>•</span>
              <span>{L('Mapped hosts:', 'Host mappati:')} <strong className="text-theme-primary">{hosts.length}</strong></span>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2 text-xs text-theme-secondary font-mono">
              <span>{L('Organization:', 'Organizzazione:')} <strong className="text-theme-accent">{getOrgName(currentScan?.org_id)}</strong></span>
              <span>•</span>
              <span>Target: <strong className="text-theme-primary">{currentScan?.targets}</strong></span>
              <span>•</span>
              <span>{L('Profile:', 'Profilo:')} {currentScan?.scan_type}</span>
              <span>•</span>
              <span className="flex items-center space-x-1">
                <Clock className="w-3 h-3 text-theme-muted" />
                <span>{new Date(currentScan?.started_at || '').toLocaleTimeString(locale)}</span>
              </span>
            </div>
          )}
        </div>

        {/* Scan Actions */}
        <div className="flex flex-wrap items-center gap-2">
          {(isAllScansMode || currentScan) && scans.length > 0 && (
            <div className="flex items-center rounded border border-theme-border bg-theme-surface/70 p-0.5">
              {(['csv', 'txt', 'pdf'] as const).map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => handleExportScan(fmt)}
                  disabled={exportingFormat !== null}
                  className="px-2 py-1 text-[11px] font-mono font-semibold text-theme-secondary hover:text-theme-primary hover:bg-theme-elevated rounded flex items-center space-x-1 transition-colors disabled:opacity-50"
                  title={`${L('Export results as', 'Esporta risultati in formato')} ${fmt.toUpperCase()}`}
                >
                  {exportingFormat === fmt ? (
                    <Loader2 className="w-3 h-3 animate-spin" />
                  ) : (
                    <Download className="w-3 h-3" />
                  )}
                  <span>{fmt.toUpperCase()}</span>
                </button>
              ))}
            </div>
          )}

          {(currentScan?.status === 'running' || currentScan?.status === 'queued') && (
            <button
              onClick={() => onStopScan(currentScan.id)}
              className="px-3 py-1.5 rounded text-xs font-semibold bg-red-950/60 text-red-300 border border-red-800 hover:bg-red-900 flex items-center space-x-1"
            >
              <StopCircle className="w-3.5 h-3.5" />
              <span>{L('Stop', 'Interrompi')}</span>
            </button>
          )}

          {currentScan && (
            <button
              onClick={() => setIsDeleteModalOpen(true)}
              className="btn-secondary px-3 py-1.5 text-xs font-semibold text-theme-muted hover:text-red-400 flex items-center space-x-1"
              title={L('Delete this scan', 'Elimina questa scansione')}
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>{L('Delete', 'Elimina')}</span>
            </button>
          )}

          {(currentScan || scans[0]) && (
            <button
              onClick={() => onAnalyzeWithAI((currentScan || scans[0]).id)}
              className="btn-primary px-3 py-1.5 text-xs font-semibold flex items-center space-x-1.5"
            >
              <Sparkles className="w-3.5 h-3.5 fill-current" />
              <span>{L('Purple Team AI Analysis', 'Analisi AI Purple Team')}</span>
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar (if running or queued) */}
      {(currentScan?.status === 'running' || currentScan?.status === 'queued') && (
        <div className={`p-3 rounded border space-y-1 ${
          currentScan.status === 'queued'
            ? 'border-cyan-500/40 bg-cyan-950/10'
            : 'border-amber-500/40 bg-amber-950/10'
        }`}>
          <div className="flex justify-between text-xs font-mono">
            <span className={`font-semibold flex items-center space-x-1.5 ${
              currentScan.status === 'queued' ? 'text-cyan-400' : 'text-amber-400'
            }`}>
              <span className={`w-2 h-2 rounded-full animate-pulse ${
                currentScan.status === 'queued' ? 'bg-cyan-400' : 'bg-amber-400'
              }`} />
              <span>
                {currentScan.status === 'queued'
                  ? L('QUEUED — WAITING FOR REMOTE PROBE...', 'IN CODA — IN ATTESA DELLA SONDA REMOTA...')
                  : L('SCAN IN PROGRESS ON SERVER...', 'SCANSIONE IN CORSO SUL SERVER...')}
              </span>
            </span>
            <span className={`font-bold tabular-nums ${
              currentScan.status === 'queued' ? 'text-cyan-300' : 'text-amber-300'
            }`}>{currentScan.progress}%</span>
          </div>
          <div className={`w-full bg-panel rounded-full h-1.5 overflow-hidden border ${
            currentScan.status === 'queued' ? 'border-cyan-500/30' : 'border-amber-500/30'
          }`}>
            <div
              className={`h-1.5 transition-all duration-500 ${
                currentScan.status === 'queued' ? 'bg-cyan-400' : 'bg-amber-400'
              }`}
              style={{ width: `${currentScan.progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center space-x-1 border-b border-theme pb-1 text-xs">
        <button
          onClick={() => setActiveTab('findings')}
          className={`px-3 py-1.5 rounded text-xs font-semibold border transition ${
            activeTab === 'findings' ? 'border-theme-accent bg-subtle text-theme-primary' : 'border-transparent text-theme-muted hover:text-theme-primary'
          }`}
        >
          {L('Discovered Vulnerabilities', 'Vulnerabilità Rilevate')} ({findings.length})
        </button>
        <button
          onClick={() => setActiveTab('hosts')}
          className={`px-3 py-1.5 rounded text-xs font-semibold border transition ${
            activeTab === 'hosts' ? 'border-theme-accent bg-subtle text-theme-primary' : 'border-transparent text-theme-muted hover:text-theme-primary'
          }`}
        >
          {L('Hosts & Ports', 'Host & Porte')} ({hosts.length})
        </button>
        {currentScan?.recon && (
          <button
            onClick={() => setActiveTab('recon')}
            className={`px-3 py-1.5 rounded text-xs font-semibold border transition ${
              activeTab === 'recon' ? 'border-theme-accent bg-subtle text-theme-primary' : 'border-transparent text-theme-muted hover:text-theme-primary'
            }`}
          >
            {L('Recon / Surface & Tech', 'Recon / Superficie & Tech')} ({currentScan.recon.tech_stack?.length ?? 0} {L('tech', 'tech')} • {currentScan.recon.external_osint?.length ?? 0} OSINT • {currentScan.recon.total_subdomains ?? 0}/{currentScan.recon.directories?.length ?? 0})
          </button>
        )}
        <button
          onClick={() => setActiveTab('logs')}
          className={`px-3 py-1.5 rounded text-xs font-semibold border transition ${
            activeTab === 'logs' ? 'border-theme-accent bg-subtle text-theme-primary' : 'border-transparent text-theme-muted hover:text-theme-primary'
          }`}
        >
          {L('Live Console & Engine Logs', 'Console Live & Log Motori')} ({displayLogs.length})
        </button>
      </div>

      {/* TAB 1: FINDINGS */}
      {activeTab === 'findings' && (
        <div className="space-y-3">
          {/* Filters Bar */}
          <div className="card-industrial p-3 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex flex-wrap items-center gap-2 flex-1">
              <div className="relative min-w-[200px] flex-1">
                <Search className="w-3.5 h-3.5 text-theme-muted absolute left-2.5 top-2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder={L('Filter vulnerabilities, company, host, CVE or service...', 'Filtra vulnerabilità, azienda, host, CVE o servizio...')}
                  className="input-industrial w-full pl-8 pr-2.5 py-1 text-xs"
                />
              </div>

              {organizations.length > 0 && (
                <select
                  value={selectedOrgFilter}
                  onChange={(e) => setSelectedOrgFilter(e.target.value)}
                  className="input-industrial px-2 py-1 text-xs font-semibold"
                >
                  <option value="all" className="bg-panel text-theme-primary">{L('All Organizations', 'Tutte le Organizzazioni')}</option>
                  {organizations.map((org) => (
                    <option key={org.id} value={org.id} className="bg-panel text-theme-primary">
                      {org.name}
                    </option>
                  ))}
                </select>
              )}

              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="input-industrial px-2 py-1 text-xs"
              >
                <option value="all" className="bg-panel text-theme-primary">{L('All Severities', 'Tutte le Severità')}</option>
                <option value="critical_high" className="bg-panel text-theme-primary">{L('Critical & High (Critical + High)', 'Critiche & Alte (Critical + High)')}</option>
                <option value="critical" className="bg-panel text-theme-primary">{L('Critical', 'Critica')}</option>
                <option value="high" className="bg-panel text-theme-primary">{L('High', 'Alta')}</option>
                <option value="medium" className="bg-panel text-theme-primary">{L('Medium', 'Media')}</option>
                <option value="low" className="bg-panel text-theme-primary">{L('Low', 'Bassa')}</option>
                <option value="info" className="bg-panel text-theme-primary">{L('Informational', 'Informativa')}</option>
              </select>

              <select
                value={selectedEngine}
                onChange={(e) => setSelectedEngine(e.target.value)}
                className="input-industrial px-2 py-1 text-xs"
              >
                <option value="all" className="bg-panel text-theme-primary">{L('All Engines', 'Tutti i Motori')}</option>
                <option value="nmap" className="bg-panel text-theme-primary">Nmap NSE</option>
                <option value="nuclei" className="bg-panel text-theme-primary">Nuclei</option>
                <option value="zap" className="bg-panel text-theme-primary">OWASP ZAP</option>
                <option value="subraptor" className="bg-panel text-theme-primary">SubRaptor</option>
                <option value="httpx" className="bg-panel text-theme-primary">PD httpx</option>
                <option value="subzy" className="bg-panel text-theme-primary">Subzy Takeover</option>
                <option value="dns_zone" className="bg-panel text-theme-primary">DNS Zone AXFR</option>
                <option value="feroxbuster" className="bg-panel text-theme-primary">Feroxbuster</option>
                <option value="native_web" className="bg-panel text-theme-primary">Native Web</option>
                <option value="native_net" className="bg-panel text-theme-primary">Native Net</option>
              </select>
            </div>

            {selectedFindingIds.length > 0 && (currentScan || scans[0]) && (
              <button
                onClick={() => onAnalyzeWithAI((currentScan || scans[0]).id, selectedFindingIds)}
                className="btn-primary px-3 py-1 text-xs font-semibold flex items-center space-x-1"
              >
                <Sparkles className="w-3 h-3 fill-current" />
                <span>{L('Analyze Selected', 'Analizza Selezionati')} ({selectedFindingIds.length})</span>
              </button>
            )}
          </div>

          {/* Table */}
          <div className="card-industrial overflow-x-auto">
            <table className="w-full text-left border-collapse table-industrial text-xs">
              <thead>
                <tr>
                  <th className="p-2.5 w-8">
                    <input
                      type="checkbox"
                      checked={selectedFindingIds.length > 0 && selectedFindingIds.length === filteredFindings.length}
                      onChange={() => {
                        if (selectedFindingIds.length === filteredFindings.length) {
                          setSelectedFindingIds([]);
                        } else {
                          setSelectedFindingIds(filteredFindings.map((f) => f.id));
                        }
                      }}
                      className="rounded"
                    />
                  </th>
                  <th className="p-2.5">{L('Severity / CVSS', 'Severità / CVSS')}</th>
                  <th className="p-2.5">{L('Organization', 'Organizzazione')}</th>
                  <th className="p-2.5">{L('Vulnerability Title', 'Titolo Vulnerabilità')}</th>
                  <th className="p-2.5">{L('Host & Port', 'Host & Porta')}</th>
                  <th className="p-2.5">{L('Engine', 'Motore')}</th>
                  <th className="p-2.5">{L('Status', 'Stato')}</th>
                  <th className="p-2.5 text-right">{L('Actions', 'Azioni')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-theme-subtle">
                {isLoadingDetails ? (
                  <tr>
                    <td colSpan={8} className="p-8 text-center text-theme-muted">
                      <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" />
                      <span>{L('Loading vulnerabilities from database...', 'Caricamento vulnerabilità dal database...')}</span>
                    </td>
                  </tr>
                ) : filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-8 text-center text-theme-muted">
                      {currentScan?.status === 'running' ? (
                        <div className="flex flex-col items-center space-y-2">
                          <Loader2 className="w-5 h-5 animate-spin text-amber-400" />
                          <span className="text-amber-400 font-semibold">
                            {L(`Scan in progress on target ${currentScan.targets} (${currentScan.progress}%)...`, `Scansione in corso sul target ${currentScan.targets} (${currentScan.progress}%)...`)}
                          </span>
                          <span className="text-[11px] text-theme-secondary">
                            {L("Discovered findings and hosts will load automatically once analysis finishes. You can track live progress in the 'Live Console & Engine Logs' tab.", "I finding e gli host rilevati verranno caricati automaticamente al completamento dell'analisi. Puoi seguire l'avanzamento in tempo reale nella scheda \"Console Live & Log Motori\".")}
                          </span>
                        </div>
                      ) : (
                        <span>{L('No vulnerabilities match the current filters.', 'Nessuna vulnerabilità corrispondente ai filtri impostati.')}</span>
                      )}
                    </td>
                  </tr>
                ) : (
                  filteredFindings.map((finding) => (
                    <tr
                      key={finding.id}
                      className="hover:bg-subtle cursor-pointer transition-colors"
                      onClick={() => setInspectingFinding(finding)}
                    >
                      <td className="p-2.5" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={selectedFindingIds.includes(finding.id)}
                          onChange={() => toggleSelectFinding(finding.id)}
                          className="rounded"
                        />
                      </td>
                      <td className="p-2.5 whitespace-nowrap font-mono tabular-nums">
                        <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded border uppercase tracking-wider ${getSeverityBadge(finding.severity)}`}>
                          {finding.severity}
                        </span>
                        <span className="text-theme-muted ml-1.5 text-[11px] font-bold">
                          {finding.cvss.toFixed(1)}
                        </span>
                      </td>
                      <td className="p-2.5 whitespace-nowrap">
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-subtle border border-theme text-[11px] font-mono font-semibold text-theme-accent">
                          <Building2 className="w-3 h-3 shrink-0" />
                          <span>{getOrgName(finding.org_id)}</span>
                        </span>
                      </td>
                      <td className="p-2.5 font-medium text-theme-primary">
                        <div className="font-semibold">{finding.title}</div>
                        {isAllScansMode && (
                          <div className="text-[10px] font-mono text-theme-muted mt-0.5">
                            {L('Session:', 'Sessione:')} {getScanName(finding.scan_id)}
                          </div>
                        )}
                        {finding.cve_ids.length > 0 && (
                          <div className="text-[10px] font-mono text-theme-accent space-x-1 mt-0.5">
                            {finding.cve_ids.slice(0, 3).map((cve) => (
                              <span key={cve} className="px-1 rounded bg-subtle border border-theme-subtle">
                                {cve}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="p-2.5 whitespace-nowrap font-mono text-theme-secondary text-[11px]">
                        <span>{finding.host}</span>
                        {finding.port && (
                          <span className="text-theme-muted">:{finding.port}/{finding.protocol || 'tcp'}</span>
                        )}
                      </td>
                      <td className="p-2.5 whitespace-nowrap font-mono text-[11px] text-theme-secondary uppercase">
                        {finding.source_engine}
                      </td>
                      <td className="p-2.5 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <select
                          value={finding.status}
                          onChange={(e) => handleUpdateStatus(finding.id, e.target.value as FindingStatus)}
                          className="input-industrial px-1.5 py-0.5 text-[11px] font-mono uppercase"
                        >
                          <option value="open" className="bg-panel text-theme-primary">{L('Open', 'Aperto')}</option>
                          <option value="in_progress" className="bg-panel text-theme-primary">{L('In Progress', 'In Corso')}</option>
                          <option value="resolved" className="bg-panel text-theme-primary">{L('Resolved', 'Risolto')}</option>
                          <option value="false_positive" className="bg-panel text-theme-primary">{L('False Pos.', 'Falso Pos.')}</option>
                        </select>
                      </td>
                      <td className="p-2.5 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => setInspectingFinding(finding)}
                          className="btn-secondary px-2 py-1 text-[11px] font-medium"
                        >
                          {L('Details', 'Dettagli')}
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: HOSTS */}
      {activeTab === 'hosts' && (
        <div className="card-industrial p-4 space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
            {L('Host Topology & Detected Port Mapping', 'Topologia Host e Mappatura Porte Rilevate')} ({hosts.length})
          </h2>

          <div className="space-y-3">
            {hosts.map((host, idx) => (
              <div key={`${host.ip}-${host.org_id || idx}`} className="p-3 rounded border border-theme bg-subtle space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs">
                  <div className="flex flex-wrap items-center gap-2 font-mono">
                    <Server className="w-4 h-4 text-theme-accent shrink-0" />
                    <span className="font-bold text-theme-primary">{host.ip}</span>
                    {host.hostname && host.hostname !== host.ip && (
                      <span className="text-theme-muted">({host.hostname})</span>
                    )}
                    {host.org_id && (
                      <span className="inline-flex items-center space-x-1 px-1.5 py-0.5 rounded bg-panel border border-theme text-[10px] font-semibold text-theme-accent">
                        <Building2 className="w-3 h-3" />
                        <span>{getOrgName(host.org_id)}</span>
                      </span>
                    )}
                    {host.os && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-panel border border-theme text-theme-secondary">
                        {host.os}
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] font-mono text-theme-secondary space-x-2">
                    <span>{host.ports.length} {L('open ports', 'porte aperte')}</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 gap-2 text-[11px] font-mono pt-1">
                  {host.ports.map((port) => (
                    <div key={`${port.port}-${port.protocol}`} className="p-1.5 rounded bg-panel border border-theme">
                      <div className="font-bold text-theme-primary">
                        {port.port}/{port.protocol}
                      </div>
                      <div className="text-[10px] text-theme-secondary truncate">
                        {port.service || 'tcp'} {port.version ? `(${port.version})` : ''}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: RECON / SURFACE */}
      {activeTab === 'recon' && currentScan?.recon && (
        <div className="space-y-4">
          {/* Recon KPI Strip */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
            <div className="card-industrial p-3">
              <div className="text-[10px] font-mono uppercase text-theme-muted">{L('Total Subdomains', 'Sottodomini Totali')}</div>
              <div className="text-lg font-bold text-theme-primary font-mono">{currentScan.recon.total_subdomains ?? 0}</div>
            </div>
            <div className="card-industrial p-3">
              <div className="text-[10px] font-mono uppercase text-theme-muted">{L('Live HTTP/S', 'HTTP/S Attivi')}</div>
              <div className="text-lg font-bold text-emerald-400 font-mono">{currentScan.recon.live_subdomains?.length ?? 0}</div>
            </div>
            <div className="card-industrial p-3">
              <div className="text-[10px] font-mono uppercase text-theme-muted">{L('Takeovers (Subzy)', 'Takeover (Subzy)')}</div>
              <div className={`text-lg font-bold font-mono ${(currentScan.recon.takeovers?.length ?? 0) > 0 ? 'text-red-400' : 'text-theme-primary'}`}>
                {currentScan.recon.takeovers?.length ?? 0}
              </div>
            </div>
            <div className="card-industrial p-3">
              <div className="text-[10px] font-mono uppercase text-theme-muted">{L('DNS AXFR Open', 'DNS AXFR Aperti')}</div>
              <div className={`text-lg font-bold font-mono ${(currentScan.recon.dns_zones?.filter((z) => z.axfr_vulnerable).length ?? 0) > 0 ? 'text-red-400' : 'text-theme-primary'}`}>
                {currentScan.recon.dns_zones?.filter((z) => z.axfr_vulnerable).length ?? 0}
              </div>
            </div>
            <div className="card-industrial p-3">
              <div className="text-[10px] font-mono uppercase text-theme-muted">{L('Directories (Ferox)', 'Directory (Ferox)')}</div>
              <div className="text-lg font-bold text-sky-400 font-mono">{currentScan.recon.directories?.length ?? 0}</div>
            </div>
            <div className="card-industrial p-3">
              <div className="text-[10px] font-mono uppercase text-theme-muted">{L('Tech Stack', 'Stack Tecnologico')}</div>
              <div className="text-lg font-bold text-theme-accent font-mono">{currentScan.recon.tech_stack?.length ?? 0}</div>
            </div>
            <div className="card-industrial p-3">
              <div className="text-[10px] font-mono uppercase text-theme-muted">{L('CVE / PoC Intel', 'CVE / PoC Intel')}</div>
              <div className={`text-lg font-bold font-mono ${(currentScan.recon.cve_intel?.length ?? 0) > 0 ? 'text-amber-400' : 'text-theme-primary'}`}>
                {currentScan.recon.cve_intel?.length ?? 0}
              </div>
            </div>
            <div className="card-industrial p-3">
              <div className="text-[10px] font-mono uppercase text-theme-muted">{L('External OSINT', 'OSINT Esterno')}</div>
              <div className="text-lg font-bold text-teal-400 font-mono">
                {currentScan.recon.external_osint?.length ?? 0}
              </div>
            </div>
          </div>

          {/* SubRaptor Sources Attribution & DNS Zone Audit */}
          {(Object.keys(currentScan.recon.sources || {}).length > 0 || (currentScan.recon.dns_zones?.length ?? 0) > 0) && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {Object.keys(currentScan.recon.sources || {}).length > 0 && (
                <div className="card-industrial p-4 space-y-2">
                  <div className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
                    {L('SubRaptor Per-Source Breakdown', 'Dettaglio Fonti SubRaptor')}
                  </div>
                  {Object.entries(currentScan.recon.sources || {}).map(([dom, srcMap]) => (
                    <div key={dom} className="space-y-1.5 pt-1">
                      <div className="text-xs font-mono font-bold text-theme-accent">{dom}</div>
                      <div className="flex flex-wrap gap-1.5">
                        {Object.entries(srcMap).map(([srcName, st]) => (
                          <span key={srcName} className="px-2 py-0.5 rounded border border-theme bg-subtle text-[11px] font-mono text-theme-secondary">
                            <span className="font-bold text-theme-primary">{srcName}</span>: {st.found} ({L('uniq', 'unici')} {st.unique}) [{st.status}]
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {(currentScan.recon.dns_zones?.length ?? 0) > 0 && (
                <div className="card-industrial p-4 space-y-2">
                  <div className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
                    {L('DNS Zone & Hygiene Audit', 'Audit Zona DNS & Igiene')}
                  </div>
                  <div className="space-y-2">
                    {(currentScan.recon.dns_zones || []).map((z) => (
                      <div key={z.domain} className="p-2 rounded border border-theme bg-subtle text-xs space-y-1">
                        <div className="flex items-center justify-between font-mono font-bold">
                          <span className="text-theme-primary">{z.domain}</span>
                          <span className={z.axfr_vulnerable ? 'text-red-400' : 'text-emerald-400'}>
                            AXFR: {z.axfr_vulnerable ? `OPEN (${z.axfr_records_count})` : 'Closed'}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-theme-muted flex flex-wrap gap-3">
                          <span>Wildcard: {z.wildcard_dns ? 'Yes' : 'No'}</span>
                          <span>SPF: {z.has_spf ? 'OK' : 'Missing'}</span>
                          <span>DMARC: {z.has_dmarc ? 'OK' : 'Missing'}</span>
                          <span>CAA: {z.has_caa ? 'OK' : 'Missing'}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Live Subdomains (httpx) */}
          {(currentScan.recon.live_subdomains?.length ?? 0) > 0 && (
            <div className="card-industrial p-4 space-y-2">
              <div className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
                {L('Live HTTP/S Subdomains & Tech Stack (httpx)', 'Sottodomini HTTP/S Attivi & Tech Stack (httpx)')}
              </div>
              <div className="overflow-x-auto max-h-80 overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-theme text-[11px] font-mono text-theme-muted">
                    <tr>
                      <th className="py-1.5 pr-3">URL</th>
                      <th className="py-1.5 pr-3">Status</th>
                      <th className="py-1.5 pr-3">Title</th>
                      <th className="py-1.5 pr-3">Tech Stack</th>
                      <th className="py-1.5">CNAME / IP</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-theme-subtle">
                    {(currentScan.recon.live_subdomains || []).map((lr, i) => (
                      <tr key={i} className="hover:bg-subtle">
                        <td className="py-1.5 pr-3 font-mono text-theme-accent break-all">{lr.url || lr.subdomain}</td>
                        <td className="py-1.5 pr-3 font-mono font-bold text-theme-primary">{lr.status_code}</td>
                        <td className="py-1.5 pr-3 text-theme-secondary max-w-xs truncate">{lr.title || '-'}</td>
                        <td className="py-1.5 pr-3 font-mono text-[11px] text-theme-secondary">
                          {(lr.tech || []).join(', ') || lr.webserver || '-'}
                        </td>
                        <td className="py-1.5 font-mono text-[11px] text-theme-muted">
                          {(lr.cname && lr.cname.length > 0 ? lr.cname.join(', ') : lr.ip) || '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Feroxbuster Discovered Paths */}
          {(currentScan.recon.directories?.length ?? 0) > 0 && (
            <div className="card-industrial p-4 space-y-2">
              <div className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
                {L('Discovered Web Paths & Directories (Feroxbuster)', 'Percorsi & Directory Scoperte (Feroxbuster)')}
              </div>
              <div className="overflow-x-auto max-h-80 overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-theme text-[11px] font-mono text-theme-muted">
                    <tr>
                      <th className="py-1.5 pr-3">Status</th>
                      <th className="py-1.5 pr-3">URL / Path</th>
                      <th className="py-1.5 pr-3">Size</th>
                      <th className="py-1.5">Content-Type</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-theme-subtle">
                    {(currentScan.recon.directories || []).map((d, i) => (
                      <tr key={i} className="hover:bg-subtle">
                        <td className="py-1.5 pr-3 font-mono font-bold text-theme-primary">{d.status}</td>
                        <td className="py-1.5 pr-3 font-mono text-theme-accent break-all">{d.url || d.path}</td>
                        <td className="py-1.5 pr-3 font-mono text-theme-secondary">{d.content_length ?? 0} B</td>
                        <td className="py-1.5 font-mono text-[11px] text-theme-muted">{d.content_type || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Detected Technology Stack */}
          {(currentScan.recon.tech_stack?.length ?? 0) > 0 && (
            <div className="card-industrial p-4 space-y-2">
              <div className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
                {L('Detected Technology Stack (Wappalyzer / httpx + Nmap CPE)', 'Stack Tecnologico Rilevato (Wappalyzer / httpx + Nmap CPE)')}
              </div>
              <div className="overflow-x-auto max-h-80 overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-theme text-[11px] font-mono text-theme-muted">
                    <tr>
                      <th className="py-1.5 pr-3">{L('Product', 'Prodotto')}</th>
                      <th className="py-1.5 pr-3">{L('Version', 'Versione')}</th>
                      <th className="py-1.5 pr-3">{L('Category', 'Categoria')}</th>
                      <th className="py-1.5 pr-3">Host / URL</th>
                      <th className="py-1.5">{L('Source', 'Fonte')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-theme-subtle">
                    {(currentScan.recon.tech_stack || []).map((ts, i) => (
                      <tr key={i} className="hover:bg-subtle">
                        <td className="py-1.5 pr-3 font-semibold text-theme-primary">{ts.name}</td>
                        <td className="py-1.5 pr-3 font-mono">
                          {ts.version ? (
                            <span className="px-1.5 py-0.5 rounded bg-subtle border border-theme text-[11px] text-theme-accent">
                              {ts.version}
                            </span>
                          ) : (
                            <span className="text-theme-muted">-</span>
                          )}
                        </td>
                        <td className="py-1.5 pr-3 text-theme-secondary">{ts.category || '-'}</td>
                        <td className="py-1.5 pr-3 font-mono text-[11px] text-theme-secondary break-all">
                          {ts.url || `${ts.host || ''}${ts.port ? `:${ts.port}` : ''}`}
                        </td>
                        <td className="py-1.5 font-mono text-[11px] text-theme-muted">{ts.source || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* CVE & PoC-in-GitHub Intelligence */}
          {(currentScan.recon.cve_intel?.length ?? 0) > 0 && (
            <div className="card-industrial p-4 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
                  {L('CVE, CISA KEV, EPSS & PoC-in-GitHub Intelligence (Version-Based)', 'Correlazione CVE, CISA KEV, EPSS & PoC GitHub (Basata su Versione)')}
                </div>
                <span className="text-[10px] font-mono text-amber-400">
                  {L('Verify OS backporting before remediation', 'Verificare eventuale backporting distro OS')}
                </span>
              </div>
              <div className="overflow-x-auto max-h-80 overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-theme text-[11px] font-mono text-theme-muted">
                    <tr>
                      <th className="py-1.5 pr-3">CVE ID</th>
                      <th className="py-1.5 pr-3">{L('Component', 'Componente')}</th>
                      <th className="py-1.5 pr-3">CVSS / KEV</th>
                      <th className="py-1.5 pr-3">EPSS</th>
                      <th className="py-1.5">{L('Public PoCs', 'PoC Pubblici')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-theme-subtle">
                    {(currentScan.recon.cve_intel || []).map((ci, i) => (
                      <tr key={i} className="hover:bg-subtle">
                        <td className="py-1.5 pr-3 font-mono font-bold text-theme-accent whitespace-nowrap">{ci.cve_id}</td>
                        <td className="py-1.5 pr-3 font-mono text-theme-primary whitespace-nowrap">
                          {ci.product} {ci.version}
                        </td>
                        <td className="py-1.5 pr-3 font-mono whitespace-nowrap">
                          <span className="font-bold text-theme-primary">{ci.cvss}</span>
                          {ci.is_kev && (
                            <span className="ml-1.5 px-1.5 py-0.5 rounded bg-red-500/20 border border-red-500/40 text-red-400 text-[10px] font-bold">
                              CISA KEV
                            </span>
                          )}
                        </td>
                        <td className="py-1.5 pr-3 font-mono text-theme-secondary whitespace-nowrap">
                          {typeof ci.epss === 'number' ? `${(ci.epss * 100).toFixed(2)}%` : '-'}
                        </td>
                        <td className="py-1.5 font-mono text-[11px]">
                          {(ci.poc_urls && ci.poc_urls.length > 0) ? (
                            <div className="flex flex-col space-y-0.5">
                              {ci.poc_urls.slice(0, 3).map((u, idx) => (
                                <a
                                  key={idx}
                                  href={u}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-theme-accent hover:underline break-all"
                                >
                                  {u}
                                </a>
                              ))}
                            </div>
                          ) : (
                            <span className="text-theme-muted">-</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* External OSINT Intelligence (Shodan InternetDB / RIPEstat / GreyNoise) */}
          {(currentScan.recon.external_osint?.length ?? 0) > 0 && (
            <div className="card-industrial p-4 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
                  {L('External OSINT Intelligence (Shodan InternetDB / RIPEstat / GreyNoise)', 'Intelligence OSINT Esterna (Shodan InternetDB / RIPEstat / GreyNoise)')}
                </div>
                <span className="text-[10px] font-mono text-theme-muted">
                  {L('Passive public IP enrichment only', 'Solo arricchimento passivo su IP pubblici')}
                </span>
              </div>
              <div className="overflow-x-auto max-h-80 overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-theme text-[11px] font-mono text-theme-muted">
                    <tr>
                      <th className="py-1.5 pr-3">IP / Hostnames</th>
                      <th className="py-1.5 pr-3">ASN / Org / Prefix</th>
                      <th className="py-1.5 pr-3">{L('Exposed Ports', 'Porte Esposte')}</th>
                      <th className="py-1.5 pr-3">Shodan CVEs / Tags</th>
                      <th className="py-1.5">GreyNoise</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-theme-subtle">
                    {(currentScan.recon.external_osint || []).map((eo, i) => {
                      const gnCls = (eo.greynoise_classification || 'unknown').toLowerCase();
                      const gnBadgeClass =
                        gnCls === 'malicious'
                          ? 'bg-red-500/20 border-red-500/40 text-red-400'
                          : (gnCls === 'benign' || eo.greynoise_riot)
                            ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400'
                            : 'bg-slate-500/15 border-slate-500/30 text-theme-muted';
                      return (
                        <tr key={i} className="hover:bg-subtle">
                          <td className="py-1.5 pr-3 font-mono whitespace-nowrap">
                            <div className="font-bold text-theme-accent">{eo.ip}</div>
                            {(eo.hostnames?.length ?? 0) > 0 && (
                              <div className="text-[10px] text-theme-muted">{eo.hostnames?.slice(0, 2).join(', ')}</div>
                            )}
                          </td>
                          <td className="py-1.5 pr-3 text-theme-primary">
                            <div className="font-mono text-[11px] font-semibold">
                              {[eo.asn, eo.prefix].filter(Boolean).join(' • ') || '-'}
                            </div>
                            {eo.org && <div className="text-[11px] text-theme-secondary">{eo.org}</div>}
                          </td>
                          <td className="py-1.5 pr-3 font-mono text-[11px] text-theme-primary">
                            {(eo.ports && eo.ports.length > 0) ? eo.ports.join(', ') : '-'}
                          </td>
                          <td className="py-1.5 pr-3 font-mono text-[11px]">
                            <div className="flex flex-wrap gap-1">
                              {(eo.tags || []).map((tag, idx) => (
                                <span key={`t-${idx}`} className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[10px]">
                                  {tag}
                                </span>
                              ))}
                              {(eo.vulns || []).slice(0, 6).map((v, idx) => (
                                <span key={`v-${idx}`} className="px-1.5 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-300 text-[10px]">
                                  {v}
                                </span>
                              ))}
                              {!(eo.tags?.length) && !(eo.vulns?.length) && <span className="text-theme-muted">-</span>}
                            </div>
                          </td>
                          <td className="py-1.5 font-mono text-[11px] whitespace-nowrap">
                            <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${gnBadgeClass}`}>
                              {gnCls}
                            </span>
                            {eo.greynoise_name && eo.greynoise_name !== 'not observed' && (
                              <span className="ml-1.5 text-theme-secondary">{eo.greynoise_name}</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: LOGS */}
      {activeTab === 'logs' && (
        <div className="card-industrial p-4 space-y-2 font-mono">
          <div className="flex items-center justify-between text-xs text-theme-muted border-b border-theme-subtle pb-2">
            <span className="flex items-center space-x-1.5">
              <Terminal className="w-3.5 h-3.5 text-theme-accent" />
              <span>{L('URIELSCAN LIVE EXECUTION TERMINAL', 'TERMINALE DI ESECUZIONE LIVE URIELSCAN')}</span>
            </span>
            <span className="text-[10px]">{L('Auto-scroll enabled', 'Auto-scroll abilitato')}</span>
          </div>
          <div className="p-3 rounded bg-canvas border border-theme max-h-96 overflow-y-auto space-y-1 text-xs">
            {displayLogs.map((line, idx) => (
              <div key={idx} className="text-theme-secondary leading-relaxed">
                <span className="text-theme-muted mr-2">[{idx + 1}]</span>
                <span>{line}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* INSPECTION DRAWER */}
      {inspectingFinding && (
        <div className="fixed inset-y-0 right-0 z-50 w-full max-w-xl bg-panel border-l border-theme p-6 overflow-y-auto shadow-2xl animate-in slide-in-from-right duration-200">
          <div className="flex items-start justify-between gap-3 border-b border-theme-subtle pb-3 mb-4">
            <div>
              <div className="flex items-center space-x-2 text-xs font-mono mb-1">
                <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded border uppercase ${getSeverityBadge(inspectingFinding.severity)}`}>
                  {inspectingFinding.severity}
                </span>
                <span className="text-theme-muted font-bold">CVSS {inspectingFinding.cvss.toFixed(1)}</span>
                <span className="text-theme-muted uppercase">{inspectingFinding.source_engine}</span>
              </div>
              <h2 className="text-sm font-bold text-theme-primary tracking-tight">
                {inspectingFinding.title}
              </h2>
            </div>
            <button
              onClick={() => setInspectingFinding(null)}
              className="btn-secondary p-1 text-theme-muted hover:text-theme-primary"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="space-y-4 text-xs">
            {/* Target details */}
            <div className="p-3 rounded bg-subtle border border-theme font-mono space-y-1">
              <div>{L('Organization:', 'Organizzazione:')} <strong className="text-theme-accent">{getOrgName(inspectingFinding.org_id)}</strong></div>
              <div>{L('Scan Session:', 'Sessione Scansione:')} <strong className="text-theme-primary">{getScanName(inspectingFinding.scan_id)}</strong></div>
              <div>Host: <strong className="text-theme-primary">{inspectingFinding.host}</strong></div>
              {inspectingFinding.port && (
                <div>{L('Port:', 'Porta:')} <strong className="text-theme-primary">{inspectingFinding.port}/{inspectingFinding.protocol || 'tcp'}</strong> ({inspectingFinding.service})</div>
              )}
              {inspectingFinding.cve_ids.length > 0 && (
                <div>CVE: <strong className="text-theme-accent">{inspectingFinding.cve_ids.join(', ')}</strong></div>
              )}
            </div>

            {/* Description */}
            <div>
              <h3 className="font-bold text-theme-secondary uppercase tracking-wider text-[11px] mb-1">
                {L('Technical Description', 'Descrizione Tecnica')}
              </h3>
              <p className="text-theme-primary leading-relaxed">
                {inspectingFinding.description}
              </p>
            </div>

            {/* Evidence */}
            {inspectingFinding.evidence && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <h3 className="font-bold text-theme-secondary uppercase tracking-wider text-[11px]">
                    {L('Evidence Gathered by Engine', 'Evidenza Raccolta dal Motore')}
                  </h3>
                  <button
                    onClick={() => copyToClipboard(inspectingFinding.evidence!)}
                    className="btn-secondary px-2 py-0.5 text-[10px] flex items-center space-x-1"
                  >
                    {copiedEvidence ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedEvidence ? L('Copied', 'Copiato') : L('Copy', 'Copia')}</span>
                  </button>
                </div>
                <pre className="p-3 rounded bg-canvas border border-theme text-xs font-mono text-theme-secondary overflow-x-auto whitespace-pre-wrap">
                  {inspectingFinding.evidence}
                </pre>
              </div>
            )}

            {/* Remediation */}
            {inspectingFinding.remediation && (
              <div>
                <h3 className="font-bold text-theme-secondary uppercase tracking-wider text-[11px] mb-1">
                  {L('Countermeasure & Blue Team Remediation', 'Contromisura & Remediation Blue Team')}
                </h3>
                <div className="p-3 rounded bg-emerald-950/10 border border-emerald-500/30 text-emerald-400 leading-relaxed">
                  {inspectingFinding.remediation}
                </div>
              </div>
            )}

            {/* AI Purple Team Insight */}
            {inspectingFinding.ai_insight ? (
              <div className="p-3 rounded bg-subtle border border-theme space-y-2">
                <div className="flex items-center space-x-1.5 text-xs font-bold text-theme-accent">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>{L('In-Depth AI Purple Team Analysis', 'Analisi Purple Team AI Approfondita')}</span>
                </div>
                <div>
                  <div className="text-[10px] uppercase font-bold text-theme-muted">{L('Red Team Offensive Vector', 'Vettore Offensivo Red Team')}</div>
                  <p className="text-theme-secondary mt-0.5 leading-relaxed">
                    {inspectingFinding.ai_insight.red_team_scenario}
                  </p>
                </div>
                <div>
                  <div className="text-[10px] uppercase font-bold text-theme-muted">{L('Blue Team Defensive Priority', 'Priorità Difensiva Blue Team')}</div>
                  <p className="text-theme-secondary mt-0.5 leading-relaxed">
                    {inspectingFinding.ai_insight.blue_team_fix}
                  </p>
                </div>
              </div>
            ) : (
              <div>
                <button
                  onClick={() => handleSingleFindingAI(inspectingFinding)}
                  disabled={isAiLoading}
                  className="btn-primary w-full py-2 text-xs font-semibold flex items-center justify-center space-x-1.5"
                >
                  {isAiLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
                  <span>{isAiLoading ? L('Analysis in progress...', 'Analisi in corso...') : L('Generate Red Scenario & Fix with AI', 'Genera Scenario Red & Fix con AI')}</span>
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Delete Scan Confirm Modal */}
      {(scanToDelete || currentScan) && (
        <ConfirmModal
          isOpen={isDeleteModalOpen}
          title={`${L('Delete Scan', 'Elimina Scansione')} #${(scanToDelete || currentScan)!.id}`}
          description={L(`Are you sure you want to permanently delete scan "${(scanToDelete || currentScan)!.name}"? All associated findings, logs and discovered hosts will be deleted from the database.`, `Sei sicuro di voler eliminare definitivamente la scansione "${(scanToDelete || currentScan)!.name}"? Tutti i risultati, i log e gli host rilevati verranno cancellati dal database.`)}
          confirmText={L('Delete Scan', 'Elimina Scansione')}
          isDestructive={true}
          isLoading={isDeleting}
          onCancel={() => {
            setIsDeleteModalOpen(false);
            setScanToDelete(null);
          }}
          onConfirm={async () => {
            const target = scanToDelete || currentScan;
            if (!target) return;
            setIsDeleting(true);
            try {
              await onDeleteScan(target.id);
              setIsDeleteModalOpen(false);
              setScanToDelete(null);
            } finally {
              setIsDeleting(false);
            }
          }}
        />
      )}
    </div>
  );
};
