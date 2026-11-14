import React, { useState } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Server, 
  Activity, 
  Play, 
  CheckCircle2, 
  Clock, 
  Flame, 
  Layers, 
  Trash2,
  PlusCircle,
  ChevronRight,
  ExternalLink 
} from 'lucide-react';
import { Scan, Finding, Organization } from '../types';
import { ConfirmModal } from './UIFeedback';
import { useI18n } from '../i18n/LanguageContext';

interface CommandCenterProps {
  scans: Scan[];
  findings: Finding[];
  selectedOrgId: string;
  organizations: Organization[];
  onNavigateToScan: (scanId: string) => void;
  onNavigateToNewScan: () => void;
  onSelectFinding: (finding: Finding) => void;
  onDeleteScan?: (scanId: string) => void;
  onNavigateToScansWithFilter?: (options: {
    tab?: 'findings' | 'hosts' | 'logs';
    severity?: string;
    engine?: string;
    scanId?: string;
  }) => void;
}

export const CommandCenter: React.FC<CommandCenterProps> = ({
  scans,
  findings,
  selectedOrgId,
  organizations,
  onNavigateToScan,
  onNavigateToNewScan,
  onSelectFinding,
  onDeleteScan,
  onNavigateToScansWithFilter,
}) => {
  const { locale, L } = useI18n();
  const [deleteTargetScan, setDeleteTargetScan] = useState<Scan | null>(null);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);

  // Filter by selected organization if not ALL
  const currentOrg = organizations.find((o) => o.id === selectedOrgId);
  const filteredScans = selectedOrgId === 'ALL' 
    ? scans 
    : scans.filter((s) => s.org_id === selectedOrgId);

  const filteredFindings = selectedOrgId === 'ALL'
    ? findings
    : findings.filter((f) => f.org_id === selectedOrgId);

  // Compute stats
  const criticalCount = filteredFindings.filter((f) => f.severity === 'Critical').length;
  const highCount = filteredFindings.filter((f) => f.severity === 'High').length;
  const mediumCount = filteredFindings.filter((f) => f.severity === 'Medium').length;
  const lowCount = filteredFindings.filter((f) => f.severity === 'Low').length;
  const infoCount = filteredFindings.filter((f) => f.severity === 'Info').length;
  const totalFindings = filteredFindings.length;

  const runningScans = filteredScans.filter((s) => s.status === 'running').length;
  const allDiscoveredHostIps = new Set<string>([
    ...filteredFindings.map((f) => f.host),
    ...filteredScans.flatMap((s) => (s.hosts || []).map((h) => h.ip)),
  ]);
  const totalHosts = allDiscoveredHostIps.size;
  const latestScanId = filteredScans[0]?.id;

  const handleDrillDown = (options: {
    tab?: 'findings' | 'hosts' | 'logs';
    severity?: string;
    engine?: string;
  }) => {
    const targetScanScope = filteredScans.length > 1 ? 'ALL' : latestScanId;
    if (onNavigateToScansWithFilter) {
      onNavigateToScansWithFilter({ ...options, scanId: targetScanScope });
    } else if (latestScanId) {
      onNavigateToScan(latestScanId);
    }
  };

  // Global Risk Score Calculation (0 - 100)
  const rawScore = (criticalCount * 25) + (highCount * 12) + (mediumCount * 4) + (lowCount * 1);
  const riskScore = filteredScans.length === 0 ? 0 : Math.min(100, Math.max(0, rawScore));

  const getRiskColor = (score: number) => {
    if (score >= 70) return { text: 'text-red-500', bg: 'bg-red-500', label: L('HIGH', 'ELEVATO') };
    if (score >= 40) return { text: 'text-amber-500', bg: 'bg-amber-500', label: L('MODERATE', 'MODERATO') };
    return { text: 'text-emerald-500', bg: 'bg-emerald-500', label: L('CONTROLLED', 'CONTROLLATO') };
  };

  const riskMeta = getRiskColor(riskScore);

  // Engine source counts
  const engineCounts = {
    nmap: filteredFindings.filter((f) => f.source_engine === 'nmap').length,
    nuclei: filteredFindings.filter((f) => f.source_engine === 'nuclei').length,
    native_web: filteredFindings.filter((f) => f.source_engine === 'native_web').length,
    native_net: filteredFindings.filter((f) => f.source_engine === 'native_net').length,
  };

  const topCriticalFindings = [...filteredFindings]
    .sort((a, b) => b.cvss - a.cvss)
    .slice(0, 5);

  const confirmDeleteScanAction = async () => {
    if (!deleteTargetScan || !onDeleteScan) return;
    setIsDeleting(true);
    try {
      await onDeleteScan(deleteTargetScan.id);
      setDeleteTargetScan(null);
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Scope banner */}
      <div className="card-industrial p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center space-x-2 text-[10px] font-mono uppercase font-bold tracking-wider text-theme-accent">
            <span>{selectedOrgId === 'ALL' ? L('MSP/MSSP Global Overview', 'Panoramica Globale MSP/MSSP') : L('Client Security Perimeter', 'Perimetro Sicurezza Cliente')}</span>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span className="text-theme-muted">{L('Live Console', 'Console Live')}</span>
          </div>
          <h1 className="text-base font-bold text-theme-primary mt-0.5 tracking-tight">
            {selectedOrgId === 'ALL' 
              ? L('Command Center & Risk Posture', 'Command Center & Postura di Rischio') 
              : `${currentOrg?.name} - ${L('Vulnerability Assessment', 'Valutazione Vulnerabilità')}`}
          </h1>
          <p className="text-xs text-theme-secondary mt-0.5 font-mono">
            {selectedOrgId === 'ALL'
              ? `${organizations.length} ${L('registered organizations', 'organizzazioni censite')} • ${filteredScans.length} ${L('scans', 'scansioni')}`
              : `${L('Scope:', 'Scope:')} ${currentOrg?.target_scope || L('Standard perimeter', 'Perimetro standard')}`}
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={onNavigateToNewScan}
            className="btn-primary flex items-center space-x-1.5 px-3.5 py-1.5 text-xs font-semibold shadow-sm"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{L('New Scan', 'Nuova Scansione')}</span>
          </button>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* KPI 1: Risk Score Gauge */}
        <div
          onClick={() => handleDrillDown({ tab: 'findings', severity: 'all', engine: 'all' })}
          title={L('Click to open all vulnerabilities detail in Scans & Results', 'Clicca per aprire il dettaglio di tutte le vulnerabilità in Scansioni & Risultati')}
          className="card-industrial p-3.5 space-y-2 cursor-pointer hover:border-theme-accent transition group"
        >
          <div className="flex items-center justify-between text-xs">
            <span className="font-medium text-theme-secondary group-hover:text-theme-primary transition">{L('Risk Index', 'Indice di Rischio')}</span>
            <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border border-theme-subtle bg-subtle ${riskMeta.text}`}>
              {riskMeta.label}
            </span>
          </div>
          <div className="flex items-baseline space-x-1.5">
            <span className={`text-3xl font-extrabold font-mono tabular-nums ${riskMeta.text}`}>
              {riskScore}
            </span>
            <span className="text-theme-muted font-mono text-xs">/ 100</span>
          </div>
          <div className="w-full bg-subtle h-1.5 rounded-full overflow-hidden border border-theme-subtle">
            <div 
              className={`h-full ${riskMeta.bg} transition-all duration-500 rounded-full`} 
              style={{ width: `${riskScore}%` }} 
            />
          </div>
        </div>

        {/* KPI 2: Vulnerabilità Critiche / Alte */}
        <div
          onClick={() => handleDrillDown({ tab: 'findings', severity: 'critical_high', engine: 'all' })}
          title={L('Click to filter Critical & High vulnerabilities in Scans & Results', 'Clicca per filtrare le vulnerabilità Critiche & Alte in Scansioni & Risultati')}
          className="card-industrial p-3.5 space-y-2 cursor-pointer hover:border-red-500/70 transition group"
        >
          <div className="flex items-center justify-between text-xs">
            <span className="font-medium text-theme-secondary group-hover:text-theme-primary transition flex items-center space-x-1">
              <span>{L('Critical & High', 'Critiche & Alte')}</span>
              <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition text-red-400" />
            </span>
            <Flame className="w-4 h-4 text-red-500" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold font-mono tabular-nums text-red-500">
              {criticalCount + highCount}
            </span>
            <span className="text-theme-muted text-xs font-mono">
              ({criticalCount} Crit • {highCount} High)
            </span>
          </div>
          <div className="text-[11px] text-theme-muted font-mono flex items-center justify-between">
            <span>{L('Out of a total of', 'Su un totale di')} {totalFindings} {L('findings', 'findings')}</span>
            <span className="text-[10px] text-theme-accent opacity-80 group-hover:underline">{L('View details →', 'Vedi dettaglio →')}</span>
          </div>
        </div>

        {/* KPI 3: Host Esplorati */}
        <div
          onClick={() => handleDrillDown({ tab: 'hosts', severity: 'all', engine: 'all' })}
          title={L('Click to open Host & Ports map in Scans & Results', 'Clicca per aprire la mappa Host & Porte rilevate in Scansioni & Risultati')}
          className="card-industrial p-3.5 space-y-2 cursor-pointer hover:border-theme-accent transition group"
        >
          <div className="flex items-center justify-between text-xs">
            <span className="font-medium text-theme-secondary group-hover:text-theme-primary transition flex items-center space-x-1">
              <span>{L('Mapped Hosts & Targets', 'Host & Target Mappati')}</span>
              <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition text-theme-accent" />
            </span>
            <Server className="w-4 h-4 text-theme-accent" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold font-mono tabular-nums text-theme-primary">
              {totalHosts}
            </span>
            <span className="text-theme-muted text-xs font-mono">{L('active endpoints', 'endpoint attivi')}</span>
          </div>
          <div className="text-[11px] text-theme-muted font-mono flex items-center justify-between">
            <span>{runningScans > 0 ? `${runningScans} ${L('active scans', 'scansioni attive')}` : L('Topology and ports', 'Topologia e porte')}</span>
            <span className="text-[10px] text-theme-accent opacity-80 group-hover:underline">{L('Host map →', 'Mappa host →')}</span>
          </div>
        </div>

        {/* KPI 4: Motori Operativi */}
        <div
          onClick={() => handleDrillDown({ tab: 'findings', severity: 'all', engine: 'all' })}
          title={L('Click to explore findings by engine (Nmap, Nuclei, Web, Net)', 'Clicca per esplorare i finding suddivisi per motore (Nmap, Nuclei, Web, Net)')}
          className="card-industrial p-3.5 space-y-2 cursor-pointer hover:border-theme-accent transition group"
        >
          <div className="flex items-center justify-between text-xs">
            <span className="font-medium text-theme-secondary group-hover:text-theme-primary transition flex items-center space-x-1">
              <span>{L('Hybrid Engines', 'Motori Ibridi')}</span>
              <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition text-theme-accent" />
            </span>
            <Layers className="w-4 h-4 text-theme-accent" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold font-mono tabular-nums text-theme-primary">
              4
            </span>
            <span className="text-theme-muted text-xs font-mono">Nmap, Nuclei, Web, Net</span>
          </div>
          <div className="text-[11px] text-theme-muted font-mono flex items-center justify-between">
            <span>{L('Network, ports and web OWASP', 'Rete, porte e web OWASP')}</span>
            <span className="text-[10px] text-theme-accent opacity-80 group-hover:underline">{L('Explore engines →', 'Esplora motori →')}</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Left Column & Right Column */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left: Severities & Engine Breakdown */}
        <div className="space-y-4">
          <div className="card-industrial p-4 space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
              {L('Severity Distribution', 'Distribuzione Severità')}
            </h2>
            <div className="space-y-2 text-xs font-mono">
              <div
                onClick={() => handleDrillDown({ tab: 'findings', severity: 'critical', engine: 'all' })}
                className="flex justify-between items-center p-2 rounded bg-subtle border border-theme hover:border-red-500/60 cursor-pointer transition"
              >
                <span className="text-red-400 font-bold">{L('CRITICAL', 'CRITICA')}</span>
                <span className="tabular-nums font-bold text-theme-primary">{criticalCount}</span>
              </div>
              <div
                onClick={() => handleDrillDown({ tab: 'findings', severity: 'high', engine: 'all' })}
                className="flex justify-between items-center p-2 rounded bg-subtle border border-theme hover:border-orange-500/60 cursor-pointer transition"
              >
                <span className="text-orange-400 font-bold">{L('HIGH', 'ALTA')}</span>
                <span className="tabular-nums font-bold text-theme-primary">{highCount}</span>
              </div>
              <div
                onClick={() => handleDrillDown({ tab: 'findings', severity: 'medium', engine: 'all' })}
                className="flex justify-between items-center p-2 rounded bg-subtle border border-theme hover:border-amber-500/60 cursor-pointer transition"
              >
                <span className="text-amber-400 font-bold">{L('MEDIUM', 'MEDIA')}</span>
                <span className="tabular-nums font-bold text-theme-primary">{mediumCount}</span>
              </div>
              <div
                onClick={() => handleDrillDown({ tab: 'findings', severity: 'low', engine: 'all' })}
                className="flex justify-between items-center p-2 rounded bg-subtle border border-theme hover:border-sky-500/60 cursor-pointer transition"
              >
                <span className="text-sky-400 font-bold">{L('LOW', 'BASSA')}</span>
                <span className="tabular-nums font-bold text-theme-primary">{lowCount}</span>
              </div>
              <div
                onClick={() => handleDrillDown({ tab: 'findings', severity: 'info', engine: 'all' })}
                className="flex justify-between items-center p-2 rounded bg-subtle border border-theme hover:border-theme-accent cursor-pointer transition"
              >
                <span className="text-theme-secondary font-bold">INFO</span>
                <span className="tabular-nums font-bold text-theme-primary">{infoCount}</span>
              </div>
            </div>
          </div>

          <div className="card-industrial p-4 space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
              {L('Detections by Engine', 'Rilevazioni per Motore')}
            </h2>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <div
                onClick={() => handleDrillDown({ tab: 'findings', severity: 'all', engine: 'nmap' })}
                className="p-2.5 rounded bg-subtle border border-theme hover:border-theme-accent cursor-pointer transition"
              >
                <div className="text-[10px] text-theme-muted">Nmap NSE</div>
                <div className="text-base font-bold text-theme-primary tabular-nums mt-0.5">{engineCounts.nmap}</div>
              </div>
              <div
                onClick={() => handleDrillDown({ tab: 'findings', severity: 'all', engine: 'nuclei' })}
                className="p-2.5 rounded bg-subtle border border-theme hover:border-theme-accent cursor-pointer transition"
              >
                <div className="text-[10px] text-theme-muted">Nuclei</div>
                <div className="text-base font-bold text-theme-primary tabular-nums mt-0.5">{engineCounts.nuclei}</div>
              </div>
              <div
                onClick={() => handleDrillDown({ tab: 'findings', severity: 'all', engine: 'native_web' })}
                className="p-2.5 rounded bg-subtle border border-theme hover:border-theme-accent cursor-pointer transition"
              >
                <div className="text-[10px] text-theme-muted">Native Web</div>
                <div className="text-base font-bold text-theme-primary tabular-nums mt-0.5">{engineCounts.native_web}</div>
              </div>
              <div
                onClick={() => handleDrillDown({ tab: 'findings', severity: 'all', engine: 'native_net' })}
                className="p-2.5 rounded bg-subtle border border-theme hover:border-theme-accent cursor-pointer transition"
              >
                <div className="text-[10px] text-theme-muted">Native Net/SSL</div>
                <div className="text-base font-bold text-theme-primary tabular-nums mt-0.5">{engineCounts.native_net}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Recent Scans & Top Vulnerabilities */}
        <div className="lg:col-span-2 space-y-4">
          {/* Recent Scans Box */}
          <div className="card-industrial p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-1.5">
                  <Activity className="w-3.5 h-3.5 text-theme-accent" />
                  <span>{L('Recent Scans & Monitoring', 'Scansioni Recenti & Monitoraggio')}</span>
                </h2>
              </div>
            </div>

            <div className="space-y-2">
              {filteredScans.length === 0 ? (
                <div className="p-6 text-center text-theme-muted border border-dashed border-theme rounded">
                  <p className="text-xs">{L('No scans present for the selected organization.', 'Nessuna scansione presente per l\'organizzazione selezionata.')}</p>
                  <button
                    onClick={onNavigateToNewScan}
                    className="btn-primary mt-3 px-3 py-1.5 text-xs font-semibold inline-flex items-center space-x-1"
                  >
                    <PlusCircle className="w-3.5 h-3.5" />
                    <span>{L('Launch New Scan', 'Avvia Nuova Scansione')}</span>
                  </button>
                </div>
              ) : (
                filteredScans.slice(0, 4).map((scan) => {
                  const org = organizations.find((o) => o.id === scan.org_id);
                  const isRunning = scan.status === 'running';

                  return (
                    <div
                      key={scan.id}
                      className="p-3 rounded border border-theme bg-subtle hover:bg-hover transition flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                    >
                      <div
                        onClick={() => onNavigateToScan(scan.id)}
                        className="cursor-pointer flex-1 space-y-1"
                      >
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-xs text-theme-primary">
                            {scan.name}
                          </span>
                          {isRunning ? (
                            <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border border-amber-600 bg-amber-950/30 text-amber-400 animate-pulse">
                              {L('IN PROGRESS', 'IN CORSO')} {scan.progress}%
                            </span>
                          ) : (
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded border border-theme-subtle text-theme-secondary uppercase">
                              {scan.status}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center space-x-2 text-[11px] text-theme-secondary font-mono">
                          <span className="text-theme-accent">{org?.name || 'MSP'}</span>
                          <span>•</span>
                          <span className="truncate max-w-xs">{scan.targets}</span>
                          <span>•</span>
                          <span>{new Date(scan.started_at).toLocaleTimeString(locale)}</span>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2 shrink-0">
                        {/* Findings badges */}
                        <div className="flex items-center space-x-1 text-[10px] font-mono tabular-nums">
                          {scan.findings_count.critical > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-600 font-bold">
                              {scan.findings_count.critical} C
                            </span>
                          )}
                          {scan.findings_count.high > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-orange-950/40 text-orange-400 border border-orange-600 font-bold">
                              {scan.findings_count.high} H
                            </span>
                          )}
                          <span className="text-theme-muted">
                            {(scan.findings_count.critical || 0) + (scan.findings_count.high || 0) + (scan.findings_count.medium || 0) + (scan.findings_count.low || 0) + (scan.findings_count.info || 0)} {L('findings', 'findings')}
                          </span>
                        </div>

                        {onDeleteScan && (
                          <button
                            onClick={() => setDeleteTargetScan(scan)}
                            className="btn-secondary p-1 text-theme-muted hover:text-red-400"
                            title={L('Delete scan', 'Elimina scansione')}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}

                        <button
                          onClick={() => onNavigateToScan(scan.id)}
                          className="btn-secondary p-1 text-theme-secondary hover:text-theme-primary"
                          title={L('View details', 'Visualizza dettagli')}
                        >
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Top Critical Findings Box */}
          <div className="card-industrial p-4 space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-1.5">
              <Flame className="w-3.5 h-3.5 text-red-500" />
              <span>{L('Blue Team Priority Vulnerabilities', 'Vulnerabilità Prioritarie Blue Team')}</span>
            </h2>

            <div className="space-y-2">
              {topCriticalFindings.length === 0 ? (
                <div className="p-4 text-center text-xs text-theme-muted">
                  {L('No critical or high-risk vulnerabilities recorded.', 'Nessuna vulnerabilità critica o ad alto rischio registrata.')}
                </div>
              ) : (
                topCriticalFindings.map((finding) => {
                  const fOrg = organizations.find((o) => String(o.id) === String(finding.org_id));
                  return (
                    <div
                      key={finding.id}
                      onClick={() => onSelectFinding(finding)}
                      className="p-2.5 rounded border border-theme bg-subtle hover:bg-hover transition cursor-pointer flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0 space-y-0.5">
                        <div className="flex items-center space-x-1.5 text-xs">
                          <span className="text-[10px] font-mono font-bold px-1 py-0.2 rounded border uppercase border-red-600 bg-red-950/30 text-red-400">
                            {finding.severity}
                          </span>
                          <span className="text-[10px] font-mono font-semibold px-1.5 py-0.2 rounded bg-panel border border-theme text-theme-accent shrink-0">
                            {fOrg?.name || `Org #${finding.org_id}`}
                          </span>
                          <span className="font-semibold text-theme-primary truncate">{finding.title}</span>
                        </div>
                        <div className="text-[10px] font-mono text-theme-secondary truncate">
                          <span>{finding.host}</span>
                          {finding.port && <span>:{finding.port}</span>}
                          <span className="ml-2 uppercase">({finding.source_engine})</span>
                        </div>
                      </div>

                      <div className="text-right shrink-0 font-mono">
                        <span className="text-xs font-bold text-red-400 tabular-nums">CVSS {finding.cvss.toFixed(1)}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Delete Scan Confirm Modal */}
      {deleteTargetScan && (
        <ConfirmModal
          isOpen={deleteTargetScan !== null}
          title={`${L('Delete Scan', 'Elimina Scansione')} #${deleteTargetScan.id}`}
          description={L(`Are you sure you want to delete scan "${deleteTargetScan.name}"? All associated findings and logs will be permanently deleted.`, `Sei sicuro di voler eliminare la scansione "${deleteTargetScan.name}"? Tutti i risultati e i log associati verranno cancellati.`)}
          confirmText={L('Delete Scan', 'Elimina Scansione')}
          isDestructive={true}
          isLoading={isDeleting}
          onCancel={() => setDeleteTargetScan(null)}
          onConfirm={confirmDeleteScanAction}
        />
      )}
    </div>
  );
};
