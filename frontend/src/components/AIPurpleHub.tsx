import React, { useState, useEffect, useRef } from 'react';
import {
  Sparkles,
  Flame,
  CheckCircle2,
  Layers,
  Code2,
  Copy,
  Check,
  RefreshCw,
  FileText,
  Send,
  ChevronDown,
  Clock,
  List,
  Trash2,
  Eye,
  ArrowLeft,
  Search,
  Download
} from 'lucide-react';
import { Scan, Finding, SavedAIReport } from '../types';
import { api } from '../services/api';
import { useToast, ConfirmModal } from './UIFeedback';
import { useI18n } from '../i18n/LanguageContext';

interface AIPurpleHubProps {
  scans: Scan[];
  findings: Finding[];
  selectedScanId: string | null;
  onNavigateToReport: () => void;
}

export const AIPurpleHub: React.FC<AIPurpleHubProps> = ({
  scans,
  findings,
  selectedScanId,
  onNavigateToReport,
}) => {
  const { lang, locale, L } = useI18n();
  const { showToast } = useToast();
  const [scanId, setScanId] = useState<string>(selectedScanId || scans[0]?.id || '');
  const [analysisMode, setAnalysisMode] = useState<'purple' | 'red' | 'blue' | 'executive'>('purple');
  const [scopeType, setScopeType] = useState<'all' | 'critical_only'>('all');
  const [extraPrompt, setExtraPrompt] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [copiedScript, setCopiedScript] = useState<boolean>(false);

  const [savedAiReports, setSavedAiReports] = useState<SavedAIReport[]>([]);
  const [activeSavedReport, setActiveSavedReport] = useState<SavedAIReport | null>(null);
  const [isDropdownOpen, setIsDropdownOpen] = useState<boolean>(false);
  const [showAllAiReports, setShowAllAiReports] = useState<boolean>(false);
  const [aiSearch, setAiSearch] = useState<string>('');
  const [aiToDelete, setAiToDelete] = useState<SavedAIReport | null>(null);
  const [isDeletingAi, setIsDeletingAi] = useState<boolean>(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const loadAiReports = async () => {
    try {
      const rows = await api.getAiReports();
      setSavedAiReports(rows);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    loadAiReports();
  }, []);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, []);

  const formatAiDate = (iso?: string) => {
    if (!iso) return L('N/A', 'N/D');
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return L('N/A', 'N/D');
    return `${d.toLocaleDateString(locale)} • ${d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' })}`;
  };

  const downloadMarkdownReport = (rep: SavedAIReport) => {
    const blob = new Blob([rep.content_md || ''], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${rep.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const [analysisResult, setAnalysisResult] = useState<{
    executive_summary: string;
    red_team_paths: string[];
    blue_team_priorities: string[];
    mitre_techniques: { id: string; name: string; tactic: string; description: string }[];
    remediation_script?: string;
  } | null>(null);

  const handleRunAnalysis = async () => {
    if (!scanId) {
      showToast(L('Please select a scan to proceed with the analysis.', 'Seleziona una scansione per procedere con l\'analisi.'), 'warning');
      return;
    }

    setIsLoading(true);
    try {
      const scanFindings = findings.filter((f) => f.scan_id === scanId);
      const targetFindings = scopeType === 'critical_only'
        ? scanFindings.filter((f) => f.severity === 'Critical' || f.severity === 'High')
        : scanFindings;

      const result = await api.analyzeWithAI({
        scan_id: scanId,
        finding_ids: targetFindings.map((f) => f.id),
        mode: analysisMode,
        extra_prompt: extraPrompt.trim() || undefined,
        lang,
      });

      setAnalysisResult(result);
      setActiveSavedReport(null);
      await loadAiReports();
      showToast(L('Purple Team analysis saved & generated successfully.', 'Analisi Purple Team salvata e generata con successo.'), 'success');
    } catch (err: any) {
      showToast(err.message || L('Error generating AI analysis.', 'Errore durante la generazione dell\'analisi AI.'), 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const copyScript = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2000);
    showToast(L('Mitigation script copied.', 'Script di mitigazione copiato.'), 'info');
  };

  if (showAllAiReports) {
    const filteredAi = savedAiReports.filter((r) => {
      if (!aiSearch.trim()) return true;
      const q = aiSearch.toLowerCase();
      return (
        r.title.toLowerCase().includes(q) ||
        (r.org_name || '').toLowerCase().includes(q) ||
        (r.mode || '').toLowerCase().includes(q) ||
        (r.model_used || '').toLowerCase().includes(q)
      );
    });

    return (
      <div className="space-y-4">
        <div className="card-industrial p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center space-x-2 text-[10px] font-mono uppercase font-bold tracking-wider text-theme-accent">
              <Sparkles className="w-3.5 h-3.5" />
              <span>{L('AI Purple Analyst Archive', 'Archivio Report AI Purple Analyst')}</span>
            </div>
            <h1 className="text-base font-bold text-theme-primary tracking-tight mt-0.5">
              {L('All Saved AI Reports', 'Tutti i Report AI Salvati')} ({savedAiReports.length})
            </h1>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-theme-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={aiSearch}
                onChange={(e) => setAiSearch(e.target.value)}
                placeholder={L('Filter by title, mode, org...', 'Filtra per titolo, mode, org...')}
                className="input-industrial pl-8 pr-3 py-1.5 text-xs w-56"
              />
            </div>
            <button
              type="button"
              onClick={() => setShowAllAiReports(false)}
              className="btn-secondary px-3 py-1.5 text-xs font-semibold flex items-center space-x-1.5"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>{L('Back to AI Hub', 'Torna ad AI Hub')}</span>
            </button>
          </div>
        </div>

        <div className="card-industrial overflow-hidden">
          {filteredAi.length === 0 ? (
            <div className="p-8 text-center text-xs text-theme-muted">
              {L('No saved AI analyses found.', 'Nessun report AI salvato trovato.')}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-theme bg-subtle text-[10px] font-mono uppercase text-theme-secondary">
                    <th className="py-2.5 px-3">{L('Mode / Scope', 'Modalità / Scope')}</th>
                    <th className="py-2.5 px-3">{L('Report Title', 'Titolo Report')}</th>
                    <th className="py-2.5 px-3">{L('Organization', 'Organizzazione')}</th>
                    <th className="py-2.5 px-3">{L('Generated At', 'Data & Ora')}</th>
                    <th className="py-2.5 px-3 text-right">{L('Actions', 'Azioni')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-theme-subtle text-xs">
                  {filteredAi.map((rep) => (
                    <tr key={rep.id} className="hover:bg-subtle/60 transition">
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border border-theme bg-panel text-theme-accent uppercase">
                          {rep.mode}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-medium text-theme-primary max-w-md truncate" title={rep.title}>
                        {rep.title}
                      </td>
                      <td className="py-2.5 px-3 text-theme-secondary">{rep.org_name || `Org #${rep.org_id}`}</td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-theme-muted">
                        {formatAiDate(rep.created_at)}
                      </td>
                      <td className="py-2.5 px-3 text-right space-x-1.5 whitespace-nowrap">
                        <button
                          type="button"
                          onClick={() => {
                            setActiveSavedReport(rep);
                            setShowAllAiReports(false);
                          }}
                          className="btn-secondary px-2 py-1 text-[11px] inline-flex items-center space-x-1"
                        >
                          <Eye className="w-3 h-3" />
                          <span>{L('View', 'Vedi')}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => downloadMarkdownReport(rep)}
                          className="btn-secondary px-2 py-1 text-[11px] inline-flex items-center"
                          title={L('Download Markdown (.md)', 'Scarica Markdown (.md)')}
                        >
                          <Download className="w-3 h-3" />
                        </button>
                        <button
                          type="button"
                          onClick={() => setAiToDelete(rep)}
                          className="btn-secondary px-2 py-1 text-[11px] text-red-400 hover:border-red-500/60 inline-flex items-center"
                          title={L('Delete AI Report', 'Elimina Report AI')}
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <ConfirmModal
          isOpen={Boolean(aiToDelete)}
          title={L('Delete AI Analysis Report', 'Elimina Report Analisi AI')}
          description={L(
            `Are you sure you want to permanently delete "${aiToDelete?.title || ''}"?`,
            `Sei sicuro di voler eliminare definitivamente "${aiToDelete?.title || ''}"?`
          )}
          confirmText={L('Delete', 'Elimina')}
          isDestructive={true}
          isLoading={isDeletingAi}
          onCancel={() => setAiToDelete(null)}
          onConfirm={async () => {
            if (!aiToDelete) return;
            setIsDeletingAi(true);
            try {
              const ok = await api.deleteAiReport(aiToDelete.id);
              if (ok) {
                setSavedAiReports((prev) => prev.filter((item) => item.id !== aiToDelete.id));
                if (activeSavedReport?.id === aiToDelete.id) {
                  setActiveSavedReport(null);
                }
                showToast(L('AI report deleted.', 'Report AI eliminato.'), 'success');
              }
            } finally {
              setIsDeletingAi(false);
              setAiToDelete(null);
            }
          }}
        />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="card-industrial p-4 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="space-y-0.5">
            <div className="flex items-center space-x-2 text-[11px] uppercase font-bold tracking-wider text-theme-accent">
              <Sparkles className="w-3.5 h-3.5" />
              <span>AI Purple Team Analyst & Correlation Hub</span>
            </div>
            <h1 className="text-base font-bold text-theme-primary tracking-tight">
              {L('Purple Team Offensive & Defensive Analyzer', 'Analizzatore Offensivo & Difensivo Purple Team')}
            </h1>
            <p className="text-xs text-theme-secondary">
              {L(
                'Automatic correlation of exploit chains (Red Team) and prioritized generation of fixes and scripts (Blue Team).',
                'Correlazione automatica di exploit chains (Red Team) e generazione prioritaria di fix e script (Blue Team).'
              )}
            </p>
          </div>

          {analysisResult && (
            <button
              onClick={onNavigateToReport}
              className="btn-secondary flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold"
            >
              <FileText className="w-3.5 h-3.5 text-theme-accent" />
              <span>{L('Export to Report', 'Esporta in Report')}</span>
            </button>
          )}
        </div>

        {/* Saved AI Reports Quick Switcher & "View all" */}
        <div className="pt-3 border-t border-theme-subtle flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono uppercase font-bold tracking-wider text-theme-muted flex items-center space-x-1">
              <Clock className="w-3 h-3 text-theme-accent" />
              <span>{L('Saved AI Reports', 'Report AI Salvati')}</span>
            </span>

            <div className="relative" ref={dropdownRef}>
              <button
                type="button"
                onClick={() => setIsDropdownOpen((prev) => !prev)}
                className="input-industrial px-2.5 py-1 text-left flex items-center justify-between gap-3 min-w-[260px] max-w-[430px]"
              >
                <div className="min-w-0">
                  {activeSavedReport ? (
                    <>
                      <div className="text-xs font-semibold text-theme-primary truncate">
                        {activeSavedReport.title}
                      </div>
                      <div className="text-[10px] font-mono text-theme-muted truncate">
                        {formatAiDate(activeSavedReport.created_at)} • {activeSavedReport.model_used || 'local'}
                      </div>
                    </>
                  ) : savedAiReports.length > 0 ? (
                    <>
                      <div className="text-xs font-semibold text-theme-primary truncate">
                        {savedAiReports[0].title}
                      </div>
                      <div className="text-[10px] font-mono text-theme-muted truncate">
                        {formatAiDate(savedAiReports[0].created_at)} • {savedAiReports[0].org_name || `Org #${savedAiReports[0].org_id}`}
                      </div>
                    </>
                  ) : (
                    <div className="text-xs text-theme-muted py-0.5">
                      {L('No saved AI analyses yet', 'Nessuna analisi AI salvata finora')}
                    </div>
                  )}
                </div>
                <ChevronDown className={`w-3.5 h-3.5 text-theme-muted shrink-0 transition-transform ${isDropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {isDropdownOpen && savedAiReports.length > 0 && (
                <div className="absolute left-0 top-full mt-1 w-96 bg-panel border border-theme rounded shadow-xl z-50 max-h-72 overflow-y-auto py-1">
                  {savedAiReports.map((rep) => (
                    <button
                      key={rep.id}
                      type="button"
                      onClick={() => {
                        setActiveSavedReport(rep);
                        setIsDropdownOpen(false);
                      }}
                      className={`w-full px-3 py-2 text-left hover:bg-hover transition border-b border-theme-subtle last:border-b-0 cursor-pointer ${
                        activeSavedReport?.id === rep.id ? 'bg-subtle text-theme-accent' : ''
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-theme-primary truncate">{rep.title}</span>
                        <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-subtle border border-theme text-theme-accent uppercase shrink-0">
                          {rep.mode}
                        </span>
                      </div>
                      <div className="text-[10px] font-mono text-theme-muted mt-0.5 truncate">
                        {formatAiDate(rep.created_at)} • {rep.org_name || `Org #${rep.org_id}`}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowAllAiReports(true)}
            className="btn-secondary px-2.5 py-1.5 text-xs font-semibold flex items-center space-x-1.5"
          >
            <List className="w-3.5 h-3.5 text-theme-accent" />
            <span>{L('View all', 'Vedi tutti')} ({savedAiReports.length})</span>
          </button>
        </div>
      </div>

      {activeSavedReport && (
        <div className="card-industrial p-4 space-y-3 border-l-4 border-l-theme-accent">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-theme-subtle pb-2">
            <div>
              <div className="text-xs font-bold text-theme-primary">{activeSavedReport.title}</div>
              <div className="text-[10px] font-mono text-theme-muted">
                {formatAiDate(activeSavedReport.created_at)} • {activeSavedReport.org_name || `Org #${activeSavedReport.org_id}`} • {activeSavedReport.model_used || 'local'}
              </div>
            </div>
            <div className="flex items-center space-x-1.5">
              <button
                type="button"
                onClick={() => downloadMarkdownReport(activeSavedReport)}
                className="btn-secondary px-2.5 py-1 text-xs flex items-center space-x-1"
              >
                <Download className="w-3 h-3" />
                <span>.MD</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveSavedReport(null)}
                className="btn-secondary px-2.5 py-1 text-xs"
              >
                {L('Close', 'Chiudi')}
              </button>
            </div>
          </div>
          <pre className="p-3 rounded bg-canvas border border-theme text-xs font-mono text-theme-primary overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto">
            {activeSavedReport.content_md}
          </pre>
        </div>
      )}

      {/* Control Panel */}
      <div className="card-industrial p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="block text-xs font-medium text-theme-secondary mb-1">
              {L('Source Scan', 'Scansione di Origine')}
            </label>
            <select
              value={scanId}
              onChange={(e) => setScanId(e.target.value)}
              className="input-industrial w-full px-2.5 py-1.5 text-xs"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id} className="bg-panel text-theme-primary">
                  {s.name} ({s.targets})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-theme-secondary mb-1">
              {L('Analysis Mode', 'Modalità Analisi')}
            </label>
            <select
              value={analysisMode}
              onChange={(e) => setAnalysisMode(e.target.value as any)}
              className="input-industrial w-full px-2.5 py-1.5 text-xs"
            >
              <option value="purple" className="bg-panel text-theme-primary">{L('Full Purple Team (Red + Blue)', 'Purple Team Completo (Red + Blue)')}</option>
              <option value="red" className="bg-panel text-theme-primary">{L('Red Team (Attack Paths & Exploits)', 'Red Team (Attack Paths & Exploits)')}</option>
              <option value="blue" className="bg-panel text-theme-primary">{L('Blue Team (Hardening & Countermeasures)', 'Blue Team (Hardening & Contromisure)')}</option>
              <option value="executive" className="bg-panel text-theme-primary">{L('Executive Summary for Management', 'Executive Summary per il Management')}</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-theme-secondary mb-1">
              {L('Analysis Scope', 'Perimetro di Analisi')}
            </label>
            <select
              value={scopeType}
              onChange={(e) => setScopeType(e.target.value as any)}
              className="input-industrial w-full px-2.5 py-1.5 text-xs"
            >
              <option value="all" className="bg-panel text-theme-primary">{L('All findings', 'Tutti i findings')}</option>
              <option value="critical_only" className="bg-panel text-theme-primary">{L('Critical & High only', 'Solo Critiche & Alte')}</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-theme-secondary mb-1">
            {L('Special Instructions & Specific Focus (Optional)', 'Istruzioni Speciali & Focus Specifico (Opzionale)')}
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={extraPrompt}
              onChange={(e) => setExtraPrompt(e.target.value)}
              placeholder={L('e.g. Verify impact on PCI-DSS framework or generate Nginx snippets...', 'es. Verifica l\'impatto sul framework PCI-DSS o genera snippet Nginx...')}
              className="input-industrial flex-1 px-3 py-1.5 text-xs"
            />
            <button
              onClick={handleRunAnalysis}
              disabled={isLoading}
              className="btn-primary flex items-center space-x-1.5 px-4 py-1.5 text-xs font-semibold shrink-0 disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>{L('Processing...', 'Elaborazione...')}</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>{L('Generate Analysis', 'Genera Analisi')}</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Analysis Results */}
      {analysisResult ? (
        <div className="space-y-4">
          {/* Executive Summary */}
          <div className="card-industrial p-4 space-y-1.5">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="font-bold text-theme-accent uppercase flex items-center space-x-1.5">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Executive AI Summary</span>
              </span>
              <span className="text-[10px] text-theme-muted uppercase">{L('AI Correlation', 'Correlazione AI')}</span>
            </div>
            <p className="text-xs text-theme-primary leading-relaxed">
              {analysisResult.executive_summary}
            </p>
          </div>

          {/* Red & Blue Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Red Team */}
            <div className="card-industrial p-4 space-y-3">
              <div className="flex items-center space-x-2 border-b border-theme-subtle pb-2">
                <Flame className="w-4 h-4 text-red-500" />
                <div>
                  <h2 className="text-xs font-bold text-red-400">
                    {L('Red Team: Attack Vectors & Exploit Chain', 'Red Team: Vettori di Attacco & Catena di Sfruttamento')}
                  </h2>
                </div>
              </div>
              <div className="space-y-2">
                {analysisResult.red_team_paths.map((path, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded bg-red-950/10 border border-red-500/20 text-xs text-theme-primary leading-relaxed"
                  >
                    {path}
                  </div>
                ))}
              </div>
            </div>

            {/* Blue Team */}
            <div className="card-industrial p-4 space-y-3">
              <div className="flex items-center space-x-2 border-b border-theme-subtle pb-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                <div>
                  <h2 className="text-xs font-bold text-emerald-400">
                    {L('Blue Team: Defense Priorities & Mitigation', 'Blue Team: Priorità di Difesa & Mitigazione')}
                  </h2>
                </div>
              </div>
              <div className="space-y-2">
                {analysisResult.blue_team_priorities.map((prio, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded bg-emerald-950/10 border border-emerald-500/20 text-xs text-theme-primary leading-relaxed"
                  >
                    {prio}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* MITRE ATT&CK */}
          <div className="card-industrial p-4 space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary flex items-center space-x-1.5">
              <Layers className="w-3.5 h-3.5 text-theme-accent" />
              <span>{L('MITRE ATT&CK Technique Mapping', 'Mappatura Tecniche MITRE ATT&CK')}</span>
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
              {analysisResult.mitre_techniques.map((tech) => (
                <div key={tech.id} className="p-2.5 rounded bg-subtle border border-theme space-y-1">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="font-bold text-theme-accent">{tech.id}</span>
                    <span className="text-[10px] text-theme-muted uppercase">{tech.tactic}</span>
                  </div>
                  <div className="text-xs font-semibold text-theme-primary">{tech.name}</div>
                  <p className="text-[11px] text-theme-secondary leading-snug">{tech.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Remediation script */}
          {analysisResult.remediation_script && (
            <div className="card-industrial p-4 space-y-2">
              <div className="flex items-center justify-between text-xs border-b border-theme-subtle pb-2">
                <span className="font-bold text-theme-secondary flex items-center space-x-1.5 font-mono">
                  <Code2 className="w-3.5 h-3.5 text-emerald-500" />
                  <span>{L('AI-Generated Hardening Script', "Script di Hardening Generato dall'AI")}</span>
                </span>
                <button
                  onClick={() => copyScript(analysisResult.remediation_script || '')}
                  className="btn-secondary px-2.5 py-1 text-xs flex items-center space-x-1"
                >
                  {copiedScript ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedScript ? L('Copied', 'Copiato') : L('Copy Script', 'Copia Script')}</span>
                </button>
              </div>
              <pre className="p-3 rounded bg-canvas border border-theme text-xs font-mono text-emerald-400 overflow-x-auto whitespace-pre">
                {analysisResult.remediation_script}
              </pre>
            </div>
          )}
        </div>
      ) : (
        <div className="card-industrial p-8 text-center text-theme-muted">
          <Sparkles className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <div className="text-xs font-semibold text-theme-secondary">{L('No analysis generated', 'Nessuna analisi generata')}</div>
          <p className="text-[11px] text-theme-muted mt-0.5">
            {L('Select the desired scan and click "Generate Analysis" to correlate vulnerabilities.', 'Seleziona la scansione desiderata e clicca su "Genera Analisi" per correlare le vulnerabilità.')}
          </p>
        </div>
      )}
    </div>
  );
};
