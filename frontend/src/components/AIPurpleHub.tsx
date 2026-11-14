import React, { useState } from 'react';
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
  Send 
} from 'lucide-react';
import { Scan, Finding } from '../types';
import { api } from '../services/api';
import { useToast } from './UIFeedback';
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
  const { lang, L } = useI18n();
  const { showToast } = useToast();
  const [scanId, setScanId] = useState<string>(selectedScanId || scans[0]?.id || '');
  const [analysisMode, setAnalysisMode] = useState<'purple' | 'red' | 'blue' | 'executive'>('purple');
  const [scopeType, setScopeType] = useState<'all' | 'critical_only'>('all');
  const [extraPrompt, setExtraPrompt] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [copiedScript, setCopiedScript] = useState<boolean>(false);

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
      showToast(L('Purple Team analysis generated successfully.', 'Analisi Purple Team generata con successo.'), 'success');
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

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="card-industrial p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
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
