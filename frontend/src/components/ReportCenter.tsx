import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Printer, 
  Download, 
  Eye, 
  Building2, 
  Layers, 
  Check, 
  X,
  ShieldCheck,
  Loader2,
  FileEdit
} from 'lucide-react';
import { Scan, Finding, Organization, ScannerProfile } from '../types';
import { api } from '../services/api';
import { useToast } from './UIFeedback';
import { useI18n } from '../i18n/LanguageContext';

interface ReportCenterProps {
  scans: Scan[];
  findings: Finding[];
  organizations: Organization[];
  scannerProfile: ScannerProfile;
  selectedScanId: string | null;
}

const DEFAULT_TITLES = {
  en: 'Purple Team Security Assessment & Remediation Report',
  it: 'Report di Valutazione di Sicurezza Purple Team & Remediation',
};

const DEFAULT_NOTES = {
  en: 'This document contains the results of the security assessment conducted on the agreed scope. Critical and High level vulnerabilities require prompt corrective action according to the attached Blue Team roadmap.',
  it: 'Il presente documento contiene i risultati della valutazione di sicurezza condotta sul perimetro concordato. Le vulnerabilità di livello Critico e Alto richiedono azione correttiva tempestiva secondo la roadmap Blue Team allegata.',
};

export const ReportCenter: React.FC<ReportCenterProps> = ({
  scans,
  findings,
  organizations,
  scannerProfile,
  selectedScanId,
}) => {
  const { lang, locale, L } = useI18n();
  const { showToast } = useToast();
  const [scanId, setScanId] = useState<string>(selectedScanId || scans[0]?.id || '');
  const [hasCustomTitle, setHasCustomTitle] = useState<boolean>(false);
  const [hasCustomNotes, setHasCustomNotes] = useState<boolean>(false);
  const [reportTitle, setReportTitle] = useState<string>(() => (lang === 'it' ? DEFAULT_TITLES.it : DEFAULT_TITLES.en));
  const [classification, setClassification] = useState<'CONFIDENTIAL' | 'STRICTLY CONFIDENTIAL' | 'INTERNAL' | 'RESTRICTED'>('CONFIDENTIAL');
  const [includeAI, setIncludeAI] = useState<boolean>(true);
  const [includeEvidence, setIncludeEvidence] = useState<boolean>(true);
  const [includeHostTopology, setIncludeHostTopology] = useState<boolean>(true);
  const [executiveNotes, setExecutiveNotes] = useState<string>(() => (lang === 'it' ? DEFAULT_NOTES.it : DEFAULT_NOTES.en));

  useEffect(() => {
    if (!hasCustomTitle) {
      setReportTitle(lang === 'it' ? DEFAULT_TITLES.it : DEFAULT_TITLES.en);
    }
    if (!hasCustomNotes) {
      setExecutiveNotes(lang === 'it' ? DEFAULT_NOTES.it : DEFAULT_NOTES.en);
    }
  }, [lang, hasCustomTitle, hasCustomNotes]);

  const [isPreviewOpen, setIsPreviewOpen] = useState<boolean>(false);
  const [exportingFormat, setExportingFormat] = useState<'docx' | 'pdf' | null>(null);

  const currentScan = scans.find((s) => s.id === scanId) || scans[0];
  const clientOrg = organizations.find((o) => o.id === currentScan?.org_id) || organizations[0];
  const scanFindings = findings.filter((f) => f.scan_id === currentScan?.id);

  const criticalCount = scanFindings.filter((f) => f.severity === 'Critical').length;
  const highCount = scanFindings.filter((f) => f.severity === 'High').length;
  const mediumCount = scanFindings.filter((f) => f.severity === 'Medium').length;
  const lowCount = scanFindings.filter((f) => f.severity === 'Low').length;

  const escHtml = (val: unknown): string =>
    String(val ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

  const safeDataImg = (url?: string): string => {
    if (!url) return '';
    const trimmed = url.trim();
    if (/^data:image\/(png|jpeg|jpg|webp|gif|svg\+xml);base64,/i.test(trimmed)) {
      return escHtml(trimmed);
    }
    return '';
  };

  const generateStandaloneHTML = () => {
    const clientFallback = L('Client', 'Cliente');
    const msspReportFallback = L('MSSP Report', 'MSSP Report');
    const safeTitle = escHtml(reportTitle);
    const safeClassification = escHtml(classification);
    const safeOrgName = escHtml(clientOrg?.name || clientFallback);
    const safeOrgIndustry = escHtml(clientOrg?.industry || 'N/A');
    const safeTargets = escHtml(currentScan?.targets || 'N/A');
    const safeMsspName = escHtml(scannerProfile.company_name);
    const safeMsspLogo = safeDataImg(scannerProfile.logo_url);
    const safeClientLogo = safeDataImg(clientOrg?.logo_url);
    const safeExecNotes = escHtml(executiveNotes);
    const safeFooter = escHtml(scannerProfile.report_footer);
    const formattedDate = new Date().toLocaleDateString(locale);
    const msspLogoAlt = L('MSSP Logo', 'Logo MSSP');
    const clientLogoAlt = L('Client Logo', 'Logo Cliente');
    const targetOrgLabel = L('Target Organization', 'Organizzazione Destinataria');
    const scanTargetsLabel = L('Scan Targets', 'Target di Scansione');
    const execSummaryTitle = L('1. Executive Summary & Risk Posture', '1. Sintesi Esecutiva & Postura di Rischio');
    const critLabel = L('Critical', 'Critiche');
    const highLabel = L('High', 'Alte');
    const medLabel = L('Medium', 'Medie');
    const lowLabel = L('Low', 'Basse');
    const remediationTitle = L('Remediation Plan & Recommendations (Standard Template)', 'Piano di Remediation & Raccomandazioni (Template Standard)');
    const thPriority = L('Priority', "Priorita'");
    const thAction = L('Recommended Action', 'Azione Consigliata');
    const thSLA = L('SLA / Timeline', 'SLA / Tempistica');
    const thStatus = L('Status / Notes', 'Stato / Note');
    const p1Label = L('P1 - Immediate', 'P1 - Immediata');
    const p1Action = L(`Mitigation of ${criticalCount + highCount} high-impact findings (Critical/High).`, `Mitigazione di ${criticalCount + highCount} criticita' ad alto impatto (Critical/High).`);
    const p1SLA = L('24 - 72 hours', '24 - 72 ore');
    const p1Status = L('[To be planned]', '[Da pianificare]');
    const p2Label = L('P2 - Medium Term', 'P2 - Medio Termine');
    const p2Action = L(`Configuration hardening and remediation of ${mediumCount} Medium findings.`, `Hardening configurazioni e remediation di ${mediumCount} finding Medi.`);
    const p2SLA = L('14 - 30 days', '14 - 30 giorni');
    const p3Label = L('P3 - Improvement', 'P3 - Miglioramento');
    const p3Action = L(`Periodic verification for ${lowCount} Low/Informational findings.`, `Verifica periodica per ${lowCount} finding Bassi/Informativi.`);
    const p3SLA = L('Next cycle', 'Prossimo ciclo');
    const findingsInventoryTitle = L('2. Vulnerability Findings Inventory', '2. Inventario Risultati di Vulnerabilità');
    const hostLabel = L('Host', 'Host');
    const portLabel = L('Port', 'Porta');
    const engineLabel = L('Engine', 'Motore');
    const blueTeamFixLabel = L('Blue Team Fix:', 'Fix Blue Team:');

    return `<!DOCTYPE html>
<html lang="${lang}">
<head>
  <meta charset="UTF-8">
  <title>${safeTitle} - ${escHtml(clientOrg?.name || msspReportFallback)}</title>
  <style>
    @page { size: A4; margin: 15mm; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111315; line-height: 1.5; margin: 0; padding: 24px; background: #fff; }
    .header-bar { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #111315; padding-bottom: 15px; margin-bottom: 25px; }
    .badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 11px; text-transform: uppercase; }
    .badge-confidential { background: #fee2e2; color: #991b1b; }
    .badge-crit { background: #ef4444; color: #fff; }
    .badge-high { background: #ea580c; color: #fff; }
    .badge-med { background: #f59e0b; color: #fff; }
    .badge-low { background: #0284c7; color: #fff; }
    h1 { font-size: 20px; color: #111315; margin: 0 0 5px 0; }
    h2 { font-size: 15px; color: #111315; border-bottom: 1px solid #e5e7eb; padding-bottom: 5px; margin-top: 25px; }
    .grid-kpi { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 15px 0; }
    .kpi-card { background: #f9fafb; border: 1px solid #e5e7eb; padding: 10px; border-radius: 4px; text-align: center; }
    .kpi-num { font-size: 20px; font-weight: bold; }
    .kpi-num.crit { color: #ef4444; }
    .kpi-num.high { color: #ea580c; }
    .finding-card { border: 1px solid #d1d5db; border-radius: 4px; padding: 12px; margin-bottom: 12px; page-break-inside: avoid; }
    .evidence-box { background: #0f172a; color: #34d399; font-family: monospace; font-size: 11px; padding: 10px; border-radius: 4px; overflow-x: auto; margin-top: 8px; white-space: pre-wrap; }
    .footer { margin-top: 40px; padding-top: 15px; border-top: 1px solid #e5e7eb; font-size: 11px; color: #6b7280; text-align: center; }
  </style>
</head>
<body>
  <div class="header-bar">
    <div style="display: flex; align-items: center; gap: 12px;">
      ${safeMsspLogo ? `<img src="${safeMsspLogo}" alt="${msspLogoAlt}" style="max-height: 40px; max-width: 120px; object-fit: contain;" />` : ''}
      <div>
        <div style="font-weight: 800; font-size: 18px; letter-spacing: 0.5px;">URIELSCAN ASSESSMENT</div>
        <div style="font-size: 12px; color: #4b5563;">${safeMsspName}</div>
      </div>
    </div>
    <div style="display: flex; align-items: center; gap: 12px; text-align: right;">
      <div>
        <span class="badge badge-confidential">${safeClassification}</span>
        <div style="font-size: 11px; color: #6b7280; margin-top: 5px;">${L('Date', 'Data')}: ${formattedDate}</div>
      </div>
      ${safeClientLogo ? `<img src="${safeClientLogo}" alt="${clientLogoAlt}" style="max-height: 40px; max-width: 120px; object-fit: contain;" />` : ''}
    </div>
  </div>

  <h1>${safeTitle}</h1>
  <div style="font-size: 13px; color: #4b5563; margin-bottom: 20px;">
    ${targetOrgLabel}: <strong>${safeOrgName}</strong> (${safeOrgIndustry})<br>
    ${scanTargetsLabel}: <code>${safeTargets}</code>
  </div>

  <h2>${execSummaryTitle}</h2>
  <p style="font-size: 13px;">${safeExecNotes}</p>

  <div class="grid-kpi">
    <div class="kpi-card"><div class="kpi-num crit">${criticalCount}</div><div style="font-size:11px;">${critLabel}</div></div>
    <div class="kpi-card"><div class="kpi-num high">${highCount}</div><div style="font-size:11px;">${highLabel}</div></div>
    <div class="kpi-card"><div class="kpi-num">${mediumCount}</div><div style="font-size:11px;">${medLabel}</div></div>
    <div class="kpi-card"><div class="kpi-num">${lowCount}</div><div style="font-size:11px;">${lowLabel}</div></div>
  </div>

  <h2>${remediationTitle}</h2>
  <table style="width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 20px;">
    <thead>
      <tr style="background: #f3f4f6; text-align: left;">
        <th style="padding: 8px; border: 1px solid #d1d5db;">${thPriority}</th>
        <th style="padding: 8px; border: 1px solid #d1d5db;">${thAction}</th>
        <th style="padding: 8px; border: 1px solid #d1d5db;">${thSLA}</th>
        <th style="padding: 8px; border: 1px solid #d1d5db;">${thStatus}</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td style="padding: 8px; border: 1px solid #d1d5db; font-weight: bold; color: #dc2626;">${p1Label}</td>
        <td style="padding: 8px; border: 1px solid #d1d5db;">${p1Action}</td>
        <td style="padding: 8px; border: 1px solid #d1d5db;">${p1SLA}</td>
        <td style="padding: 8px; border: 1px solid #d1d5db;">${p1Status}</td>
      </tr>
      <tr>
        <td style="padding: 8px; border: 1px solid #d1d5db; font-weight: bold; color: #d97706;">${p2Label}</td>
        <td style="padding: 8px; border: 1px solid #d1d5db;">${p2Action}</td>
        <td style="padding: 8px; border: 1px solid #d1d5db;">${p2SLA}</td>
        <td style="padding: 8px; border: 1px solid #d1d5db;">${p1Status}</td>
      </tr>
      <tr>
        <td style="padding: 8px; border: 1px solid #d1d5db; font-weight: bold; color: #2563eb;">${p3Label}</td>
        <td style="padding: 8px; border: 1px solid #d1d5db;">${p3Action}</td>
        <td style="padding: 8px; border: 1px solid #d1d5db;">${p3SLA}</td>
        <td style="padding: 8px; border: 1px solid #d1d5db;">${p1Status}</td>
      </tr>
    </tbody>
  </table>

  <h2>${findingsInventoryTitle}</h2>
  ${scanFindings.map((f, i) => `
    <div class="finding-card">
      <div style="display: flex; justify-content: space-between;">
        <strong>#${i + 1} ${escHtml(f.title)}</strong>
        <span class="badge badge-${escHtml(f.severity.toLowerCase())}">${escHtml(f.severity)} (CVSS ${f.cvss.toFixed(1)})</span>
      </div>
      <div style="font-size: 11px; color: #4b5563; font-family: monospace; margin: 4px 0;">${hostLabel}: ${escHtml(f.host)} | ${portLabel}: ${escHtml(f.port || 'N/A')} | ${engineLabel}: ${escHtml(f.source_engine.toUpperCase())}</div>
      <p style="font-size: 12px; margin: 6px 0;">${escHtml(f.description)}</p>
      ${f.remediation ? `<div style="font-size: 12px; background: #ecfdf5; border-left: 3px solid #10b981; padding: 6px; margin-top: 6px;"><strong>${blueTeamFixLabel}</strong> ${escHtml(f.remediation)}</div>` : ''}
      ${includeEvidence && f.evidence ? `<pre class="evidence-box">${escHtml(f.evidence)}</pre>` : ''}
    </div>
  `).join('')}

  <div class="footer">
    ${safeFooter}
  </div>
</body>
</html>`;
  };

  const handleDownloadHTML = () => {
    const html = generateStandaloneHTML();
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `UrielScan_Report_${clientOrg?.name ? clientOrg.name.replace(/\s+/g, '_') : 'Assessment'}.html`;
    link.click();
    URL.revokeObjectURL(url);
    showToast(L('HTML report downloaded successfully.', 'Report HTML scaricato con successo.'), 'success');
  };

  const handlePrintPDF = () => {
    const html = generateStandaloneHTML();
    const printWindow = window.open('', '_blank');
    if (printWindow) {
      printWindow.document.write(html);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 500);
    }
  };

  const handleDownloadBackendReport = async (format: 'docx' | 'pdf') => {
    if (!currentScan) {
      showToast(L('Please select a valid scan first.', 'Seleziona prima una scansione valida.'), 'error');
      return;
    }
    setExportingFormat(format);
    try {
      await (api.downloadCustomReport as any)({
        scan_id: currentScan.id,
        format,
        report_title: reportTitle,
        classification,
        executive_notes: executiveNotes,
        include_ai: includeAI,
        include_evidence: includeEvidence,
        include_host_topology: includeHostTopology,
        lang,
      });
      showToast(
        format === 'docx'
          ? L('Editable DOCX report downloaded successfully.', 'Report DOCX modificabile scaricato con successo.')
          : L('PDF report downloaded successfully.', 'Report PDF scaricato con successo.'),
        'success'
      );
    } catch (err: any) {
      showToast(err?.message || L(`Error generating ${format.toUpperCase()} report`, `Errore generazione report ${format.toUpperCase()}`), 'error');
    } finally {
      setExportingFormat(null);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="card-industrial p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center space-x-2 text-[11px] uppercase font-bold tracking-wider text-theme-accent">
            <FileText className="w-3.5 h-3.5" />
            <span>Report Center White-Label MSP</span>
          </div>
          <h1 className="text-base font-bold text-theme-primary mt-0.5 tracking-tight">
            {L('Security & Compliance Report Generator', 'Generatore Report di Sicurezza & Conformità')}
          </h1>
          <p className="text-xs text-theme-secondary mt-0.5">
            {L(
              'Export technical assessments and executive summaries ready for CISO sign-off and PDF printing.',
              'Esporta valutazioni tecniche ed executive summary pronti per la firma del CISO e la stampa PDF.'
            )}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setIsPreviewOpen(true)}
            className="btn-secondary flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold"
          >
            <Eye className="w-3.5 h-3.5 text-theme-accent" />
            <span>{L('Preview', 'Anteprima')}</span>
          </button>
          <button
            onClick={() => handleDownloadBackendReport('docx')}
            disabled={!currentScan || exportingFormat !== null}
            className="btn-primary flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
            title={L('Download editable template in Word / LibreOffice Writer (.docx)', 'Scarica template modificabile in Word / LibreOffice Writer (.docx)')}
          >
            {exportingFormat === 'docx' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileEdit className="w-3.5 h-3.5" />}
            <span>{L('Download DOCX (Editable)', 'Scarica DOCX (Modificabile)')}</span>
          </button>
          <button
            onClick={() => handleDownloadBackendReport('pdf')}
            disabled={!currentScan || exportingFormat !== null}
            className="btn-secondary flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
            title={L('Download formatted PDF document', 'Scarica documento PDF impaginato')}
          >
            {exportingFormat === 'pdf' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            <span>{L('Download PDF', 'Scarica PDF')}</span>
          </button>
          <button
            onClick={handleDownloadHTML}
            className="btn-secondary flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold"
          >
            <Download className="w-3.5 h-3.5" />
            <span>HTML</span>
          </button>
          <button
            onClick={handlePrintPDF}
            className="btn-secondary flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>{L('Print', 'Stampa')}</span>
          </button>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left: Options */}
        <div className="lg:col-span-2 space-y-4">
          <div className="card-industrial p-4 space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
              {L('Document Parameters', 'Parametri del Documento')}
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
                      {s.name} ({s.status})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  {L('Confidentiality Classification', 'Classificazione Riservatezza')}
                </label>
                <select
                  value={classification}
                  onChange={(e) => setClassification(e.target.value as any)}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs font-mono"
                >
                  <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                  <option value="STRICTLY CONFIDENTIAL">STRICTLY CONFIDENTIAL</option>
                  <option value="INTERNAL">INTERNAL</option>
                  <option value="RESTRICTED">RESTRICTED</option>
                </select>
              </div>

              <div className="md:col-span-2">
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  {L('Main Report Title', 'Titolo Principale del Report')}
                </label>
                <input
                  type="text"
                  value={reportTitle}
                  onChange={(e) => {
                    setReportTitle(e.target.value);
                    setHasCustomTitle(true);
                  }}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs"
                />
              </div>

              <div className="md:col-span-2">
                <label className="block text-xs font-medium text-theme-secondary mb-1">
                  {L('Executive Summary Notes for Management', 'Note di Sintesi Esecutiva per il Management')}
                </label>
                <textarea
                  rows={3}
                  value={executiveNotes}
                  onChange={(e) => {
                    setExecutiveNotes(e.target.value);
                    setHasCustomNotes(true);
                  }}
                  className="input-industrial w-full px-2.5 py-1.5 text-xs"
                />
              </div>
            </div>

            <div className="pt-2 border-t border-theme-subtle space-y-2">
              <label className="text-xs font-semibold text-theme-secondary block">
                {L('Sections to Include', 'Sezioni da Includere')}
              </label>
              <div className="flex flex-wrap gap-4 text-xs text-theme-primary">
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeAI}
                    onChange={(e) => setIncludeAI(e.target.checked)}
                    className="rounded"
                  />
                  <span>{L('AI Purple Team Analysis', 'Analisi Purple Team AI')}</span>
                </label>
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeEvidence}
                    onChange={(e) => setIncludeEvidence(e.target.checked)}
                    className="rounded"
                  />
                  <span>{L('Technical Engine Evidence', 'Evidenze Tecniche dei Motori')}</span>
                </label>
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeHostTopology}
                    onChange={(e) => setIncludeHostTopology(e.target.checked)}
                    className="rounded"
                  />
                  <span>{L('Host & Port Topology', 'Topologia Host & Porte')}</span>
                </label>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Summary Card */}
        <div className="space-y-4">
          <div className="card-industrial p-4 space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-theme-secondary">
              {L('Recipient Information', 'Dati del Destinatario')}
            </h2>
            <div className="space-y-2 text-xs">
              <div className="p-2.5 rounded bg-subtle border border-theme">
                <div className="font-bold text-theme-primary">{clientOrg?.name || L('Client', 'Cliente')}</div>
                <div className="text-[11px] text-theme-secondary font-mono">{clientOrg?.industry}</div>
                <div className="text-[11px] text-theme-muted font-mono mt-1">Scope: {currentScan?.targets}</div>
              </div>
              <div className="p-2.5 rounded bg-subtle border border-theme font-mono text-[11px] space-y-1">
                <div>{L('Total Findings:', 'Totale Finding:')} <strong>{scanFindings.length}</strong></div>
                <div className="text-red-400">{L('Critical:', 'Critiche:')} {criticalCount}</div>
                <div className="text-orange-400">{L('High:', 'Alte:')} {highCount}</div>
                <div className="text-amber-400">{L('Medium:', 'Medie:')} {mediumCount}</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Preview Modal */}
      {isPreviewOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
          <div className="card-industrial w-full max-w-4xl max-h-[85vh] flex flex-col overflow-hidden shadow-2xl">
            <div className="flex items-center justify-between p-3 border-b border-theme bg-subtle">
              <span className="text-xs font-bold text-theme-primary">{L('Assessment Document Preview', 'Anteprima Documento di Valutazione')}</span>
              <button
                onClick={() => setIsPreviewOpen(false)}
                className="btn-secondary p-1 text-theme-muted hover:text-theme-primary"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-6 bg-white text-slate-900">
              <iframe
                title={L('Report Preview', 'Anteprima Report')}
                sandbox=""
                srcDoc={generateStandaloneHTML()}
                className="w-full h-[600px] border-0"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
