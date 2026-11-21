const I18N = {
  en: {
    navTag: 'BY URIELSEC',
    navEngines: 'Engines',
    navMsp: 'MSP Probes',
    navReporting: 'AI & Reports',
    navQuickstart: 'Quick Start',
    heroBadge: 'OPEN SOURCE • PURPLE TEAM • MSP READY',
    heroTitle: 'Unified Network & Web Vulnerability Operations.',
    heroDesc:
      'UrielScan merges Nmap + NSE, Nuclei templates, and asynchronous Native probes into a single command center — built for MSP/MSSP teams with remote client probes, AI Purple Team correlation, and white-label reporting.',
    ctaGithub: 'Explore on GitHub',
    ctaDeploy: 'Deploy in 60s',
    mEngines: 'Scan Engines',
    mProbes: 'Zero-Port Probes',
    mReports: 'Editable Reports',
    mLang: 'Bilingual UI',
    tabLive: 'Live Scan Stream',
    tabProbe: 'Remote Probe',
    tabReport: 'Purple Output',
    btnReplay: 'Replay',
    secEnginesEyebrow: 'TRI-ENGINE PIPELINE',
    secEnginesTitle: 'Real Scanners. Zero Blind Spots.',
    secEnginesDesc:
      'Combine deep infrastructure discovery with modern CVE detection and custom asynchronous checks from one unified orchestration layer.',
    cardNmap:
      'Automatic indexing of system .nse scripts, ZenMap++ operational profiles, service/version fingerprinting, and raw XML parsing.',
    cardNmapLi: 'Custom flags & NSE script catalog',
    cardNuclei:
      'Cross-platform GitHub Releases auto-downloader with tag & severity filtering and real-time JSONL findings ingestion.',
    cardNucleiLi: 'Automatic binary & template management',
    cardNative:
      'High-speed Python asynchronous TCP banner grabbing, TLS/SSL cipher & cert inspection, HTTP security headers, CORS, and safe web checks.',
    cardNativeLi: 'Zero external dependencies required',
    secMspEyebrow: 'MULTI-TENANT MSP ARCHITECTURE',
    secMspTitle: 'Scan Client LANs Without Opening Firewall Ports.',
    secMspDesc:
      'Deploy a single lightweight probe inside each client network. Outbound HTTPS pull eliminates VPN routing headaches and RFC1918 IP conflicts.',
    archClient: "Runs Nmap, Nuclei & Native scans locally inside the customer's VLAN.",
    archServer: 'Queues jobs, streams live progress, correlates findings, and isolates data per tenant.',
    mspFeat1Title: 'Zero Inbound Ports & Zero IP Conflicts',
    mspFeat1Desc:
      'Manage 50 clients using overlapping 192.168.1.0/24 subnets simultaneously. Each probe authenticates via SHA-256 hashed tokens and polls outbound over TLS.',
    mspFeat2Title: '2FA TOTP, Scheduler & Multi-Theme UI',
    mspFeat2Desc:
      'Built-in TOTP Two-Factor Authentication, recurring cron/interval scan scheduler, and 4 industrial themes (Uriel Ops default, Foundry Dark, Swiss Light, Phosphor Ops).',
    secRepEyebrow: 'PURPLE TEAM & DELIVERABLES',
    secRepTitle: 'AI Attack Paths & Editable Client Reports.',
    secRepDesc:
      'Turn raw scan output into executive and technical deliverables — with multi-provider AI or built-in offline remediation templates.',
    cardAiDesc:
      'Connect Google Gemini, OpenAI, Anthropic Claude, or local Ollama — or rely on the built-in heuristic engine for Red Team attack paths, MITRE ATT&CK mapping, and Blue Team fixes.',
    cardRepDesc:
      'Export raw scan results in CSV, TXT, or PDF, and generate white-label dual-logo client reports in editable DOCX (Word/LibreOffice), PDF, and HTML — even with AI offline.',
    secQsEyebrow: 'DEPLOYMENT',
    secQsTitle: 'Up and Running in Seconds.',
    secQsDesc: 'Clone from GitHub, install Python dependencies, and launch UrielScan on Windows or Linux.',
    btnCopy: 'Copy',
    btnCopied: 'Copied',
    footerNote: 'Open-source Purple Team Vulnerability Platform developed within the UrielSec ecosystem.',
    fProject: 'Project',
    fContacts: 'Contacts & Ecosystem',
  },
  it: {
    navTag: 'BY URIELSEC',
    navEngines: 'Motori',
    navMsp: 'Sonde MSP',
    navReporting: 'AI & Report',
    navQuickstart: 'Avvio Rapido',
    heroBadge: 'OPEN SOURCE • PURPLE TEAM • MSP READY',
    heroTitle: 'Operazioni Unificate di Vulnerability Assessment Rete & Web.',
    heroDesc:
      'UrielScan unisce Nmap + NSE, template Nuclei e probe asincroni Nativi in un unico Command Center — progettato per MSP/MSSP con sonde remote presso i clienti, analisi AI Purple Team e reportistica white-label.',
    ctaGithub: 'Esplora su GitHub',
    ctaDeploy: 'Avvia in 60s',
    mEngines: 'Motori di Scansione',
    mProbes: 'Sonde Zero-Porte',
    mReports: 'Report Modificabili',
    mLang: 'UI Bilingue',
    tabLive: 'Stream Scansione',
    tabProbe: 'Sonda Remota',
    tabReport: 'Output Purple',
    btnReplay: 'Riproduci',
    secEnginesEyebrow: 'PIPELINE TRI-MOTORE',
    secEnginesTitle: 'Scanner Reali. Zero Punti Ciechi.',
    secEnginesDesc:
      'Combina discovery infrastrutturale profonda, rilevamento CVE moderno e controlli web asincroni da un solo pannello di orchestrazione.',
    cardNmap:
      'Indicizzazione automatica degli script .nse di sistema, profili operativi ZenMap++, fingerprinting servizi/versioni e parsing XML.',
    cardNmapLi: 'Flag personalizzati & catalogo script NSE',
    cardNuclei:
      'Auto-downloader multipiattaforma da GitHub Releases con filtri per tag/severità e acquisizione finding JSONL in tempo reale.',
    cardNucleiLi: 'Gestione automatica binario e template',
    cardNative:
      'Scanner asincrono Python per banner TCP, ispezione cipher/certificati TLS/SSL, Security Header HTTP, CORS e controlli web sicuri.',
    cardNativeLi: 'Nessuna dipendenza esterna richiesta',
    secMspEyebrow: 'ARCHITETTURA MSP MULTI-TENANT',
    secMspTitle: 'Scansiona le LAN dei Clienti Senza Aprire Porte sul Firewall.',
    secMspDesc:
      'Installa una singola sonda leggera nella rete del cliente. Il polling HTTPS in uscita elimina VPN complesse e conflitti su subnet RFC1918.',
    archClient: 'Esegue Nmap, Nuclei e controlli Nativi localmente nella VLAN del cliente.',
    archServer: 'Accoda i job, riceve progresso live, correla i finding e isola i dati per tenant.',
    mspFeat1Title: 'Zero Porte in Ingresso & Zero Conflitti IP',
    mspFeat1Desc:
      'Gestisci 50 clienti con la stessa subnet 192.168.1.0/24 contemporaneamente. Ogni sonda si autentica con token SHA-256 via TLS in uscita.',
    mspFeat2Title: '2FA TOTP, Scheduler & UI Multi-Tema',
    mspFeat2Desc:
      'Autenticazione 2FA TOTP integrata, pianificatore cron/intervalli e 4 temi industriali (Uriel Ops default, Foundry Dark, Swiss Light, Phosphor Ops).',
    secRepEyebrow: 'PURPLE TEAM & DELIVERABLE',
    secRepTitle: 'Attack Path AI & Report Modificabili per Clienti.',
    secRepDesc:
      'Trasforma i risultati tecnici in deliverable esecutivi — con AI multi-provider o template di remediation offline integrati.',
    cardAiDesc:
      'Collega Google Gemini, OpenAI, Anthropic Claude o Ollama locale — oppure usa il motore euristico offline per vettori Red Team, MITRE ATT&CK e fix Blue Team.',
    cardRepDesc:
      'Esporta i risultati in CSV, TXT o PDF e genera report white-label con doppio logo in DOCX modificabile (Word/LibreOffice), PDF e HTML anche senza AI.',
    secQsEyebrow: 'DEPLOYMENT',
    secQsTitle: 'Operativo in Pochi Secondi.',
    secQsDesc: 'Clona da GitHub, installa le dipendenze Python e avvia UrielScan su Windows o Linux.',
    btnCopy: 'Copia',
    btnCopied: 'Copiato',
    footerNote: 'Piattaforma Open-Source di Vulnerability Assessment Purple Team sviluppata nell’ecosistema UrielSec.',
    fProject: 'Progetto',
    fContacts: 'Contatti & Ecosistema',
  },
};

const CONSOLE_SCRIPTS = {
  live: {
    meta: 'TARGET: 10.24.0.0/24 • ENGINES: NMAP + NUCLEI + NATIVE',
    lines: [
      '[19:42:01] [INFO] Initializing UrielScan Tri-Engine pipeline...',
      '[19:42:02] [NMAP] Running discovery & service detection (-sV --script ssl-enum-ciphers)',
      '[19:42:06] [NATIVE] Probing TLS certificates, HSTS, CSP & CORS policies...',
      '[19:42:09] [HIGH] Weak TLS 1.1 cipher suite detected on 10.24.0.12:443 (CVSS 7.4)',
      '[19:42:12] [NUCLEI] Executing CVE & misconfiguration templates...',
      '[19:42:16] [CRITICAL] Exposed Spring Boot Actuator /env on 10.24.0.18:8080 (CVSS 9.8)',
      '[19:42:18] [DONE] 2 hosts mapped • 7 findings saved • Ready for Purple Team AI & DOCX export.',
    ],
  },
  probe: {
    meta: 'PROBE: Milan-HQ-01 • OUTBOUND HTTPS -> urielscan.urielsec.com',
    lines: [
      '$ python3 urielscan_probe.py --server https://urielscan.urielsec.com --token us_***8f2a',
      '[PROBE] Detected engines: NMAP=true, NUCLEI=true, NATIVE=true',
      '[PROBE] Heartbeat OK -> status: ONLINE (outbound TLS 443)',
      '[JOB #42] Picked up queued scan for tenant: Acme FinTech S.p.A.',
      '[JOB #42] Scanning local subnet 192.168.10.0/24 (zero inbound firewall rules)',
      '[JOB #42] Uploading 14 findings & host topology to central Command Center...',
      '[PROBE] Job #42 completed cleanly. Waiting for next assignment.',
    ],
  },
  report: {
    meta: 'DELIVERABLES: DOCX (EDITABLE) • PDF • HTML • CSV • TXT',
    lines: [
      '# URIELSCAN PURPLE TEAM ASSESSMENT REPORT',
      'Client: Acme FinTech S.p.A. | Classification: CONFIDENTIAL',
      '------------------------------------------------------------',
      'KPI Summary: Critical: 1 | High: 3 | Medium: 5 | Low: 4',
      'Red Team Path : External API -> Actuator Exposure -> Token Leak (MITRE T1190)',
      'Blue Team P1  : Disable /env actuator & enforce TLS 1.3 (SLA: 24-72h)',
      'Export Ready  : urielscan_report_scan_42.docx (Editable Word/LibreOffice)',
    ],
  },
};

let currentLang = 'en';
let currentTab = 'live';
let typingTimer = null;

function applyLanguage(lang) {
  currentLang = lang;
  document.documentElement.lang = lang;
  document.querySelectorAll('.lang-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.lang === lang);
  });
  const dict = I18N[lang] || I18N.en;
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) el.textContent = dict[key];
  });
}

function playConsoleTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.console-tab').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
  });
  const out = document.getElementById('console-output');
  const meta = document.getElementById('console-meta');
  const data = CONSOLE_SCRIPTS[tab] || CONSOLE_SCRIPTS.live;
  meta.textContent = data.meta;
  out.textContent = '';

  if (typingTimer) clearInterval(typingTimer);
  let idx = 0;
  typingTimer = setInterval(() => {
    if (idx < data.lines.length) {
      out.textContent += (idx > 0 ? '\n' : '') + data.lines[idx];
      idx += 1;
    } else {
      clearInterval(typingTimer);
      typingTimer = null;
    }
  }, 190);
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('year').textContent = new Date().getFullYear();

  document.querySelectorAll('.lang-btn').forEach((btn) => {
    btn.addEventListener('click', () => applyLanguage(btn.dataset.lang));
  });

  document.querySelectorAll('.console-tab').forEach((btn) => {
    btn.addEventListener('click', () => playConsoleTab(btn.dataset.tab));
  });

  document.getElementById('replay-btn').addEventListener('click', () => playConsoleTab(currentTab));

  document.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const text = btn.getAttribute('data-copy') || '';
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = I18N[currentLang].btnCopied;
        setTimeout(() => {
          btn.textContent = I18N[currentLang].btnCopy;
        }, 1500);
      } catch {
        // fallback ignored
      }
    });
  });

  applyLanguage('en');
  playConsoleTab('live');
});
