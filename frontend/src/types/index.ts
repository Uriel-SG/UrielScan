export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type EngineSource = 'nmap' | 'nuclei' | 'zap' | 'native_web' | 'native_net' | string;

export type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'false_positive';

export interface Finding {
  id: string;
  scan_id: string;
  org_id: string;
  host: string;
  port?: number;
  protocol?: string;
  service?: string;
  title: string;
  severity: SeverityLevel;
  cvss: number;
  cve_ids: string[];
  cwe_id?: string;
  source_engine: EngineSource;
  description: string;
  evidence?: string;
  remediation?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  status: FindingStatus;
  ai_insight?: {
    red_team_scenario: string;
    blue_team_fix: string;
    code_snippet?: string;
    mitre_attack_id?: string;
  };
  created_at: string;
}

export interface HostInfo {
  ip: string;
  hostname?: string;
  os?: string;
  ports: {
    port: number;
    protocol: string;
    state: string;
    service: string;
    version?: string;
    banner?: string;
  }[];
  vulns_count: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export type ScanStatus = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'stopped';

export interface RemoteAgent {
  id: string;
  org_id: string;
  org_name?: string;
  name: string;
  token_prefix: string;
  token?: string;
  status: 'online' | 'offline';
  last_seen?: string;
  hostname?: string;
  ip_address?: string;
  os_info?: string;
  engines?: { nmap?: boolean; nuclei?: boolean; zap?: boolean; native?: boolean };
  version?: string;
  created_at: string;
}

export interface Scan {
  id: string;
  org_id: string;
  agent_id?: string | null;
  agent_name?: string | null;
  name: string;
  targets: string;
  scan_type: string;
  engines: string[];
  nmap_args?: string;
  nse_scripts?: string[];
  nuclei_tags?: string[];
  nuclei_severity?: string[];
  web_checks?: string[];
  zap_mode?: 'baseline' | 'full';
  onion_mode?: boolean;
  proxy_url?: string;
  enable_subdomain_enum?: boolean;
  enable_dir_enum?: boolean;
  recon?: ReconSummary;
  routing?: {
    mode?: string;
    onion_mode?: boolean;
    proxy_url?: string;
    exit_ip?: string;
    is_tor?: boolean;
  };
  status: ScanStatus;
  progress: number;
  started_at: string;
  completed_at?: string;
  findings_count: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  hosts_count: number;
  hosts?: HostInfo[];
  logs: string[];
  cloud_posture?: CloudPostureSummary;
  internal_ad?: InternalADSummary;
  ai_analysis?: {
    executive_summary: string;
    red_team_paths: string[];
    blue_team_priorities: string[];
    risk_score_reduction: string;
  };
}

export interface Organization {
  id: string;
  name: string;
  contact_email: string;
  industry: string;
  logo_url?: string;
  notes?: string;
  target_scope: string;
  created_at: string;
  scans_count?: number;
  open_vulns_count?: number;
}

export interface ScannerProfile {
  company_name: string;
  contact_email: string;
  website: string;
  report_footer: string;
  logo_url?: string;
  ai_provider: 'openai' | 'gemini' | 'anthropic' | 'ollama' | 'offline';
  ai_api_key?: string;
  ai_api_key_configured?: boolean;
  ai_api_key_masked?: string;
  ai_model: string;
  ai_base_url?: string;
}

export interface WordlistItem {
  id: string;
  name: string;
  filename: string;
  category: 'dns' | 'web';
  source: 'seclists' | 'custom';
  cached: boolean;
  size_bytes?: number | null;
  lines?: number | null;
  description?: string;
}

export interface ReconSummary {
  domains?: string[];
  total_subdomains?: number;
  subdomains?: string[];
  sources?: Record<string, Record<string, { status: string; found: number; unique: number }>>;
  live_subdomains?: Array<{
    subdomain: string;
    url: string;
    status_code: number;
    title?: string;
    tech?: string[];
    webserver?: string;
    ip?: string;
    cname?: string[];
    content_length?: number;
  }>;
  takeovers?: Array<{
    subdomain: string;
    service: string;
    cname: string;
    status: string;
    http_status?: number;
    reason?: string;
  }>;
  dns_zones?: Array<{
    domain: string;
    nameservers?: string[];
    axfr_vulnerable?: boolean;
    axfr_nameservers?: string[];
    axfr_records_count?: number;
    wildcard_dns?: boolean;
    has_spf?: boolean;
    has_dmarc?: boolean;
    has_caa?: boolean;
  }>;
  directories?: Array<{
    url: string;
    path: string;
    status: number;
    content_length?: number;
    content_type?: string;
  }>;
  tech_stack?: Array<{
    name: string;
    version?: string;
    category?: string;
    host?: string;
    url?: string;
    port?: number;
    source?: string;
    cpe?: string;
  }>;
  cve_intel?: Array<{
    cve_id: string;
    product: string;
    version: string;
    host?: string;
    url?: string;
    port?: number;
    cvss: number;
    severity: string;
    is_kev?: boolean;
    epss?: number | null;
    published?: string;
    summary?: string;
    poc_urls?: string[];
  }>;
  external_osint?: Array<{
    ip: string;
    hostnames?: string[];
    asn?: string;
    prefix?: string;
    org?: string;
    ports?: number[];
    cpes?: string[];
    vulns?: string[];
    tags?: string[];
    greynoise_classification?: string;
    greynoise_name?: string;
    greynoise_noise?: boolean;
    greynoise_riot?: boolean;
    greynoise_link?: string;
  }>;
}

export interface EngineStatus {
  nmap: {
    available: boolean;
    version?: string;
    scripts_count: number;
  };
  nuclei: {
    available: boolean;
    version?: string;
  };
  zap?: {
    available: boolean;
    version?: string;
    mode?: string;
  };
  tor?: {
    available: boolean;
    installed: boolean;
    version?: string;
    running?: boolean;
    socks_port?: number;
    control_port?: number;
    proxy_url?: string;
  };
  subfinder?: {
    available: boolean;
    installed?: boolean;
    version?: string;
  };
  httpx?: {
    available: boolean;
    installed?: boolean;
    version?: string;
  };
  feroxbuster?: {
    available: boolean;
    installed?: boolean;
    version?: string;
  };
  subzy?: {
    available: boolean;
    installed?: boolean;
    version?: string;
    fingerprints_count?: number;
  };
  native: {
    available: boolean;
  };
  ai: {
    configured: boolean;
    provider: string;
    model: string;
  };
  bootstrap?: {
    running: boolean;
    completed: boolean;
    engines: Record<string, { status: string; message: string }>;
  };
}

export interface NSEScript {
  name: string;
  categories: string[];
  description: string;
  author?: string;
  arguments?: string[];
}

export interface Schedule {
  id: string;
  org_id: string;
  name: string;
  targets: string;
  profile: string;
  frequency: 'hourly' | 'daily' | 'weekly' | 'monthly' | 'cron';
  cron_expr?: string;
  time_of_day?: string;
  day_of_week?: number;
  enabled: boolean;
  last_run?: string;
  next_run?: string;
}

export interface AuthUser {
  id: number;
  username: string;
  two_factor_enabled: boolean;
  totp_enabled?: boolean;
}

export interface LoginResponse {
  requires_2fa: boolean;
  temp_token?: string;
  token?: string;
  user?: AuthUser;
  message?: string;
}

export interface Setup2FAResponse {
  secret: string;
  otpauth_uri: string;
  qr_svg: string;
}

export interface SavedReport {
  id: string;
  scan_id: number;
  org_id: number;
  org_name?: string;
  title: string;
  classification?: string;
  created_at: string;
  file_path?: string;
  summary?: {
    format?: string;
    risk_score?: number;
    total_findings?: number;
    include_ai?: boolean;
  };
}

export interface SavedAIReport {
  id: string;
  scan_id?: number | null;
  org_id: number;
  org_name?: string;
  scan_name?: string;
  mode: string;
  scope_type: string;
  title: string;
  model_used?: string;
  locale?: string;
  prompt?: string;
  content_md: string;
  created_at: string;
}

export interface NatCheckResult {
  egress_public_ip: string | null;
  has_nat_loopback: boolean;
  loopback_targets: string[];
  details: Array<{
    target: string;
    host: string;
    resolved_ips: string[];
    is_nat_loopback: boolean;
  }>;
}

export interface ProbeInstallerPackage {
  agent_id: number;
  agent_name: string;
  platform: 'windows_msi' | 'linux_sh';
  filename: string;
  download_url: string;
  local_download_path: string;
  silent_command: string;
  expires_in_seconds: number;
}

export interface CloudPostureSummary {
  provider: string;
  account: string;
  compliance: string;
  services: string[];
  passed: number;
  failed: number;
  manual: number;
  total_checks: number;
  pass_rate: number;
  by_service: Record<string, { passed: number; failed: number; manual: number }>;
  by_severity: Record<string, number>;
}

export interface CloudProfile {
  id: string;
  org_id: string;
  org_name?: string;
  name: string;
  provider: string;
  region?: string;
  credentials_masked: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface CloudProviderSpec {
  id: string;
  label: string;
  short: string;
  default_region: string;
  default_services: string[];
  compliances: string[];
  fields: Array<{
    key: string;
    label: string;
    secret: boolean;
    placeholder?: string;
    multiline?: boolean;
  }>;
}

export interface CloudCatalog {
  engine: {
    installed: boolean;
    mode: string;
    path: string;
    version: string;
  };
  providers: Record<string, CloudProviderSpec>;
  compliances: Array<{ id: string; label: string }>;
}

export interface InternalToolInfo {
  installed: boolean;
  path: string;
  version: string;
  active_binary?: boolean;
}

export interface InternalADCatalog {
  tools: {
    netexec: InternalToolInfo;
    bloodhound: InternalToolInfo;
    azurehound: InternalToolInfo;
    enum4linux_ng: InternalToolInfo;
    responder: InternalToolInfo;
  };
  netexec_protocols: string[];
  netexec_checks: string[];
}

export interface NetworkInterfaceItem {
  name: string;
  ip: string;
  label: string;
}

export interface ResponderSessionStatus {
  running: boolean;
  mode: 'passive' | 'active';
  interface: string;
  bind_ip: string;
  started_at: string;
  elapsed_sec: number;
  hosts_seen: string[];
  protocols_seen: string[];
  packets_count: number;
  logs: Array<{ time: string; level: string; msg: string }>;
  error: string;
}

export interface InternalADSummary {
  targets?: string;
  domain?: string;
  export_available?: boolean;
  enum4linux?: { open_shares: string[]; users_count: number };
  bloodhound?: {
    domain: string;
    unconstrained_delegation: number;
    dangerous_acls: number;
    kerberoastable_admins: number;
    asrep_roastable: number;
    pwd_never_expires: number;
    domain_admins_count: number;
  };
  azurehound?: {
    tenant: string;
    global_admins: number;
    risky_graph_apps: number;
    privileged_guests: number;
  };
  lan_broadcast?: {
    mode: string;
    duration: number;
    hosts_seen: string[];
  };
}
