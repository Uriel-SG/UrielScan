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
