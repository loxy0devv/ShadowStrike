// ─── Severity ────────────────────────────────────────────────────────────────
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type SeverityNum = 0 | 1 | 2 | 3 | 4

export function severityFromNum(n: SeverityNum): Severity {
  const map: Record<SeverityNum, Severity> = {
    0: 'info',
    1: 'low',
    2: 'medium',
    3: 'high',
    4: 'critical',
  }
  return map[n] ?? 'info'
}

// ─── Dashboard ───────────────────────────────────────────────────────────────
export interface ModuleState {
  name: string
  enabled: boolean
  status: 'running' | 'paused' | 'error' | 'disabled'
  lastEvent?: string
}

export interface ThreatTimelinePoint {
  hour: string
  count: number
}

export interface DashboardData {
  threats_24h: number
  active_scans: number
  protection_status: 'protected' | 'at_risk' | 'paused' | 'disabled'
  rules_loaded: number
  module_states: ModuleState[]
  threat_timeline: ThreatTimelinePoint[]
  recent_detections: Detection[]
}

// ─── Detections ──────────────────────────────────────────────────────────────
export interface Detection {
  id: string
  timestamp: string
  threat_name: string
  severity: Severity
  file_path: string
  process: string
  pid?: number
  action_taken: string
  rule_matched: string
  status: 'detected' | 'quarantined' | 'blocked' | 'allowed' | 'investigating'
  raw?: Record<string, unknown>
  attack_chain?: AttackChainStep[]
  evidence?: string[]
}

export interface AttackChainStep {
  step: number
  timestamp: string
  action: string
  process: string
  pid: number
  detail: string
}

export interface DetectionsResponse {
  detections: Detection[]
  total: number
  page: number
  limit: number
}

// ─── Alerts ──────────────────────────────────────────────────────────────────
export type AlertType = 'threat' | 'scan' | 'update' | 'system' | 'policy' | 'network'

export interface Alert {
  id: string
  type: AlertType
  title: string
  message: string
  severity: Severity
  timestamp: string
  dismissed: boolean
  source?: string
}

export interface AlertsResponse {
  alerts: Alert[]
  unread_count: number
}

// ─── Scan ────────────────────────────────────────────────────────────────────
export type ScanType = 'quick' | 'full' | 'custom'
export type ScanStatus = 'idle' | 'running' | 'completed' | 'stopped' | 'error'

export interface ScanProgress {
  scan_id: string
  type: ScanType
  status: ScanStatus
  percent: number
  files_scanned: number
  files_total: number
  threats_found: number
  current_file: string
  eta_seconds: number
  started_at: string
}

export interface ScanHistoryItem {
  id: string
  type: ScanType
  status: ScanStatus
  started_at: string
  completed_at: string
  files_scanned: number
  threats_found: number
  duration_seconds: number
}

// ─── Quarantine ───────────────────────────────────────────────────────────────
export interface QuarantineItem {
  id: string
  filename: string
  original_path: string
  quarantine_date: string
  threat_name: string
  severity: Severity
  size_bytes: number
  hash_sha256: string
}

// ─── Rules ───────────────────────────────────────────────────────────────────
export type RuleScope = 'file' | 'process' | 'network' | 'registry' | 'behavior' | 'memory'
export type RuleSource = 'native' | 'sigma' | 'capa' | 'elastic' | 'custom' | 'yara'

export interface Rule {
  id: string
  name: string
  scope: RuleScope
  severity: Severity
  enabled: boolean
  source: RuleSource
  description?: string
  tags?: string[]
  matches_24h?: number
  last_matched?: string
  created_at?: string
}

export interface RulesResponse {
  rules: Rule[]
  total: number
  enabled_count: number
}

// ─── Settings ────────────────────────────────────────────────────────────────
export interface GeneralSettings {
  realtime_protection: boolean
  ml_model_enabled: boolean
  auto_update: boolean
  behavior_monitoring: boolean
  network_monitoring: boolean
  cloud_lookup: boolean
  game_mode: boolean
}

export interface Exclusion {
  id: string
  type: 'path' | 'path_prefix' | 'extension' | 'process' | 'hash'
  pattern: string
  description?: string
  enabled: boolean
  created_at: string
}

export type WebcamPolicy = 'allow' | 'ask' | 'block'

export interface WebcamSettings {
  policy: WebcamPolicy
  trusted_processes: WebcamTrustedProcess[]
  devices: WebcamDevice[]
}

export interface WebcamTrustedProcess {
  id: string
  image_name: string
  image_path?: string
  signer?: string
  added_at: string
}

export interface WebcamDevice {
  id: string
  name: string
  busy: boolean
}

// ─── Telemetry ────────────────────────────────────────────────────────────────
export interface ProcessNode {
  pid: number
  ppid: number
  name: string
  path: string
  command_line: string
  user: string
  integrity: 'system' | 'high' | 'medium' | 'low'
  evidence_score: number
  started_at: string
  children?: ProcessNode[]
  suspicious?: boolean
}

export interface NetworkConnection {
  pid: number
  process: string
  protocol: 'tcp' | 'udp'
  local_address: string
  local_port: number
  remote_address: string
  remote_port: number
  state: 'established' | 'listening' | 'time_wait' | 'close_wait' | 'syn_sent' | 'syn_recv'
  bytes_sent?: number
  bytes_recv?: number
}

export interface FileEvent {
  id: string
  timestamp: string
  operation: 'create' | 'write' | 'read' | 'delete' | 'rename' | 'move'
  path: string
  pid: number
  process: string
  size_bytes?: number
  flags?: string[]
}

export interface RegistryEvent {
  id: string
  timestamp: string
  operation: 'create' | 'set' | 'delete' | 'query' | 'rename'
  key: string
  value_name?: string
  data?: string
  pid: number
  process: string
}

// ─── API Responses ────────────────────────────────────────────────────────────
export interface ApiError {
  ok: false
  error: {
    code: string
    message: string
  }
}

export interface ApiSuccess<T = unknown> {
  ok: true
  data: T
}

export type ApiResponse<T = unknown> = ApiSuccess<T> | ApiError

// ─── Connection Status ────────────────────────────────────────────────────────
export type ConnectionStatus = 'connected' | 'disconnected' | 'connecting'
