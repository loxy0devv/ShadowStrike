import apiClient from './client'
import type {
  DashboardData,
  DetectionsResponse,
  Detection,
  AlertsResponse,
  ScanProgress,
  ScanHistoryItem,
  QuarantineItem,
  RulesResponse,
  Rule,
  GeneralSettings,
  Exclusion,
  WebcamSettings,
  WebcamPolicy,
  WebcamTrustedProcess,
  ProcessNode,
  NetworkConnection,
  FileEvent,
  RegistryEvent,
  ScanType,
} from '../types'

// ─── Auth ─────────────────────────────────────────────────────────────────────
export const authApi = {
  login: async (password: string) => {
    const res = await apiClient.post<{ token: string; csrfToken: string }>('/auth/login', { password })
    return res.data
  },
  logout: async () => {
    await apiClient.post('/auth/logout')
  },
  session: async () => {
    const res = await apiClient.get('/auth/session')
    return res.data
  },
  health: async () => {
    const res = await apiClient.get('/health')
    return res.data
  },
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
export const dashboardApi = {
  get: async (): Promise<DashboardData> => {
    const res = await apiClient.get<DashboardData>('/api/v1/dashboard')
    return res.data
  },
  getStatus: async () => {
    const res = await apiClient.get('/api/v1/status')
    return res.data
  },
  getStats: async () => {
    const res = await apiClient.get('/api/v1/stats')
    return res.data
  },
  getModules: async () => {
    const res = await apiClient.get('/api/v1/modules')
    return res.data
  },
}

// ─── Detections ───────────────────────────────────────────────────────────────
export const detectionsApi = {
  list: async (params: {
    page?: number
    limit?: number
    severity?: string
    q?: string
    from?: string
    to?: string
  }): Promise<DetectionsResponse> => {
    const res = await apiClient.get<DetectionsResponse>('/api/v1/detections', { params })
    return res.data
  },
  get: async (id: string): Promise<Detection> => {
    const res = await apiClient.get<Detection>(`/api/v1/detections/${id}`)
    return res.data
  },
  // REST API also exposes /threats
  listThreats: async (limit = 50) => {
    const res = await apiClient.get('/api/v1/threats', { params: { limit } })
    return res.data
  },
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
export const alertsApi = {
  list: async (): Promise<AlertsResponse> => {
    const res = await apiClient.get<AlertsResponse>('/api/v1/alerts')
    return res.data
  },
  dismiss: async (id: string): Promise<void> => {
    await apiClient.post(`/api/v1/alerts/${id}/dismiss`)
  },
  dismissAll: async (): Promise<void> => {
    await apiClient.post('/api/v1/alerts/dismiss-all')
  },
}

// ─── Scanner ──────────────────────────────────────────────────────────────────
export const scanApi = {
  start: async (type: ScanType, paths?: string[]): Promise<{ scan_id: string }> => {
    const body = type === 'custom' ? { type, paths } : { type }
    const res = await apiClient.post<{ scan_id: string }>('/api/v1/scan/start', body)
    return res.data
  },
  stop: async (scanId: string): Promise<void> => {
    await apiClient.post('/api/v1/scan/stop', { scan_id: scanId })
  },
  progress: async (): Promise<ScanProgress | null> => {
    const res = await apiClient.get<ScanProgress | null>('/api/v1/scan/progress')
    return res.data
  },
  history: async (): Promise<ScanHistoryItem[]> => {
    const res = await apiClient.get<ScanHistoryItem[]>('/api/v1/scan/history')
    return res.data
  },
}

// ─── Quarantine ───────────────────────────────────────────────────────────────
export const quarantineApi = {
  list: async (): Promise<QuarantineItem[]> => {
    const res = await apiClient.get<QuarantineItem[]>('/api/v1/quarantine')
    return res.data
  },
  restore: async (id: string): Promise<void> => {
    await apiClient.post(`/api/v1/quarantine/${id}/restore`)
  },
  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/quarantine/${id}`)
  },
}

// ─── Rules ────────────────────────────────────────────────────────────────────
export const rulesApi = {
  list: async (params?: { scope?: string; source?: string }): Promise<RulesResponse> => {
    const res = await apiClient.get<RulesResponse>('/api/v1/rules', { params })
    return res.data
  },
  get: async (id: string): Promise<Rule> => {
    const res = await apiClient.get<Rule>(`/api/v1/rules/${id}`)
    return res.data
  },
  setEnabled: async (id: string, enabled: boolean): Promise<void> => {
    await apiClient.put(`/api/v1/rules/${id}/enabled`, { enabled })
  },
  importRule: async (file: File): Promise<void> => {
    const text = await file.text()
    await apiClient.post('/api/v1/rules/import', { content: text, filename: file.name })
  },
  reload: async (): Promise<void> => {
    await apiClient.post('/api/v1/rules/reload')
  },
}

// ─── Settings ────────────────────────────────────────────────────────────────
export const settingsApi = {
  get: async (): Promise<GeneralSettings> => {
    const res = await apiClient.get<GeneralSettings>('/api/v1/settings')
    return res.data
  },
  update: async (settings: Partial<GeneralSettings>): Promise<void> => {
    await apiClient.put('/api/v1/settings', settings)
  },
  // REST: /config
  getConfig: async () => {
    const res = await apiClient.get('/api/v1/config')
    return res.data
  },
  updateConfig: async (updates: Record<string, unknown>) => {
    await apiClient.put('/api/v1/config', updates)
  },
}

// ─── Exclusions ───────────────────────────────────────────────────────────────
export const exclusionsApi = {
  list: async (): Promise<Exclusion[]> => {
    const res = await apiClient.get<Exclusion[]>('/api/v1/exclusions')
    return res.data
  },
  add: async (exclusion: Omit<Exclusion, 'id' | 'created_at'>): Promise<Exclusion> => {
    const res = await apiClient.post<Exclusion>('/api/v1/exclusions', exclusion)
    return res.data
  },
  remove: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/exclusions/${id}`)
  },
}

// ─── Webcam ───────────────────────────────────────────────────────────────────
export const webcamApi = {
  get: async (): Promise<WebcamSettings> => {
    const res = await apiClient.get<WebcamSettings>('/api/v1/devices/webcam')
    return res.data
  },
  getPolicy: async (): Promise<{ policy: WebcamPolicy }> => {
    const res = await apiClient.get<{ policy: WebcamPolicy }>('/api/v1/devices/webcam/policy')
    return res.data
  },
  setPolicy: async (policy: WebcamPolicy): Promise<void> => {
    await apiClient.put('/api/v1/devices/webcam/policy', { policy })
  },
  getTrusted: async (): Promise<WebcamTrustedProcess[]> => {
    const res = await apiClient.get<WebcamTrustedProcess[]>('/api/v1/devices/webcam/trusted')
    return res.data
  },
  addTrusted: async (process: { image_name: string; image_path?: string; signer?: string }): Promise<void> => {
    await apiClient.post('/api/v1/devices/webcam/trusted', process)
  },
  removeTrusted: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/devices/webcam/trusted/${id}`)
  },
}

// ─── Telemetry ────────────────────────────────────────────────────────────────
export const telemetryApi = {
  processes: async (): Promise<ProcessNode[]> => {
    const res = await apiClient.get<ProcessNode[]>('/api/v1/telemetry/processes')
    return res.data
  },
  network: async (): Promise<NetworkConnection[]> => {
    const res = await apiClient.get<NetworkConnection[]>('/api/v1/telemetry/network')
    return res.data
  },
  files: async (): Promise<FileEvent[]> => {
    const res = await apiClient.get<FileEvent[]>('/api/v1/telemetry/files')
    return res.data
  },
  registry: async (): Promise<RegistryEvent[]> => {
    const res = await apiClient.get<RegistryEvent[]>('/api/v1/telemetry/registry')
    return res.data
  },
}
