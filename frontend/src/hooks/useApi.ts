import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  dashboardApi,
  detectionsApi,
  alertsApi,
  scanApi,
  quarantineApi,
  rulesApi,
  settingsApi,
  exclusionsApi,
  webcamApi,
  telemetryApi,
} from '../api/endpoints'
import type { ScanType, WebcamPolicy, GeneralSettings, Exclusion, Rule } from '../types'

// ─── Dashboard ────────────────────────────────────────────────────────────────
export function useDashboard() {
  return useQuery({
    queryKey: ['dashboard'],
    queryFn: dashboardApi.get,
    refetchInterval: 30_000,
    retry: 2,
  })
}

export function useStatus() {
  return useQuery({
    queryKey: ['status'],
    queryFn: dashboardApi.getStatus,
    refetchInterval: 15_000,
  })
}

// ─── Detections ───────────────────────────────────────────────────────────────
export function useDetections(params: {
  page?: number
  limit?: number
  severity?: string
  q?: string
  from?: string
  to?: string
}) {
  return useQuery({
    queryKey: ['detections', params],
    queryFn: () => detectionsApi.list(params),
    placeholderData: (prev) => prev,
  })
}

export function useDetection(id: string | null) {
  return useQuery({
    queryKey: ['detection', id],
    queryFn: () => detectionsApi.get(id!),
    enabled: !!id,
  })
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
export function useAlerts() {
  return useQuery({
    queryKey: ['alerts'],
    queryFn: alertsApi.list,
    refetchInterval: 5_000,
  })
}

export function useDismissAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: alertsApi.dismiss,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })
}

// ─── Scanner ──────────────────────────────────────────────────────────────────
export function useScanProgress() {
  return useQuery({
    queryKey: ['scan-progress'],
    queryFn: scanApi.progress,
    refetchInterval: 2_000,
  })
}

export function useScanHistory() {
  return useQuery({
    queryKey: ['scan-history'],
    queryFn: scanApi.history,
  })
}

export function useStartScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ type, paths }: { type: ScanType; paths?: string[] }) =>
      scanApi.start(type, paths),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-progress'] })
      qc.invalidateQueries({ queryKey: ['scan-history'] })
    },
  })
}

export function useStopScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (scanId: string) => scanApi.stop(scanId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-progress'] }),
  })
}

// ─── Quarantine ───────────────────────────────────────────────────────────────
export function useQuarantine() {
  return useQuery({
    queryKey: ['quarantine'],
    queryFn: quarantineApi.list,
  })
}

export function useRestoreQuarantine() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => quarantineApi.restore(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['quarantine'] }),
  })
}

export function useDeleteQuarantine() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => quarantineApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['quarantine'] }),
  })
}

// ─── Rules ────────────────────────────────────────────────────────────────────
export function useRules(params?: { scope?: string; source?: string }) {
  return useQuery({
    queryKey: ['rules', params],
    queryFn: () => rulesApi.list(params),
  })
}

export function useSetRuleEnabled() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      rulesApi.setEnabled(id, enabled),
    onMutate: async ({ id, enabled }) => {
      await qc.cancelQueries({ queryKey: ['rules'] })
      const prev = qc.getQueriesData<{ rules: Rule[] }>({ queryKey: ['rules'] })
      qc.setQueriesData<{ rules: Rule[]; total: number; enabled_count: number }>(
        { queryKey: ['rules'] },
        (old) => old
          ? {
              ...old,
              rules: old.rules.map((r) => (r.id === id ? { ...r, enabled } : r)),
            }
          : old
      )
      return { prev }
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.prev) {
        ctx.prev.forEach(([key, val]) => qc.setQueryData(key, val))
      }
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useImportRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (file: File) => rulesApi.importRule(file),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

// ─── Settings ────────────────────────────────────────────────────────────────
export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: settingsApi.get,
  })
}

export function useUpdateSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (settings: Partial<GeneralSettings>) => settingsApi.update(settings),
    onMutate: async (updates) => {
      await qc.cancelQueries({ queryKey: ['settings'] })
      const prev = qc.getQueryData<GeneralSettings>(['settings'])
      qc.setQueryData<GeneralSettings>(['settings'], (old) =>
        old ? { ...old, ...updates } : old
      )
      return { prev }
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.prev) qc.setQueryData(['settings'], ctx.prev)
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['settings'] }),
  })
}

// ─── Exclusions ───────────────────────────────────────────────────────────────
export function useExclusions() {
  return useQuery({
    queryKey: ['exclusions'],
    queryFn: exclusionsApi.list,
  })
}

export function useAddExclusion() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (excl: Omit<Exclusion, 'id' | 'created_at'>) => exclusionsApi.add(excl),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['exclusions'] }),
  })
}

export function useRemoveExclusion() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => exclusionsApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['exclusions'] }),
  })
}

// ─── Webcam ───────────────────────────────────────────────────────────────────
export function useWebcam() {
  return useQuery({
    queryKey: ['webcam'],
    queryFn: webcamApi.get,
  })
}

export function useSetWebcamPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (policy: WebcamPolicy) => webcamApi.setPolicy(policy),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webcam'] }),
  })
}

export function useAddWebcamTrusted() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: webcamApi.addTrusted,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webcam'] }),
  })
}

export function useRemoveWebcamTrusted() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => webcamApi.removeTrusted(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webcam'] }),
  })
}

// ─── Telemetry ────────────────────────────────────────────────────────────────
export function useProcessTree() {
  return useQuery({
    queryKey: ['telemetry-processes'],
    queryFn: telemetryApi.processes,
    refetchInterval: 5_000,
  })
}

export function useNetworkConnections() {
  return useQuery({
    queryKey: ['telemetry-network'],
    queryFn: telemetryApi.network,
    refetchInterval: 5_000,
  })
}

export function useFileEvents() {
  return useQuery({
    queryKey: ['telemetry-files'],
    queryFn: telemetryApi.files,
    refetchInterval: 5_000,
  })
}

export function useRegistryEvents() {
  return useQuery({
    queryKey: ['telemetry-registry'],
    queryFn: telemetryApi.registry,
    refetchInterval: 5_000,
  })
}
