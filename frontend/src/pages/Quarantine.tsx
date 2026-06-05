import { useState } from 'react'
import toast from 'react-hot-toast'
import { useQuarantine, useRestoreQuarantine, useDeleteQuarantine } from '../hooks/useApi'
import { SeverityBadge } from '../components/SeverityBadge'
import { ConfirmModal } from '../components/ConfirmModal'
import { PageLoader } from '../components/LoadingSpinner'
import type { QuarantineItem } from '../types'

// ─── Mock data ────────────────────────────────────────────────────────────────
const MOCK_QUARANTINE: QuarantineItem[] = [
  {
    id: 'q1',
    filename: 'setup.exe',
    original_path: 'C:\\Users\\user\\Downloads\\setup.exe',
    quarantine_date: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    threat_name: 'Trojan.GenericKD.71435882',
    severity: 'critical',
    size_bytes: 2_450_000,
    hash_sha256: 'a94f3e8b1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f',
  },
  {
    id: 'q2',
    filename: 'wcrypt.exe',
    original_path: 'C:\\Temp\\wcrypt.exe',
    quarantine_date: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    threat_name: 'Ransom.WannaCrypt',
    severity: 'critical',
    size_bytes: 3_720_000,
    hash_sha256: 'b3e4f5a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4',
  },
  {
    id: 'q3',
    filename: 'svchost32.exe',
    original_path: 'C:\\ProgramData\\svchost32.exe',
    quarantine_date: new Date(Date.now() - 1000 * 60 * 60 * 3).toISOString(),
    threat_name: 'Miner.XMRig',
    severity: 'high',
    size_bytes: 1_230_000,
    hash_sha256: 'c4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5',
  },
  {
    id: 'q4',
    filename: 'browse_fox.dll',
    original_path: 'C:\\Users\\user\\AppData\\browse_fox.dll',
    quarantine_date: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString(),
    threat_name: 'PUA.Adware.BrowseFox',
    severity: 'medium',
    size_bytes: 450_000,
    hash_sha256: 'd5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6',
  },
]

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function Quarantine() {
  const { data, isLoading, isError, refetch } = useQuarantine()
  const restoreMutation = useRestoreQuarantine()
  const deleteMutation = useDeleteQuarantine()

  const [confirmAction, setConfirmAction] = useState<{
    type: 'restore' | 'delete'
    item: QuarantineItem
  } | null>(null)

  const items: QuarantineItem[] = data ?? (isError ? MOCK_QUARANTINE : [])

  function handleRestore(item: QuarantineItem) {
    setConfirmAction({ type: 'restore', item })
  }

  function handleDelete(item: QuarantineItem) {
    setConfirmAction({ type: 'delete', item })
  }

  function handleConfirm() {
    if (!confirmAction) return
    const { type, item } = confirmAction
    setConfirmAction(null)

    if (type === 'restore') {
      restoreMutation.mutate(item.id, {
        onSuccess: () => toast.success(`Restored: ${item.filename}`),
        onError: () => toast.error('Failed to restore item'),
      })
    } else {
      deleteMutation.mutate(item.id, {
        onSuccess: () => toast.success(`Deleted: ${item.filename}`),
        onError: () => toast.error('Failed to delete item'),
      })
    }
  }

  if (isLoading && !items.length) return <PageLoader />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Quarantine</h1>
          <p className="text-sm text-text-muted mt-0.5">{items.length} item{items.length !== 1 ? 's' : ''} in quarantine</p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-bg-tertiary border border-bg-border text-text-secondary hover:text-text-primary text-sm transition-colors"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </button>
      </div>

      {isError && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 px-4 py-2 rounded-lg text-sm">
          Showing demo data — API unreachable.
        </div>
      )}

      <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-bg-tertiary border-b border-bg-border">
                {['Filename', 'Original Path', 'Threat Name', 'Severity', 'Date', 'Size', 'Actions'].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} className="border-t border-bg-border/50 hover:bg-bg-tertiary/30 transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-8 rounded bg-red-500/10 flex items-center justify-center flex-shrink-0">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4 text-red-400">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                        </svg>
                      </div>
                      <span className="font-medium text-text-primary font-mono text-xs">{item.filename}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-text-muted max-w-[220px] truncate">
                    {item.original_path}
                  </td>
                  <td className="px-4 py-3 text-text-secondary max-w-[180px] truncate">
                    {item.threat_name}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={item.severity} size="sm" />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-text-muted whitespace-nowrap">
                    {new Date(item.quarantine_date).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-text-muted text-xs">
                    {formatSize(item.size_bytes)}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleRestore(item)}
                        disabled={restoreMutation.isPending || deleteMutation.isPending}
                        className="px-2 py-1 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded text-xs hover:bg-blue-500/30 transition-colors disabled:opacity-50"
                      >
                        Restore
                      </button>
                      <button
                        onClick={() => handleDelete(item)}
                        disabled={restoreMutation.isPending || deleteMutation.isPending}
                        className="px-2 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs hover:bg-red-500/30 transition-colors disabled:opacity-50"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-text-muted">
                    <div className="flex flex-col items-center gap-2">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="w-10 h-10 opacity-30">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <p>Quarantine is empty</p>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* SHA-256 hashes section */}
        {items.length > 0 && (
          <div className="border-t border-bg-border px-4 py-3">
            <details className="text-xs text-text-muted">
              <summary className="cursor-pointer hover:text-text-primary transition-colors">Show SHA-256 hashes</summary>
              <div className="mt-2 space-y-1">
                {items.map((item) => (
                  <div key={item.id} className="flex gap-3 font-mono">
                    <span className="text-text-primary">{item.filename}</span>
                    <span className="text-text-muted break-all">{item.hash_sha256}</span>
                  </div>
                ))}
              </div>
            </details>
          </div>
        )}
      </div>

      <ConfirmModal
        open={!!confirmAction}
        title={confirmAction?.type === 'restore' ? 'Restore File' : 'Delete File Permanently'}
        message={
          confirmAction?.type === 'restore'
            ? `Restore "${confirmAction.item.filename}" to its original location "${confirmAction.item.original_path}"? Ensure the threat has been remediated first.`
            : `Permanently delete "${confirmAction?.item.filename}"? This action cannot be undone.`
        }
        confirmLabel={confirmAction?.type === 'restore' ? 'Restore' : 'Delete Permanently'}
        danger={confirmAction?.type === 'delete'}
        onConfirm={handleConfirm}
        onCancel={() => setConfirmAction(null)}
      />
    </div>
  )
}
