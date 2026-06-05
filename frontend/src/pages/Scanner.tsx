import { useState, useRef } from 'react'
import toast from 'react-hot-toast'
import { useScanProgress, useScanHistory, useStartScan, useStopScan } from '../hooks/useApi'
import type { ScanHistoryItem, ScanType } from '../types'

// ─── Mock data ────────────────────────────────────────────────────────────────
const MOCK_HISTORY: ScanHistoryItem[] = [
  {
    id: 's1',
    type: 'quick',
    status: 'completed',
    started_at: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    completed_at: new Date(Date.now() - 1000 * 60 * 75).toISOString(),
    files_scanned: 24891,
    threats_found: 2,
    duration_seconds: 900,
  },
  {
    id: 's2',
    type: 'full',
    status: 'completed',
    started_at: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
    completed_at: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString(),
    files_scanned: 1482943,
    threats_found: 5,
    duration_seconds: 7200,
  },
  {
    id: 's3',
    type: 'custom',
    status: 'completed',
    started_at: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
    completed_at: new Date(Date.now() - 1000 * 60 * 60 * 23).toISOString(),
    files_scanned: 8231,
    threats_found: 0,
    duration_seconds: 3400,
  },
]

function formatDuration(secs: number): string {
  const m = Math.floor(secs / 60)
  const s = secs % 60
  if (m >= 60) return `${Math.floor(m / 60)}h ${m % 60}m`
  return `${m}m ${s}s`
}

function formatETA(secs: number): string {
  if (secs <= 0) return 'calculating...'
  if (secs < 60) return `${secs}s`
  return `~${Math.ceil(secs / 60)}m`
}

// ─── Scan progress card ───────────────────────────────────────────────────────
function ScanProgressCard() {
  const { data: progress } = useScanProgress()
  const stopMutation = useStopScan()

  if (!progress || progress.status === 'idle' || progress.status === 'completed' || progress.status === 'stopped') {
    return null
  }

  const pct = Math.max(0, Math.min(100, progress.percent))

  return (
    <div className="bg-bg-card border border-accent-blue/30 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-text-primary">
            {progress.type === 'quick' ? 'Quick Scan' : progress.type === 'full' ? 'Full Scan' : 'Custom Scan'} in Progress
          </h3>
          <p className="text-xs text-text-muted mt-0.5">Scan ID: {progress.scan_id}</p>
        </div>
        <button
          onClick={() => {
            stopMutation.mutate(progress.scan_id, {
              onSuccess: () => toast.success('Scan stopped'),
              onError: () => toast.error('Failed to stop scan'),
            })
          }}
          disabled={stopMutation.isPending}
          className="px-3 py-1.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg text-sm hover:bg-red-500/30 transition-colors disabled:opacity-50"
        >
          Stop Scan
        </button>
      </div>

      {/* Progress bar */}
      <div className="mb-4">
        <div className="flex justify-between text-xs text-text-muted mb-1.5">
          <span>{pct.toFixed(1)}%</span>
          <span>ETA: {formatETA(progress.eta_seconds)}</span>
        </div>
        <div className="w-full bg-bg-tertiary rounded-full h-2">
          <div
            className="bg-accent-blue h-2 rounded-full transition-all duration-500"
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div>
          <p className="text-xs text-text-muted">Files Scanned</p>
          <p className="text-base font-bold text-text-primary">{progress.files_scanned.toLocaleString()}</p>
        </div>
        <div>
          <p className="text-xs text-text-muted">Total Files</p>
          <p className="text-base font-bold text-text-primary">
            {progress.files_total > 0 ? progress.files_total.toLocaleString() : '—'}
          </p>
        </div>
        <div>
          <p className="text-xs text-text-muted">Threats Found</p>
          <p className={`text-base font-bold ${progress.threats_found > 0 ? 'text-red-400' : 'text-green-400'}`}>
            {progress.threats_found}
          </p>
        </div>
      </div>

      {progress.current_file && (
        <div className="mt-3 bg-bg-primary rounded-lg px-3 py-2">
          <p className="text-xs text-text-muted mb-0.5">Scanning:</p>
          <p className="text-xs font-mono text-text-secondary truncate">{progress.current_file}</p>
        </div>
      )}
    </div>
  )
}

// ─── Scan history table ───────────────────────────────────────────────────────
function ScanHistoryTable({ items }: { items: ScanHistoryItem[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-bg-tertiary border-b border-bg-border">
            {['Type', 'Status', 'Started', 'Duration', 'Files Scanned', 'Threats Found'].map((h) => (
              <th key={h} className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id} className="border-t border-bg-border/50 hover:bg-bg-tertiary/30 transition-colors">
              <td className="px-4 py-3 text-text-primary font-medium capitalize">{item.type}</td>
              <td className="px-4 py-3">
                <span className={`text-xs font-medium px-2 py-0.5 rounded ${
                  item.status === 'completed'
                    ? 'bg-green-500/20 text-green-400'
                    : item.status === 'error'
                    ? 'bg-red-500/20 text-red-400'
                    : item.status === 'stopped'
                    ? 'bg-yellow-500/20 text-yellow-400'
                    : 'bg-blue-500/20 text-blue-400'
                }`}>
                  {item.status}
                </span>
              </td>
              <td className="px-4 py-3 text-text-muted text-xs font-mono">
                {new Date(item.started_at).toLocaleString()}
              </td>
              <td className="px-4 py-3 text-text-secondary">
                {formatDuration(item.duration_seconds)}
              </td>
              <td className="px-4 py-3 text-text-secondary">
                {item.files_scanned.toLocaleString()}
              </td>
              <td className="px-4 py-3">
                <span className={item.threats_found > 0 ? 'text-red-400 font-semibold' : 'text-green-400'}>
                  {item.threats_found}
                </span>
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={6} className="px-4 py-8 text-center text-text-muted">
                No scan history yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function Scanner() {
  const [customPath, setCustomPath] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const startMutation = useStartScan()
  const { data: historyData, isError: historyError, isLoading: historyLoading } = useScanHistory()

  const history: ScanHistoryItem[] = historyData ?? (historyError ? MOCK_HISTORY : [])

  function startScan(type: ScanType) {
    const paths = type === 'custom' && customPath ? customPath.split('\n').filter(Boolean) : undefined
    startMutation.mutate(
      { type, paths },
      {
        onSuccess: () => toast.success(`${type.charAt(0).toUpperCase() + type.slice(1)} scan started`),
        onError: () => toast.error('Failed to start scan'),
      }
    )
  }

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-text-primary">Scanner</h1>

      {/* Scan controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Quick Scan */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-5">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
                <circle cx="11" cy="11" r="8" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35" />
              </svg>
            </div>
            <div>
              <h3 className="font-semibold text-text-primary">Quick Scan</h3>
              <p className="text-xs text-text-muted">Common threat locations (~5 min)</p>
            </div>
          </div>
          <button
            onClick={() => startScan('quick')}
            disabled={startMutation.isPending}
            className="w-full py-2 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded-lg text-sm font-medium hover:bg-blue-500/30 transition-colors disabled:opacity-50"
          >
            {startMutation.isPending ? 'Starting...' : 'Start Quick Scan'}
          </button>
        </div>

        {/* Full Scan */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-5">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center text-green-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
              </svg>
            </div>
            <div>
              <h3 className="font-semibold text-text-primary">Full Scan</h3>
              <p className="text-xs text-text-muted">All drives and locations (~2h)</p>
            </div>
          </div>
          <button
            onClick={() => startScan('full')}
            disabled={startMutation.isPending}
            className="w-full py-2 bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg text-sm font-medium hover:bg-green-500/30 transition-colors disabled:opacity-50"
          >
            {startMutation.isPending ? 'Starting...' : 'Start Full Scan'}
          </button>
        </div>

        {/* Custom Scan */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-5">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center text-purple-400">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
            </div>
            <div>
              <h3 className="font-semibold text-text-primary">Custom Scan</h3>
              <p className="text-xs text-text-muted">Select specific paths</p>
            </div>
          </div>
          <textarea
            value={customPath}
            onChange={(e) => setCustomPath(e.target.value)}
            placeholder={"C:\\Users\\user\\Downloads\nC:\\Temp"}
            rows={2}
            className="w-full bg-bg-tertiary border border-bg-border rounded-lg px-3 py-2 text-xs font-mono text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-blue mb-2 resize-none"
          />
          <div className="flex gap-2">
            <button
              onClick={() => fileInputRef.current?.click()}
              className="px-3 py-2 bg-bg-tertiary border border-bg-border text-text-secondary text-xs rounded-lg hover:text-text-primary transition-colors"
            >
              Browse
            </button>
            <button
              onClick={() => startScan('custom')}
              disabled={startMutation.isPending || !customPath.trim()}
              className="flex-1 py-2 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-lg text-sm font-medium hover:bg-purple-500/30 transition-colors disabled:opacity-50"
            >
              {startMutation.isPending ? 'Starting...' : 'Start Custom Scan'}
            </button>
          </div>
          <input ref={fileInputRef} type="file" className="hidden" onChange={(e) => {
            // Just show the filename as path for demo
            const f = e.target.files?.[0]
            if (f) setCustomPath((p) => p ? `${p}\n${f.name}` : f.name)
          }} />
        </div>
      </div>

      {/* Active scan progress */}
      <ScanProgressCard />

      {/* Scan history */}
      <div className="bg-bg-card border border-bg-border rounded-xl">
        <div className="px-5 py-4 border-b border-bg-border">
          <h2 className="text-sm font-semibold text-text-primary">Scan History</h2>
        </div>
        {historyLoading && !history.length ? (
          <div className="py-10 flex justify-center">
            <div className="h-6 w-6 rounded-full border-2 border-bg-border border-t-accent-green animate-spin" />
          </div>
        ) : (
          <ScanHistoryTable items={history} />
        )}
      </div>
    </div>
  )
}
