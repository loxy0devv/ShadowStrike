import { useState, useEffect } from 'react'
import { useDetections } from '../hooks/useApi'
import { SeverityBadge } from '../components/SeverityBadge'
import { SkeletonRow } from '../components/LoadingSpinner'
import type { Detection, Severity, AttackChainStep } from '../types'

const SEVERITIES: Array<{ value: string; label: string }> = [
  { value: '', label: 'All Severity' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
]

// ─── Detail modal ─────────────────────────────────────────────────────────────
function DetectionModal({
  detection,
  onClose,
}: {
  detection: Detection
  onClose: () => void
}) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-10 pb-6 px-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 bg-bg-card border border-bg-border rounded-xl w-full max-w-3xl max-h-[80vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-bg-card border-b border-bg-border px-6 py-4 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-text-primary">{detection.threat_name}</h2>
            <div className="flex items-center gap-2 mt-1">
              <SeverityBadge severity={detection.severity} />
              <span className="text-xs text-text-muted">
                {new Date(detection.timestamp).toLocaleString()}
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-text-muted hover:text-text-primary transition-colors flex-shrink-0 mt-1"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Core details */}
          <div className="grid grid-cols-2 gap-4">
            {[
              { label: 'File Path', value: detection.file_path, mono: true },
              { label: 'Process', value: detection.process, mono: true },
              { label: 'Rule Matched', value: detection.rule_matched, mono: true },
              { label: 'Action Taken', value: detection.action_taken },
              { label: 'Status', value: detection.status },
              { label: 'Detection ID', value: detection.id, mono: true },
            ].map(({ label, value, mono }) => (
              <div key={label} className="bg-bg-tertiary rounded-lg p-3">
                <p className="text-xs text-text-muted mb-1">{label}</p>
                <p className={`text-sm text-text-primary ${mono ? 'font-mono break-all' : 'font-medium'}`}>
                  {value}
                </p>
              </div>
            ))}
          </div>

          {/* Attack chain */}
          {detection.attack_chain && detection.attack_chain.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-text-primary mb-3">Attack Chain</h3>
              <div className="space-y-2">
                {(detection.attack_chain as AttackChainStep[]).map((step) => (
                  <div key={step.step} className="flex gap-3 items-start">
                    <div className="flex-shrink-0 w-6 h-6 rounded-full bg-accent-green/20 text-accent-green text-xs flex items-center justify-center font-bold">
                      {step.step}
                    </div>
                    <div className="flex-1 bg-bg-tertiary rounded-lg p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono text-text-primary">{step.process}</span>
                        <span className="text-xs text-text-muted">PID {step.pid}</span>
                        <span className="text-xs text-text-muted ml-auto">
                          {new Date(step.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-xs text-text-secondary">{step.action}: {step.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Evidence */}
          {detection.evidence && detection.evidence.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-text-primary mb-3">Evidence</h3>
              <ul className="space-y-1">
                {(detection.evidence as string[]).map((ev, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-text-secondary">
                    <span className="text-accent-green mt-0.5">›</span>
                    <span className="font-mono text-xs">{ev}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Raw JSON */}
          {detection.raw && (
            <div>
              <h3 className="text-sm font-semibold text-text-primary mb-3">Raw Detection Data</h3>
              <pre className="bg-bg-primary border border-bg-border rounded-lg p-4 text-xs font-mono text-accent-green overflow-x-auto">
                {JSON.stringify(detection.raw, null, 2)}
              </pre>
            </div>
          )}

          {/* Full object fallback if no raw */}
          {!detection.raw && (
            <div>
              <h3 className="text-sm font-semibold text-text-primary mb-3">Raw Detection Data</h3>
              <pre className="bg-bg-primary border border-bg-border rounded-lg p-4 text-xs font-mono text-accent-green overflow-x-auto">
                {JSON.stringify(detection, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function Detections() {
  const [page, setPage] = useState(1)
  const [severity, setSeverity] = useState('')
  const [q, setQ] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [selected, setSelected] = useState<Detection | null>(null)
  const LIMIT = 50

  const { data, isLoading, isError, refetch } = useDetections({
    page,
    limit: LIMIT,
    severity: severity || undefined,
    q: q || undefined,
    from: from || undefined,
    to: to || undefined,
  })

  // Mock data when API unavailable
  const mockDetections: Detection[] = Array.from({ length: 12 }, (_, i) => ({
    id: `det-${i + 1}`,
    timestamp: new Date(Date.now() - i * 1000 * 60 * 15).toISOString(),
    threat_name: ['Trojan.GenericKD', 'Ransom.WannaCrypt', 'Miner.XMRig', 'HackTool.Mimikatz', 'PUA.Adware.BrowseFox'][i % 5] + `.${1000 + i}`,
    severity: (['critical', 'high', 'medium', 'low', 'critical', 'high', 'medium', 'low', 'critical', 'high', 'medium', 'low'] as Severity[])[i],
    file_path: `C:\\Users\\user\\AppData\\Local\\Temp\\threat_${i}.exe`,
    process: ['explorer.exe', 'cmd.exe', 'powershell.exe', 'mshta.exe'][i % 4],
    pid: 1000 + i * 100,
    action_taken: ['Quarantined', 'Blocked', 'Allowed'][i % 3],
    rule_matched: `YARA/rule_${i + 1}`,
    status: 'quarantined',
  }))

  const detections = data?.detections ?? (isError ? mockDetections : [])
  const total = data?.total ?? (isError ? mockDetections.length : 0)
  const totalPages = Math.ceil(total / LIMIT) || 1

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-text-primary">Detections</h1>
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

      {/* Filters */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-4 flex flex-wrap gap-3">
        <div className="flex gap-2 flex-1 min-w-[200px]">
          <input
            type="text"
            placeholder="Search threats, paths, rules..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') { setQ(searchInput); setPage(1) }
            }}
            className="flex-1 bg-bg-tertiary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-blue"
          />
          <button
            onClick={() => { setQ(searchInput); setPage(1) }}
            className="px-3 py-2 bg-accent-blue/20 text-accent-blue border border-accent-blue/30 rounded-lg text-sm hover:bg-accent-blue/30 transition-colors"
          >
            Search
          </button>
        </div>

        <select
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setPage(1) }}
          className="bg-bg-tertiary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-blue"
        >
          {SEVERITIES.map((s) => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>

        <input
          type="date"
          value={from}
          onChange={(e) => { setFrom(e.target.value); setPage(1) }}
          className="bg-bg-tertiary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-blue"
          title="From date"
        />
        <input
          type="date"
          value={to}
          onChange={(e) => { setTo(e.target.value); setPage(1) }}
          className="bg-bg-tertiary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-blue"
          title="To date"
        />

        {(q || severity || from || to) && (
          <button
            onClick={() => { setQ(''); setSearchInput(''); setSeverity(''); setFrom(''); setTo(''); setPage(1) }}
            className="px-3 py-2 text-text-muted hover:text-text-primary text-sm transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-bg-tertiary border-b border-bg-border">
                {['Time', 'Threat Name', 'Severity', 'File Path', 'Process', 'Action', 'Rule'].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading && !detections.length
                ? Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} cols={7} />)
                : detections.map((d) => (
                  <tr
                    key={d.id}
                    onClick={() => setSelected(d)}
                    className="border-t border-bg-border/50 hover:bg-bg-tertiary/40 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted whitespace-nowrap">
                      {new Date(d.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5 text-text-primary font-medium max-w-[180px] truncate">
                      {d.threat_name}
                    </td>
                    <td className="px-4 py-2.5">
                      <SeverityBadge severity={d.severity} size="sm" />
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted max-w-[200px] truncate">
                      {d.file_path}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
                      {d.process}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`text-xs font-medium ${
                        d.action_taken === 'Quarantined' ? 'text-yellow-400' :
                        d.action_taken === 'Blocked' ? 'text-green-400' :
                        d.action_taken === 'Allowed' ? 'text-blue-400' :
                        'text-text-muted'
                      }`}>
                        {d.action_taken}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted max-w-[160px] truncate">
                      {d.rule_matched}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-bg-border">
            <span className="text-xs text-text-muted">
              Page {page} of {totalPages} · {total} total
            </span>
            <div className="flex gap-2">
              <button
                disabled={page === 1}
                onClick={() => setPage((p) => p - 1)}
                className="px-3 py-1 rounded bg-bg-tertiary border border-bg-border text-sm text-text-secondary hover:text-text-primary disabled:opacity-40 transition-colors"
              >
                Previous
              </button>
              <button
                disabled={page === totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1 rounded bg-bg-tertiary border border-bg-border text-sm text-text-secondary hover:text-text-primary disabled:opacity-40 transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {selected && (
        <DetectionModal detection={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}
