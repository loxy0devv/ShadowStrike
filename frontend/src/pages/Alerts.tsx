import toast from 'react-hot-toast'
import { useAlerts, useDismissAlert } from '../hooks/useApi'
import { SeverityBadge } from '../components/SeverityBadge'
import { PageLoader } from '../components/LoadingSpinner'
import type { Alert, AlertType, Severity } from '../types'

// ─── Mock data ────────────────────────────────────────────────────────────────
const MOCK_ALERTS: Alert[] = [
  {
    id: 'a1',
    type: 'threat',
    title: 'Ransomware Activity Detected',
    message: 'Suspicious file encryption behavior detected in C:\\Users\\user. Process: powershell.exe (PID 4892)',
    severity: 'critical',
    timestamp: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
    dismissed: false,
    source: 'Behavior Monitor',
  },
  {
    id: 'a2',
    type: 'threat',
    title: 'Credential Dumping Attempt',
    message: 'LSASS memory read detected from non-trusted process mimikatz.exe (PID 3401)',
    severity: 'high',
    timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    dismissed: false,
    source: 'SIGMA Rules',
  },
  {
    id: 'a3',
    type: 'network',
    title: 'C2 Communication Blocked',
    message: 'Outbound connection to known C2 server 185.234.218.x:443 blocked for svchost32.exe',
    severity: 'high',
    timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    dismissed: false,
    source: 'Network Guard',
  },
  {
    id: 'a4',
    type: 'scan',
    title: 'Quick Scan Completed',
    message: 'Quick scan completed: 24,891 files scanned, 2 threats found',
    severity: 'medium',
    timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    dismissed: false,
    source: 'Scanner',
  },
  {
    id: 'a5',
    type: 'update',
    title: 'Definitions Updated',
    message: 'Threat definition database updated to version 20260528.001 (2,847 new signatures)',
    severity: 'info',
    timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    dismissed: false,
    source: 'Updater',
  },
  {
    id: 'a6',
    type: 'policy',
    title: 'Webcam Access Request',
    message: 'Process zoom.exe is requesting webcam access. Policy: Ask',
    severity: 'low',
    timestamp: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    dismissed: true,
    source: 'Webcam Guard',
  },
]

// ─── Alert type icons ─────────────────────────────────────────────────────────
function AlertIcon({ type }: { type: AlertType }) {
  switch (type) {
    case 'threat':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        </svg>
      )
    case 'network':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
        </svg>
      )
    case 'scan':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
          <circle cx="11" cy="11" r="8" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35" />
        </svg>
      )
    case 'update':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
        </svg>
      )
    case 'policy':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z" />
        </svg>
      )
    default:
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-5 h-5">
          <circle cx="12" cy="12" r="10" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01" />
        </svg>
      )
  }
}

const ALERT_ICON_COLORS: Record<AlertType, string> = {
  threat: 'text-red-400 bg-red-500/10',
  network: 'text-orange-400 bg-orange-500/10',
  scan: 'text-blue-400 bg-blue-500/10',
  update: 'text-green-400 bg-green-500/10',
  policy: 'text-yellow-400 bg-yellow-500/10',
  system: 'text-purple-400 bg-purple-500/10',
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

// ─── Alert card ───────────────────────────────────────────────────────────────
function AlertCard({ alert, onDismiss }: { alert: Alert; onDismiss: (id: string) => void }) {
  return (
    <div
      className={`bg-bg-card border rounded-xl p-4 flex gap-4 transition-all ${
        alert.dismissed ? 'opacity-40 border-bg-border' : 'border-bg-border hover:border-bg-tertiary'
      }`}
    >
      <div className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${ALERT_ICON_COLORS[alert.type]}`}>
        <AlertIcon type={alert.type} />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-start justify-between gap-2 mb-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-sm text-text-primary">{alert.title}</span>
            <SeverityBadge severity={alert.severity as Severity} size="sm" />
          </div>
          <span className="text-xs text-text-muted whitespace-nowrap flex-shrink-0">
            {timeAgo(alert.timestamp)}
          </span>
        </div>
        <p className="text-sm text-text-secondary mb-2">{alert.message}</p>
        <div className="flex items-center gap-3">
          {alert.source && (
            <span className="text-xs text-text-muted bg-bg-tertiary px-2 py-0.5 rounded">
              {alert.source}
            </span>
          )}
          {!alert.dismissed && (
            <button
              onClick={() => onDismiss(alert.id)}
              className="text-xs text-text-muted hover:text-text-primary transition-colors"
            >
              Dismiss
            </button>
          )}
          {alert.dismissed && (
            <span className="text-xs text-text-muted italic">Dismissed</span>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function Alerts() {
  const { data, isError, isLoading, refetch } = useAlerts()
  const dismissMutation = useDismissAlert()

  const alerts: Alert[] = data?.alerts ?? (isError ? MOCK_ALERTS : [])
  const unreadCount = alerts.filter((a) => !a.dismissed).length

  function handleDismiss(id: string) {
    dismissMutation.mutate(id, {
      onSuccess: () => toast.success('Alert dismissed'),
      onError: () => toast.error('Failed to dismiss alert'),
    })
  }

  function handleDismissAll() {
    const active = alerts.filter((a) => !a.dismissed)
    active.forEach((a) => dismissMutation.mutate(a.id))
    toast.success(`Dismissed ${active.length} alerts`)
  }

  if (isLoading && !alerts.length) return <PageLoader />

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold text-text-primary">Alerts</h1>
          {unreadCount > 0 && (
            <span className="bg-red-500 text-white text-xs font-bold rounded-full min-w-[22px] h-[22px] flex items-center justify-center px-1">
              {unreadCount}
            </span>
          )}
        </div>
        <div className="flex gap-2">
          {unreadCount > 0 && (
            <button
              onClick={handleDismissAll}
              className="px-3 py-1.5 text-sm text-text-muted hover:text-text-primary transition-colors"
            >
              Dismiss all
            </button>
          )}
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
      </div>

      {isError && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 px-4 py-2 rounded-lg text-sm">
          Showing demo data — API unreachable. Polling every 5s when connected.
        </div>
      )}

      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-3">
        {(['critical', 'high', 'medium', 'low'] as Severity[]).map((sev) => {
          const count = alerts.filter((a) => a.severity === sev && !a.dismissed).length
          return (
            <div key={sev} className="bg-bg-card border border-bg-border rounded-xl p-3 text-center">
              <p className="text-2xl font-bold text-text-primary">{count}</p>
              <SeverityBadge severity={sev} size="sm" />
            </div>
          )
        })}
      </div>

      {/* Active alerts */}
      {alerts.filter((a) => !a.dismissed).length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wide">Active</h2>
          {alerts
            .filter((a) => !a.dismissed)
            .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
            .map((alert) => (
              <AlertCard key={alert.id} alert={alert} onDismiss={handleDismiss} />
            ))}
        </div>
      )}

      {/* Dismissed alerts */}
      {alerts.filter((a) => a.dismissed).length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wide">Dismissed</h2>
          {alerts
            .filter((a) => a.dismissed)
            .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
            .map((alert) => (
              <AlertCard key={alert.id} alert={alert} onDismiss={handleDismiss} />
            ))}
        </div>
      )}

      {alerts.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 text-text-muted">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} className="w-12 h-12 mb-3 opacity-40">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
          <p className="text-sm">No alerts</p>
        </div>
      )}
    </div>
  )
}
