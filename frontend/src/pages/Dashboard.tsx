import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { useDashboard } from '../hooks/useApi'
import { SeverityBadge } from '../components/SeverityBadge'
import { StatusIndicator } from '../components/StatusIndicator'
import { PageLoader, SkeletonCard } from '../components/LoadingSpinner'
import type { Detection, DashboardData } from '../types'

// ─── Mock fallback data ────────────────────────────────────────────────────────
function makeMockDashboard(): DashboardData {
  const now = Date.now()
  return {
    threats_24h: 14,
    active_scans: 1,
    protection_status: 'protected',
    rules_loaded: 2847,
    module_states: [
      { name: 'Real-time Protection', enabled: true, status: 'running' },
      { name: 'YARA Engine', enabled: true, status: 'running' },
      { name: 'ML Classifier', enabled: true, status: 'running' },
      { name: 'Behavior Monitor', enabled: true, status: 'running' },
      { name: 'Network Guard', enabled: false, status: 'disabled' },
    ],
    threat_timeline: Array.from({ length: 24 }, (_, i) => ({
      hour: `${String(23 - i).padStart(2, '0')}:00`,
      count: Math.floor(Math.random() * 5),
    })).reverse(),
    recent_detections: [
      {
        id: '1',
        timestamp: new Date(now - 1000 * 60 * 5).toISOString(),
        threat_name: 'Trojan.GenericKD.71435882',
        severity: 'critical',
        file_path: 'C:\\Users\\user\\Downloads\\setup.exe',
        process: 'explorer.exe',
        action_taken: 'Quarantined',
        rule_matched: 'YARA/trojan_generic',
        status: 'quarantined',
      },
      {
        id: '2',
        timestamp: new Date(now - 1000 * 60 * 22).toISOString(),
        threat_name: 'Ransom.WannaCrypt',
        severity: 'critical',
        file_path: 'C:\\Temp\\wcrypt.exe',
        process: 'cmd.exe',
        action_taken: 'Blocked',
        rule_matched: 'SIG/ransomware_wannacrypt',
        status: 'blocked',
      },
      {
        id: '3',
        timestamp: new Date(now - 1000 * 60 * 45).toISOString(),
        threat_name: 'Miner.XMRig',
        severity: 'high',
        file_path: 'C:\\ProgramData\\svchost32.exe',
        process: 'svchost32.exe',
        action_taken: 'Blocked',
        rule_matched: 'CAPA/cryptominer_xmrig',
        status: 'blocked',
      },
      {
        id: '4',
        timestamp: new Date(now - 1000 * 60 * 90).toISOString(),
        threat_name: 'PUA.Adware.BrowseFox',
        severity: 'medium',
        file_path: 'C:\\Users\\user\\AppData\\browse_fox.dll',
        process: 'iexplore.exe',
        action_taken: 'Quarantined',
        rule_matched: 'SIG/pua_browsefox',
        status: 'quarantined',
      },
      {
        id: '5',
        timestamp: new Date(now - 1000 * 60 * 120).toISOString(),
        threat_name: 'HackTool.Mimikatz',
        severity: 'high',
        file_path: 'C:\\Users\\user\\Desktop\\mimi.exe',
        process: 'mimi.exe',
        action_taken: 'Blocked',
        rule_matched: 'SIGMA/credential_dump_mimikatz',
        status: 'blocked',
      },
    ],
  }
}

// ─── Sub-components ────────────────────────────────────────────────────────────
function StatCard({
  label,
  value,
  sub,
  accent,
}: {
  label: string
  value: string | number
  sub?: string
  accent?: 'green' | 'blue' | 'red' | 'yellow'
}) {
  const accentColor = {
    green: 'text-accent-green',
    blue: 'text-accent-blue',
    red: 'text-red-400',
    yellow: 'text-yellow-400',
  }[accent ?? 'green']

  return (
    <div className="bg-bg-card border border-bg-border rounded-xl p-5">
      <p className="text-xs text-text-muted uppercase tracking-wider mb-1">{label}</p>
      <p className={`text-3xl font-bold ${accentColor} mb-1`}>{value}</p>
      {sub && <p className="text-xs text-text-muted">{sub}</p>}
    </div>
  )
}


function ProtectionBadge({ status }: { status: DashboardData['protection_status'] }) {
  const config = {
    protected: { label: 'Protected', cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
    at_risk: { label: 'At Risk', cls: 'bg-red-500/20 text-red-400 border-red-500/30' },
    paused: { label: 'Paused', cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
    disabled: { label: 'Disabled', cls: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
  }[status]
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-semibold border ${config.cls}`}>
      {config.label}
    </span>
  )
}

function RecentDetectionsTable({ detections }: { detections: Detection[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-bg-border">
            <th className="text-left px-4 py-2 text-xs font-medium text-text-muted uppercase tracking-wider">Time</th>
            <th className="text-left px-4 py-2 text-xs font-medium text-text-muted uppercase tracking-wider">Threat</th>
            <th className="text-left px-4 py-2 text-xs font-medium text-text-muted uppercase tracking-wider">Severity</th>
            <th className="text-left px-4 py-2 text-xs font-medium text-text-muted uppercase tracking-wider">Path</th>
            <th className="text-left px-4 py-2 text-xs font-medium text-text-muted uppercase tracking-wider">Action</th>
          </tr>
        </thead>
        <tbody>
          {detections.map((d) => (
            <tr key={d.id} className="border-t border-bg-border/50 hover:bg-bg-tertiary/40 transition-colors">
              <td className="px-4 py-2.5 font-mono text-xs text-text-muted whitespace-nowrap">
                {new Date(d.timestamp).toLocaleTimeString()}
              </td>
              <td className="px-4 py-2.5 text-text-primary font-medium max-w-[200px] truncate">
                {d.threat_name}
              </td>
              <td className="px-4 py-2.5">
                <SeverityBadge severity={d.severity} size="sm" />
              </td>
              <td className="px-4 py-2.5 font-mono text-xs text-text-muted max-w-[240px] truncate">
                {d.file_path}
              </td>
              <td className="px-4 py-2.5">
                <span className={`text-xs font-medium ${
                  d.action_taken === 'Quarantined' ? 'text-yellow-400' :
                  d.action_taken === 'Blocked' ? 'text-green-400' :
                  'text-text-muted'
                }`}>
                  {d.action_taken}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const customTooltipStyle = {
  backgroundColor: '#1a2035',
  border: '1px solid #2a3550',
  borderRadius: '8px',
  color: '#f1f5f9',
}

// ─── Main component ────────────────────────────────────────────────────────────
export default function Dashboard() {
  const { data, isLoading, isError, refetch } = useDashboard()

  // Use mock data when API is unreachable (dev mode not enabled)
  const dashboard = data ?? (isError ? makeMockDashboard() : null)

  if (isLoading && !dashboard) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => <SkeletonCard key={i} />)}
        </div>
        <PageLoader />
      </div>
    )
  }

  if (!dashboard) return null

  return (
    <div className="space-y-6">
      {isError && (
        <div className="flex items-center gap-3 bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 px-4 py-3 rounded-xl text-sm">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4 flex-shrink-0">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
          </svg>
          <span>Showing demo data — API unreachable. Enable DevMode to connect.</span>
          <button
            onClick={() => refetch()}
            className="ml-auto underline hover:no-underline text-xs"
          >
            Retry
          </button>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Threats (24h)"
          value={dashboard.threats_24h}
          sub="detections in last 24 hours"
          accent={dashboard.threats_24h > 0 ? 'red' : 'green'}
        />
        <StatCard
          label="Active Scans"
          value={dashboard.active_scans}
          sub={dashboard.active_scans > 0 ? 'scan in progress' : 'no scans running'}
          accent="blue"
        />
        <div className="bg-bg-card border border-bg-border rounded-xl p-5">
          <p className="text-xs text-text-muted uppercase tracking-wider mb-1">Protection</p>
          <div className="mt-2">
            <ProtectionBadge status={dashboard.protection_status} />
          </div>
        </div>
        <StatCard
          label="Rules Loaded"
          value={dashboard.rules_loaded.toLocaleString()}
          sub="detection rules active"
          accent="blue"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Threat timeline */}
        <div className="lg:col-span-2 bg-bg-card border border-bg-border rounded-xl p-5">
          <h2 className="text-sm font-semibold text-text-primary mb-4">Threat Timeline (24h)</h2>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={dashboard.threat_timeline} margin={{ top: 5, right: 10, bottom: 5, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a3550" />
              <XAxis
                dataKey="hour"
                tick={{ fill: '#64748b', fontSize: 11 }}
                axisLine={{ stroke: '#2a3550' }}
                tickLine={false}
                interval={3}
              />
              <YAxis
                tick={{ fill: '#64748b', fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={customTooltipStyle}
                labelStyle={{ color: '#94a3b8', fontSize: 12 }}
                itemStyle={{ color: '#4ade80' }}
              />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#4ade80"
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4, fill: '#4ade80' }}
                name="Threats"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Module status */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-5">
          <h2 className="text-sm font-semibold text-text-primary mb-4">Module Status</h2>
          <div className="space-y-3">
            {dashboard.module_states.map((mod) => (
              <div key={mod.name} className="flex items-center justify-between">
                <span className="text-sm text-text-secondary truncate max-w-[160px]">{mod.name}</span>
                <StatusIndicator
                  status={
                    mod.status === 'running' ? 'running' :
                    mod.status === 'paused' ? 'paused' :
                    mod.status === 'error' ? 'error' : 'disabled'
                  }
                  pulse={mod.status === 'running'}
                />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent detections */}
      <div className="bg-bg-card border border-bg-border rounded-xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-bg-border">
          <h2 className="text-sm font-semibold text-text-primary">Recent Detections</h2>
          <a href="/detections" className="text-xs text-accent-blue hover:underline">View all</a>
        </div>
        <RecentDetectionsTable detections={dashboard.recent_detections.slice(0, 10)} />
      </div>
    </div>
  )
}
