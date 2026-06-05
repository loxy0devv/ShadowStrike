import { useState } from 'react'
import {
  useProcessTree,
  useNetworkConnections,
  useFileEvents,
  useRegistryEvents,
} from '../hooks/useApi'
import { PageLoader } from '../components/LoadingSpinner'
import type { ProcessNode, NetworkConnection, FileEvent, RegistryEvent } from '../types'

// ─── Mock data ────────────────────────────────────────────────────────────────
const MOCK_PROCESSES: ProcessNode[] = [
  {
    pid: 4, ppid: 0, name: 'System', path: '', command_line: 'System',
    user: 'SYSTEM', integrity: 'system', evidence_score: 0,
    started_at: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
    children: [
      {
        pid: 680, ppid: 4, name: 'smss.exe', path: 'C:\\Windows\\System32\\smss.exe', command_line: 'smss.exe',
        user: 'SYSTEM', integrity: 'system', evidence_score: 0,
        started_at: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
      },
    ],
  },
  {
    pid: 1040, ppid: 0, name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe', command_line: 'C:\\Windows\\Explorer.EXE',
    user: 'user', integrity: 'medium', evidence_score: 12,
    started_at: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString(),
    children: [
      {
        pid: 4892, ppid: 1040, name: 'powershell.exe', path: 'C:\\Windows\\System32\\powershell.exe',
        command_line: 'powershell.exe -EncodedCommand JABjAA...',
        user: 'user', integrity: 'high', evidence_score: 85,
        started_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
        suspicious: true,
      },
      {
        pid: 3401, ppid: 1040, name: 'mimi.exe', path: 'C:\\Users\\user\\Desktop\\mimi.exe',
        command_line: 'mimi.exe privilege::debug sekurlsa::logonpasswords',
        user: 'user', integrity: 'high', evidence_score: 99,
        started_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
        suspicious: true,
      },
    ],
  },
]

const MOCK_NETWORK: NetworkConnection[] = [
  { pid: 4892, process: 'powershell.exe', protocol: 'tcp', local_address: '192.168.1.100', local_port: 49215, remote_address: '185.234.218.12', remote_port: 443, state: 'established' },
  { pid: 1040, process: 'explorer.exe', protocol: 'tcp', local_address: '192.168.1.100', local_port: 49201, remote_address: '13.107.42.14', remote_port: 443, state: 'established' },
  { pid: 4, process: 'System', protocol: 'tcp', local_address: '0.0.0.0', local_port: 445, remote_address: '0.0.0.0', remote_port: 0, state: 'listening' },
]

const now = Date.now()
const MOCK_FILES: FileEvent[] = [
  { id: 'f1', timestamp: new Date(now - 1000).toISOString(), operation: 'write', path: 'C:\\Users\\user\\Documents\\doc.enc', pid: 4892, process: 'powershell.exe', size_bytes: 24500 },
  { id: 'f2', timestamp: new Date(now - 5000).toISOString(), operation: 'create', path: 'C:\\Temp\\tmp_3f21.exe', pid: 4892, process: 'powershell.exe', size_bytes: 3500000 },
  { id: 'f3', timestamp: new Date(now - 12000).toISOString(), operation: 'read', path: 'C:\\Windows\\System32\\lsass.exe', pid: 3401, process: 'mimi.exe' },
  { id: 'f4', timestamp: new Date(now - 30000).toISOString(), operation: 'delete', path: 'C:\\Users\\user\\shadow_copy.vssadmin', pid: 4892, process: 'powershell.exe' },
]

const MOCK_REGISTRY: RegistryEvent[] = [
  { id: 'r1', timestamp: new Date(now - 2000).toISOString(), operation: 'set', key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', value_name: 'ShadowTask', data: 'C:\\Temp\\tmp_3f21.exe', pid: 4892, process: 'powershell.exe' },
  { id: 'r2', timestamp: new Date(now - 15000).toISOString(), operation: 'create', key: 'HKLM\\Software\\Classes\\ms-settings\\shell\\open\\command', pid: 3401, process: 'mimi.exe' },
]

// ─── Process tree node ────────────────────────────────────────────────────────
function ProcessTreeNode({ node, depth = 0 }: { node: ProcessNode; depth?: number }) {
  const [expanded, setExpanded] = useState(depth < 2)
  const hasChildren = (node.children?.length ?? 0) > 0

  const scoreColor =
    node.evidence_score >= 80 ? 'text-red-400' :
    node.evidence_score >= 50 ? 'text-orange-400' :
    node.evidence_score >= 20 ? 'text-yellow-400' :
    'text-text-muted'

  return (
    <div>
      <div
        className={`flex items-center gap-2 py-1.5 px-3 rounded-lg hover:bg-bg-tertiary/50 cursor-pointer group ${
          node.suspicious ? 'bg-red-500/5 border-l-2 border-red-500/50' : ''
        }`}
        style={{ paddingLeft: `${depth * 20 + 12}px` }}
        onClick={() => hasChildren && setExpanded((e) => !e)}
      >
        <span className="flex-shrink-0 w-4">
          {hasChildren ? (
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              className={`w-3 h-3 text-text-muted transition-transform ${expanded ? 'rotate-90' : ''}`}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
            </svg>
          ) : null}
        </span>

        <span className="font-mono text-xs font-medium text-text-primary">{node.name}</span>
        <span className="text-xs text-text-muted">PID {node.pid}</span>
        {node.suspicious && (
          <span className="text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded ml-1">suspicious</span>
        )}
        {node.evidence_score > 0 && (
          <span className={`ml-auto text-xs font-mono ${scoreColor}`}>
            score: {node.evidence_score}
          </span>
        )}
        {node.user && (
          <span className="text-xs text-text-muted">{node.user}</span>
        )}
      </div>

      {expanded && node.children?.map((child) => (
        <ProcessTreeNode key={child.pid} node={child} depth={depth + 1} />
      ))}
    </div>
  )
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────
const TABS = ['Process Tree', 'Network', 'File Events', 'Registry'] as const
type Tab = typeof TABS[number]

// ─── Main page ────────────────────────────────────────────────────────────────
export default function Telemetry() {
  const [activeTab, setActiveTab] = useState<Tab>('Process Tree')

  const { data: processes, isLoading: procLoading, isError: procError } = useProcessTree()
  const { data: network, isLoading: netLoading, isError: netError } = useNetworkConnections()
  const { data: files, isLoading: filesLoading, isError: filesError } = useFileEvents()
  const { data: registry, isLoading: regLoading, isError: regError } = useRegistryEvents()

  const procData: ProcessNode[] = processes ?? (procError ? MOCK_PROCESSES : [])
  const netData: NetworkConnection[] = network ?? (netError ? MOCK_NETWORK : [])
  const filesData: FileEvent[] = files ?? (filesError ? MOCK_FILES : [])
  const regData: RegistryEvent[] = registry ?? (regError ? MOCK_REGISTRY : [])

  const STATE_COLORS: Record<NetworkConnection['state'], string> = {
    established: 'text-green-400',
    listening: 'text-blue-400',
    time_wait: 'text-yellow-400',
    close_wait: 'text-yellow-400',
    syn_sent: 'text-orange-400',
    syn_recv: 'text-orange-400',
  }

  const OP_COLORS: Record<FileEvent['operation'], string> = {
    create: 'text-green-400',
    write: 'text-yellow-400',
    read: 'text-blue-400',
    delete: 'text-red-400',
    rename: 'text-purple-400',
    move: 'text-purple-400',
  }

  const REG_OP_COLORS: Record<RegistryEvent['operation'], string> = {
    create: 'text-green-400',
    set: 'text-yellow-400',
    delete: 'text-red-400',
    query: 'text-blue-400',
    rename: 'text-purple-400',
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-text-primary">Telemetry</h1>
        <div className="flex items-center gap-2 text-xs text-text-muted">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-50" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-400" />
          </span>
          Live — polling every 5s
        </div>
      </div>

      {(procError || netError || filesError || regError) && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 px-4 py-2 rounded-lg text-sm">
          Showing demo data — API unreachable.
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 bg-bg-card border border-bg-border rounded-xl p-1">
        {TABS.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`flex-1 py-2 px-3 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab
                ? 'bg-bg-tertiary text-text-primary'
                : 'text-text-muted hover:text-text-secondary'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Process Tree */}
      {activeTab === 'Process Tree' && (
        <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-bg-border flex items-center justify-between">
            <h2 className="text-sm font-semibold text-text-primary">Live Process Tree</h2>
            <span className="text-xs text-text-muted">{procData.length} root processes</span>
          </div>
          {procLoading && !procData.length ? (
            <PageLoader />
          ) : (
            <div className="p-2 max-h-[600px] overflow-y-auto">
              {procData.map((node) => (
                <ProcessTreeNode key={node.pid} node={node} />
              ))}
              {procData.length === 0 && (
                <p className="text-center text-text-muted py-8 text-sm">No process data available</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* Network */}
      {activeTab === 'Network' && (
        <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-bg-border">
            <h2 className="text-sm font-semibold text-text-primary">Network Connections</h2>
          </div>
          {netLoading && !netData.length ? (
            <PageLoader />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-bg-tertiary border-b border-bg-border">
                    {['PID', 'Process', 'Protocol', 'Local', 'Remote', 'State'].map((h) => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {netData.map((conn, i) => (
                    <tr key={i} className="border-t border-bg-border/50 hover:bg-bg-tertiary/30">
                      <td className="px-4 py-2.5 font-mono text-xs text-text-muted">{conn.pid}</td>
                      <td className="px-4 py-2.5 font-mono text-xs text-text-primary">{conn.process}</td>
                      <td className="px-4 py-2.5 text-xs text-text-muted uppercase">{conn.protocol}</td>
                      <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">
                        {conn.local_address}:{conn.local_port}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">
                        {conn.remote_address === '0.0.0.0' ? '—' : `${conn.remote_address}:${conn.remote_port}`}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`text-xs font-medium capitalize ${STATE_COLORS[conn.state]}`}>
                          {conn.state.replace('_', ' ')}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {netData.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-text-muted">No connections</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* File Events */}
      {activeTab === 'File Events' && (
        <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-bg-border">
            <h2 className="text-sm font-semibold text-text-primary">File Events (last 100)</h2>
          </div>
          {filesLoading && !filesData.length ? (
            <PageLoader />
          ) : (
            <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0">
                  <tr className="bg-bg-tertiary border-b border-bg-border">
                    {['Timestamp', 'Operation', 'Path', 'PID', 'Process', 'Size'].map((h) => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filesData.map((ev) => (
                    <tr key={ev.id} className="border-t border-bg-border/50 hover:bg-bg-tertiary/30">
                      <td className="px-4 py-2 font-mono text-xs text-text-muted whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-4 py-2">
                        <span className={`text-xs font-medium uppercase ${OP_COLORS[ev.operation]}`}>
                          {ev.operation}
                        </span>
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-text-primary max-w-[300px] truncate">
                        {ev.path}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-text-muted">{ev.pid}</td>
                      <td className="px-4 py-2 font-mono text-xs text-text-secondary">{ev.process}</td>
                      <td className="px-4 py-2 text-xs text-text-muted">
                        {ev.size_bytes ? `${(ev.size_bytes / 1024).toFixed(1)} KB` : '—'}
                      </td>
                    </tr>
                  ))}
                  {filesData.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-text-muted">No file events</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Registry Events */}
      {activeTab === 'Registry' && (
        <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-bg-border">
            <h2 className="text-sm font-semibold text-text-primary">Registry Events</h2>
          </div>
          {regLoading && !regData.length ? (
            <PageLoader />
          ) : (
            <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0">
                  <tr className="bg-bg-tertiary border-b border-bg-border">
                    {['Timestamp', 'Operation', 'Registry Key', 'Value', 'Data', 'Process'].map((h) => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {regData.map((ev) => (
                    <tr key={ev.id} className="border-t border-bg-border/50 hover:bg-bg-tertiary/30">
                      <td className="px-4 py-2 font-mono text-xs text-text-muted whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-4 py-2">
                        <span className={`text-xs font-medium uppercase ${REG_OP_COLORS[ev.operation]}`}>
                          {ev.operation}
                        </span>
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-text-primary max-w-[250px] truncate">
                        {ev.key}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-text-muted">
                        {ev.value_name || '—'}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-text-secondary max-w-[200px] truncate">
                        {ev.data || '—'}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-text-secondary">
                        {ev.process} ({ev.pid})
                      </td>
                    </tr>
                  ))}
                  {regData.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-text-muted">No registry events</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
