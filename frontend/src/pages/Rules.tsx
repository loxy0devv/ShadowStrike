import { useState, useRef } from 'react'
import toast from 'react-hot-toast'
import { useRules, useSetRuleEnabled, useImportRule } from '../hooks/useApi'
import { SeverityBadge } from '../components/SeverityBadge'
import { PageLoader } from '../components/LoadingSpinner'
import type { Rule, RuleScope, RuleSource, Severity } from '../types'

// ─── Mock data ────────────────────────────────────────────────────────────────
const MOCK_RULES: Rule[] = [
  { id: 'r1', name: 'Ransomware File Encryption Behavior', scope: 'behavior', severity: 'critical', enabled: true, source: 'native', matches_24h: 2 },
  { id: 'r2', name: 'LSASS Memory Read (Mimikatz)', scope: 'process', severity: 'critical', enabled: true, source: 'sigma', matches_24h: 1 },
  { id: 'r3', name: 'Suspicious PowerShell Encoding', scope: 'process', severity: 'high', enabled: true, source: 'sigma', matches_24h: 5 },
  { id: 'r4', name: 'XMRig Miner Detection', scope: 'file', severity: 'high', enabled: true, source: 'yara', matches_24h: 1 },
  { id: 'r5', name: 'Known C2 Domains', scope: 'network', severity: 'high', enabled: true, source: 'native', matches_24h: 3 },
  { id: 'r6', name: 'Registry Run Key Modification', scope: 'registry', severity: 'medium', enabled: true, source: 'sigma', matches_24h: 0 },
  { id: 'r7', name: 'Process Hollowing Detection', scope: 'memory', severity: 'high', enabled: true, source: 'capa', matches_24h: 0 },
  { id: 'r8', name: 'Suspicious MSHTA Execution', scope: 'process', severity: 'high', enabled: true, source: 'sigma', matches_24h: 0 },
  { id: 'r9', name: 'PUA Adware BrowseFox', scope: 'file', severity: 'medium', enabled: true, source: 'yara', matches_24h: 0 },
  { id: 'r10', name: 'CVE-2024-1234 Exploit Pattern', scope: 'memory', severity: 'critical', enabled: false, source: 'elastic', matches_24h: 0 },
  { id: 'r11', name: 'Keylogger API Calls', scope: 'behavior', severity: 'high', enabled: true, source: 'capa', matches_24h: 0 },
  { id: 'r12', name: 'DNS Exfiltration Pattern', scope: 'network', severity: 'medium', enabled: true, source: 'sigma', matches_24h: 0 },
]

const SCOPES: Array<{ value: string; label: string }> = [
  { value: '', label: 'All Scopes' },
  { value: 'file', label: 'File' },
  { value: 'process', label: 'Process' },
  { value: 'network', label: 'Network' },
  { value: 'registry', label: 'Registry' },
  { value: 'behavior', label: 'Behavior' },
  { value: 'memory', label: 'Memory' },
]

const SOURCES: Array<{ value: string; label: string }> = [
  { value: '', label: 'All Sources' },
  { value: 'native', label: 'Native' },
  { value: 'sigma', label: 'Sigma' },
  { value: 'capa', label: 'CAPA' },
  { value: 'elastic', label: 'Elastic' },
  { value: 'yara', label: 'YARA' },
  { value: 'custom', label: 'Custom' },
]

const SOURCE_COLORS: Record<RuleSource, string> = {
  native: 'bg-green-500/20 text-green-400',
  sigma: 'bg-blue-500/20 text-blue-400',
  capa: 'bg-purple-500/20 text-purple-400',
  elastic: 'bg-yellow-500/20 text-yellow-400',
  yara: 'bg-orange-500/20 text-orange-400',
  custom: 'bg-cyan-500/20 text-cyan-400',
}

const SCOPE_COLORS: Record<RuleScope, string> = {
  file: 'text-blue-300',
  process: 'text-green-300',
  network: 'text-orange-300',
  registry: 'text-yellow-300',
  behavior: 'text-red-300',
  memory: 'text-purple-300',
}

// ─── Toggle component ─────────────────────────────────────────────────────────
function Toggle({
  enabled,
  onChange,
  disabled,
}: {
  enabled: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
}) {
  return (
    <button
      onClick={() => !disabled && onChange(!enabled)}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${
        enabled ? 'bg-accent-green' : 'bg-bg-tertiary border border-bg-border'
      } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
      role="switch"
      aria-checked={enabled}
    >
      <span
        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
          enabled ? 'translate-x-[18px]' : 'translate-x-[3px]'
        }`}
      />
    </button>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function Rules() {
  const [scopeFilter, setScopeFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [search, setSearch] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const { data, isLoading, isError, refetch } = useRules({
    scope: scopeFilter || undefined,
    source: sourceFilter || undefined,
  })
  const setEnabledMutation = useSetRuleEnabled()
  const importMutation = useImportRule()

  const allRules: Rule[] = data?.rules ?? (isError ? MOCK_RULES : [])

  const rules = allRules.filter((r) => {
    if (search && !r.name.toLowerCase().includes(search.toLowerCase()) && !r.id.includes(search)) return false
    if (scopeFilter && r.scope !== scopeFilter) return false
    if (sourceFilter && r.source !== sourceFilter) return false
    return true
  })

  const enabledCount = data?.enabled_count ?? allRules.filter((r) => r.enabled).length
  const total = data?.total ?? allRules.length

  function handleToggle(rule: Rule) {
    setEnabledMutation.mutate(
      { id: rule.id, enabled: !rule.enabled },
      {
        onSuccess: () => toast.success(`Rule ${rule.enabled ? 'disabled' : 'enabled'}: ${rule.name}`),
        onError: () => toast.error('Failed to update rule'),
      }
    )
  }

  function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    importMutation.mutate(file, {
      onSuccess: () => {
        toast.success(`Imported rule: ${file.name}`)
        refetch()
      },
      onError: () => toast.error('Failed to import rule'),
    })
    e.target.value = ''
  }

  if (isLoading && !allRules.length) return <PageLoader />

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Detection Rules</h1>
          <p className="text-sm text-text-muted mt-0.5">
            {enabledCount} / {total} rules enabled
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={importMutation.isPending}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-accent-green/20 border border-accent-green/30 text-accent-green text-sm hover:bg-accent-green/30 transition-colors disabled:opacity-50"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            {importMutation.isPending ? 'Importing...' : 'Import Rule'}
          </button>
          <input ref={fileInputRef} type="file" accept=".json,.yaml,.yml" className="hidden" onChange={handleImport} />
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
          Showing demo data — API unreachable.
        </div>
      )}

      {/* Filters */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-4 flex flex-wrap gap-3">
        <input
          type="text"
          placeholder="Search rules..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 min-w-[200px] bg-bg-tertiary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-blue"
        />
        <select
          value={scopeFilter}
          onChange={(e) => setScopeFilter(e.target.value)}
          className="bg-bg-tertiary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-blue"
        >
          {SCOPES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        <select
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
          className="bg-bg-tertiary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-blue"
        >
          {SOURCES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        {(search || scopeFilter || sourceFilter) && (
          <button
            onClick={() => { setSearch(''); setScopeFilter(''); setSourceFilter('') }}
            className="px-3 py-2 text-text-muted hover:text-text-primary text-sm transition-colors"
          >
            Clear
          </button>
        )}
      </div>

      {/* Rules table */}
      <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-bg-tertiary border-b border-bg-border">
                {['Rule Name', 'Scope', 'Severity', 'Source', 'Matches (24h)', 'Enabled'].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id} className="border-t border-bg-border/50 hover:bg-bg-tertiary/30 transition-colors">
                  <td className="px-4 py-3">
                    <div>
                      <p className="font-medium text-text-primary">{rule.name}</p>
                      {rule.description && (
                        <p className="text-xs text-text-muted mt-0.5">{rule.description}</p>
                      )}
                      <p className="text-xs text-text-muted font-mono mt-0.5">{rule.id}</p>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-medium capitalize ${SCOPE_COLORS[rule.scope]}`}>
                      {rule.scope}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={rule.severity as Severity} size="sm" />
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded uppercase ${SOURCE_COLORS[rule.source]}`}>
                      {rule.source}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {rule.matches_24h !== undefined && (
                      <span className={`text-sm font-medium ${rule.matches_24h > 0 ? 'text-red-400' : 'text-text-muted'}`}>
                        {rule.matches_24h}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <Toggle
                      enabled={rule.enabled}
                      onChange={() => handleToggle(rule)}
                      disabled={setEnabledMutation.isPending}
                    />
                  </td>
                </tr>
              ))}
              {rules.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-text-muted">
                    No rules match the current filters
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
