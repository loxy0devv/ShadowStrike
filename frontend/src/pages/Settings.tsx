import { useState } from 'react'
import toast from 'react-hot-toast'
import {
  useSettings,
  useUpdateSettings,
  useExclusions,
  useAddExclusion,
  useRemoveExclusion,
  useWebcam,
  useSetWebcamPolicy,
  useAddWebcamTrusted,
  useRemoveWebcamTrusted,
} from '../hooks/useApi'
import { ConfirmModal } from '../components/ConfirmModal'
import { PageLoader } from '../components/LoadingSpinner'
import type { Exclusion, WebcamPolicy, GeneralSettings } from '../types'

// ─── Toggle ───────────────────────────────────────────────────────────────────
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
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${
        enabled ? 'bg-accent-green' : 'bg-bg-tertiary border border-bg-border'
      } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
      role="switch"
      aria-checked={enabled}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
          enabled ? 'translate-x-[22px]' : 'translate-x-[4px]'
        }`}
      />
    </button>
  )
}

// ─── Settings row ─────────────────────────────────────────────────────────────
function SettingRow({
  label,
  description,
  children,
}: {
  label: string
  description?: string
  children: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between py-4 border-b border-bg-border last:border-0">
      <div className="flex-1 mr-4">
        <p className="text-sm font-medium text-text-primary">{label}</p>
        {description && <p className="text-xs text-text-muted mt-0.5">{description}</p>}
      </div>
      {children}
    </div>
  )
}

// ─── Mock defaults ────────────────────────────────────────────────────────────
const DEFAULT_SETTINGS: GeneralSettings = {
  realtime_protection: true,
  ml_model_enabled: true,
  auto_update: true,
  behavior_monitoring: true,
  network_monitoring: true,
  cloud_lookup: true,
  game_mode: false,
}

const MOCK_EXCLUSIONS: Exclusion[] = [
  { id: 'e1', type: 'path', pattern: 'C:\\DevTools\\', description: 'Development tools', enabled: true, created_at: new Date().toISOString() },
  { id: 'e2', type: 'process', pattern: 'vmware.exe', description: 'VMware Workstation', enabled: true, created_at: new Date().toISOString() },
  { id: 'e3', type: 'extension', pattern: '.test', description: 'Test files', enabled: true, created_at: new Date().toISOString() },
]

// ─── Tab: General ─────────────────────────────────────────────────────────────
function GeneralTab() {
  const { data, isError } = useSettings()
  const updateMutation = useUpdateSettings()
  const settings: GeneralSettings = data ?? (isError ? DEFAULT_SETTINGS : DEFAULT_SETTINGS)

  function toggle(key: keyof GeneralSettings) {
    updateMutation.mutate(
      { [key]: !settings[key] },
      {
        onSuccess: () => toast.success('Setting updated'),
        onError: () => toast.error('Failed to update setting'),
      }
    )
  }

  const settingItems: Array<{ key: keyof GeneralSettings; label: string; description: string }> = [
    { key: 'realtime_protection', label: 'Real-time Protection', description: 'Monitor files and processes as they are accessed' },
    { key: 'ml_model_enabled', label: 'ML Threat Classifier', description: 'Use machine learning model for unknown threat detection' },
    { key: 'auto_update', label: 'Auto-Update Definitions', description: 'Automatically download and apply threat definition updates' },
    { key: 'behavior_monitoring', label: 'Behavior Monitoring', description: 'Monitor process behavior for suspicious activity patterns' },
    { key: 'network_monitoring', label: 'Network Guard', description: 'Monitor network connections for suspicious outbound traffic' },
    { key: 'cloud_lookup', label: 'Cloud Threat Lookup', description: 'Query threat intelligence cloud for unknown files' },
    { key: 'game_mode', label: 'Game Mode', description: 'Reduce performance impact during gaming sessions' },
  ]

  return (
    <div>
      {settingItems.map(({ key, label, description }) => (
        <SettingRow key={key} label={label} description={description}>
          <Toggle
            enabled={settings[key]}
            onChange={() => toggle(key)}
            disabled={updateMutation.isPending}
          />
        </SettingRow>
      ))}
    </div>
  )
}

// ─── Tab: Exclusions ──────────────────────────────────────────────────────────
function ExclusionsTab() {
  const { data, isError } = useExclusions()
  const addMutation = useAddExclusion()
  const removeMutation = useRemoveExclusion()

  const [form, setForm] = useState({ type: 'path' as Exclusion['type'], pattern: '', description: '' })
  const [deleteTarget, setDeleteTarget] = useState<Exclusion | null>(null)

  const exclusions: Exclusion[] = data ?? (isError ? MOCK_EXCLUSIONS : [])

  const TYPE_OPTIONS: Array<{ value: Exclusion['type']; label: string }> = [
    { value: 'path', label: 'Path' },
    { value: 'path_prefix', label: 'Path Prefix' },
    { value: 'extension', label: 'Extension' },
    { value: 'process', label: 'Process Name' },
    { value: 'hash', label: 'File Hash' },
  ]

  function handleAdd() {
    if (!form.pattern.trim()) return
    addMutation.mutate(
      { type: form.type, pattern: form.pattern, description: form.description, enabled: true },
      {
        onSuccess: () => {
          toast.success('Exclusion added')
          setForm({ type: 'path', pattern: '', description: '' })
        },
        onError: () => toast.error('Failed to add exclusion'),
      }
    )
  }

  function handleRemove(excl: Exclusion) {
    setDeleteTarget(excl)
  }

  return (
    <div className="space-y-4">
      {/* Add form */}
      <div className="bg-bg-tertiary border border-bg-border rounded-xl p-4">
        <h3 className="text-sm font-semibold text-text-primary mb-3">Add Exclusion</h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <select
            value={form.type}
            onChange={(e) => setForm((f) => ({ ...f, type: e.target.value as Exclusion['type'] }))}
            className="bg-bg-primary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-blue"
          >
            {TYPE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <input
            type="text"
            placeholder="Pattern (e.g. C:\\DevTools\\ or process.exe)"
            value={form.pattern}
            onChange={(e) => setForm((f) => ({ ...f, pattern: e.target.value }))}
            onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
            className="bg-bg-primary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-blue"
          />
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="Description (optional)"
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              className="flex-1 bg-bg-primary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-blue"
            />
            <button
              onClick={handleAdd}
              disabled={addMutation.isPending || !form.pattern.trim()}
              className="px-4 py-2 bg-accent-green/20 text-accent-green border border-accent-green/30 rounded-lg text-sm font-medium hover:bg-accent-green/30 transition-colors disabled:opacity-50"
            >
              Add
            </button>
          </div>
        </div>
      </div>

      {/* List */}
      <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-bg-tertiary border-b border-bg-border">
              {['Type', 'Pattern', 'Description', 'Status', 'Actions'].map((h) => (
                <th key={h} className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {exclusions.map((excl) => (
              <tr key={excl.id} className="border-t border-bg-border/50 hover:bg-bg-tertiary/30">
                <td className="px-4 py-3">
                  <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded capitalize">
                    {excl.type.replace('_', ' ')}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-text-primary">{excl.pattern}</td>
                <td className="px-4 py-3 text-text-muted text-xs">{excl.description || '—'}</td>
                <td className="px-4 py-3">
                  <span className={`text-xs ${excl.enabled ? 'text-green-400' : 'text-text-muted'}`}>
                    {excl.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => handleRemove(excl)}
                    className="text-xs text-red-400 hover:text-red-300 transition-colors"
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
            {exclusions.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-center text-text-muted text-sm">
                  No exclusions configured
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <ConfirmModal
        open={!!deleteTarget}
        title="Remove Exclusion"
        message={`Remove exclusion for "${deleteTarget?.pattern}"? This file or process will be scanned again.`}
        confirmLabel="Remove"
        danger
        onConfirm={() => {
          if (deleteTarget) {
            removeMutation.mutate(deleteTarget.id, {
              onSuccess: () => toast.success('Exclusion removed'),
              onError: () => toast.error('Failed to remove exclusion'),
            })
          }
          setDeleteTarget(null)
        }}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  )
}

// ─── Tab: Webcam ──────────────────────────────────────────────────────────────
function WebcamTab() {
  const { data, isError } = useWebcam()
  const setPolicyMutation = useSetWebcamPolicy()
  const addTrustedMutation = useAddWebcamTrusted()
  const removeTrustedMutation = useRemoveWebcamTrusted()

  const [newProcess, setNewProcess] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)

  const POLICY_OPTIONS: Array<{ value: WebcamPolicy; label: string; desc: string; color: string }> = [
    { value: 'allow', label: 'Allow All', desc: 'Any process can access the webcam', color: 'border-green-500/40 bg-green-500/10' },
    { value: 'ask', label: 'Ask', desc: 'Prompt for approval on each access', color: 'border-yellow-500/40 bg-yellow-500/10' },
    { value: 'block', label: 'Block All', desc: 'Deny all webcam access', color: 'border-red-500/40 bg-red-500/10' },
  ]

  const currentPolicy = data?.policy ?? 'ask'
  const trustedProcesses = data?.trusted_processes ?? []
  const devices = data?.devices ?? []

  return (
    <div className="space-y-6">
      {isError && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 px-4 py-2 rounded-lg text-sm">
          API unreachable — showing defaults.
        </div>
      )}

      {/* Policy selector */}
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">Camera Access Policy</h3>
        <div className="grid grid-cols-3 gap-3">
          {POLICY_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              onClick={() => {
                setPolicyMutation.mutate(opt.value, {
                  onSuccess: () => toast.success(`Webcam policy set to: ${opt.label}`),
                  onError: () => toast.error('Failed to update policy'),
                })
              }}
              className={`p-4 rounded-xl border-2 text-left transition-all ${
                currentPolicy === opt.value
                  ? `${opt.color} border-opacity-100`
                  : 'border-bg-border bg-bg-tertiary border-opacity-50'
              }`}
            >
              <p className="font-semibold text-sm text-text-primary">{opt.label}</p>
              <p className="text-xs text-text-muted mt-1">{opt.desc}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Devices */}
      {devices.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-text-primary mb-3">Detected Cameras</h3>
          <div className="space-y-2">
            {devices.map((dev) => (
              <div key={dev.id} className="flex items-center gap-3 bg-bg-tertiary border border-bg-border rounded-lg px-4 py-2">
                <div className={`w-2 h-2 rounded-full ${dev.busy ? 'bg-red-400 animate-pulse' : 'bg-gray-500'}`} />
                <span className="text-sm text-text-primary">{dev.name}</span>
                <span className="text-xs text-text-muted ml-auto">{dev.busy ? 'In use' : 'Idle'}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Trusted processes */}
      <div>
        <h3 className="text-sm font-semibold text-text-primary mb-3">Trusted Processes</h3>
        <div className="flex gap-2 mb-3">
          <input
            type="text"
            placeholder="Process name (e.g. zoom.exe)"
            value={newProcess}
            onChange={(e) => setNewProcess(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && newProcess.trim()) {
                addTrustedMutation.mutate(
                  { image_name: newProcess.trim() },
                  {
                    onSuccess: () => { toast.success('Process trusted'); setNewProcess('') },
                    onError: () => toast.error('Failed to add trusted process'),
                  }
                )
              }
            }}
            className="flex-1 bg-bg-tertiary border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-blue"
          />
          <button
            onClick={() => {
              if (!newProcess.trim()) return
              addTrustedMutation.mutate(
                { image_name: newProcess.trim() },
                {
                  onSuccess: () => { toast.success('Process trusted'); setNewProcess('') },
                  onError: () => toast.error('Failed to add trusted process'),
                }
              )
            }}
            disabled={addTrustedMutation.isPending || !newProcess.trim()}
            className="px-4 py-2 bg-accent-green/20 text-accent-green border border-accent-green/30 rounded-lg text-sm font-medium hover:bg-accent-green/30 transition-colors disabled:opacity-50"
          >
            Add
          </button>
        </div>

        <div className="space-y-2">
          {trustedProcesses.map((proc) => (
            <div key={proc.id} className="flex items-center gap-3 bg-bg-tertiary border border-bg-border rounded-lg px-4 py-2">
              <span className="text-sm font-mono text-text-primary">{proc.image_name}</span>
              {proc.signer && <span className="text-xs text-text-muted">Signer: {proc.signer}</span>}
              <button
                onClick={() => setDeleteTarget(proc.id)}
                className="ml-auto text-xs text-red-400 hover:text-red-300 transition-colors"
              >
                Remove
              </button>
            </div>
          ))}
          {trustedProcesses.length === 0 && (
            <p className="text-sm text-text-muted px-2">No trusted processes configured</p>
          )}
        </div>
      </div>

      <ConfirmModal
        open={!!deleteTarget}
        title="Remove Trusted Process"
        message="Remove this process from the webcam trusted list?"
        confirmLabel="Remove"
        danger
        onConfirm={() => {
          if (deleteTarget) {
            removeTrustedMutation.mutate(deleteTarget, {
              onSuccess: () => toast.success('Process removed'),
              onError: () => toast.error('Failed to remove process'),
            })
          }
          setDeleteTarget(null)
        }}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
const TABS = ['General', 'Protection', 'Exclusions', 'Webcam', 'Network'] as const
type Tab = typeof TABS[number]

export default function Settings() {
  const [activeTab, setActiveTab] = useState<Tab>('General')
  const { isLoading } = useSettings()

  if (isLoading) return <PageLoader />

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-text-primary">Settings</h1>

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

      {/* Tab content */}
      <div className="bg-bg-card border border-bg-border rounded-xl p-5">
        {activeTab === 'General' && <GeneralTab />}
        {activeTab === 'Protection' && (
          <div>
            <p className="text-sm text-text-secondary mb-4">Protection module-specific settings are configured per-module via the Dashboard.</p>
            <GeneralTab />
          </div>
        )}
        {activeTab === 'Exclusions' && <ExclusionsTab />}
        {activeTab === 'Webcam' && <WebcamTab />}
        {activeTab === 'Network' && (
          <div className="space-y-4">
            <p className="text-sm text-text-secondary">Network monitoring and firewall policy settings.</p>
            <GeneralTab />
          </div>
        )}
      </div>
    </div>
  )
}
