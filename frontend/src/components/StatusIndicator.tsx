interface Props {
  status: 'running' | 'paused' | 'error' | 'disabled' | 'connected' | 'disconnected'
  label?: string
  pulse?: boolean
}

const STATUS_CLASSES = {
  running: 'bg-green-400',
  connected: 'bg-green-400',
  paused: 'bg-yellow-400',
  error: 'bg-red-400',
  disabled: 'bg-gray-500',
  disconnected: 'bg-red-400',
}

const STATUS_LABELS = {
  running: 'Running',
  connected: 'Connected',
  paused: 'Paused',
  error: 'Error',
  disabled: 'Disabled',
  disconnected: 'Disconnected',
}

export function StatusIndicator({ status, label, pulse = false }: Props) {
  const colorClass = STATUS_CLASSES[status] ?? 'bg-gray-400'
  const displayLabel = label ?? STATUS_LABELS[status] ?? status

  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="relative flex h-2 w-2">
        {pulse && (status === 'running' || status === 'connected') && (
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${colorClass}`} />
        )}
        <span className={`relative inline-flex rounded-full h-2 w-2 ${colorClass}`} />
      </span>
      <span className="text-sm text-slate-300">{displayLabel}</span>
    </span>
  )
}
