import type { Severity } from '../types'

interface Props {
  severity: Severity
  size?: 'sm' | 'md'
}

const CLASSES: Record<Severity, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/40',
  high: 'bg-orange-500/20 text-orange-400 border border-orange-500/40',
  medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40',
  low: 'bg-blue-500/20 text-blue-400 border border-blue-500/40',
  info: 'bg-gray-500/20 text-gray-400 border border-gray-500/40',
}

const DOT_CLASSES: Record<Severity, string> = {
  critical: 'bg-red-400',
  high: 'bg-orange-400',
  medium: 'bg-yellow-400',
  low: 'bg-blue-400',
  info: 'bg-gray-400',
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  const sizeClass = size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2 py-1 text-xs font-semibold'
  return (
    <span className={`inline-flex items-center gap-1 rounded-md uppercase tracking-wide ${sizeClass} ${CLASSES[severity]}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${DOT_CLASSES[severity]}`} />
      {severity}
    </span>
  )
}
