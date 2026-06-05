interface Props {
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

const SIZES = {
  sm: 'h-4 w-4 border-2',
  md: 'h-8 w-8 border-2',
  lg: 'h-12 w-12 border-3',
}

export function LoadingSpinner({ size = 'md', className = '' }: Props) {
  return (
    <div
      className={`${SIZES[size]} rounded-full border-bg-border border-t-accent-green animate-spin ${className}`}
      role="status"
      aria-label="Loading"
    />
  )
}

export function PageLoader() {
  return (
    <div className="flex flex-col items-center justify-center flex-1 gap-4 py-20">
      <LoadingSpinner size="lg" />
      <p className="text-text-muted text-sm">Loading data...</p>
    </div>
  )
}

export function SkeletonRow({ cols = 5 }: { cols?: number }) {
  return (
    <tr className="border-t border-bg-border">
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-bg-tertiary rounded animate-pulse" />
        </td>
      ))}
    </tr>
  )
}

export function SkeletonCard() {
  return (
    <div className="bg-bg-card border border-bg-border rounded-xl p-5 animate-pulse">
      <div className="h-3 bg-bg-tertiary rounded w-1/3 mb-3" />
      <div className="h-8 bg-bg-tertiary rounded w-1/2 mb-2" />
      <div className="h-3 bg-bg-tertiary rounded w-2/3" />
    </div>
  )
}
