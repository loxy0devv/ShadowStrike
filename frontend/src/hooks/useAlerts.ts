import { useQuery, useQueryClient } from '@tanstack/react-query'
import { alertsApi } from '../api/endpoints'
import type { Alert } from '../types'

const POLL_INTERVAL = 5_000

/**
 * Polling hook for live alert feed.
 * Returns alerts list, unread count, and a function to manually refetch.
 */
export function useAlertsFeed() {
  const qc = useQueryClient()

  const query = useQuery({
    queryKey: ['alerts-feed'],
    queryFn: alertsApi.list,
    refetchInterval: POLL_INTERVAL,
    refetchIntervalInBackground: true,
    select: (data) => ({
      alerts: data.alerts as Alert[],
      unread_count: data.unread_count,
      active: data.alerts.filter((a) => !a.dismissed) as Alert[],
    }),
  })

  const refetch = () => qc.invalidateQueries({ queryKey: ['alerts-feed'] })

  return {
    ...query,
    refetch,
    alerts: query.data?.alerts ?? [],
    activeAlerts: query.data?.active ?? [],
    unreadCount: query.data?.unread_count ?? 0,
  }
}
