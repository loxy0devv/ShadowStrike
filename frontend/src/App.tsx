import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'react-hot-toast'
import { Layout } from './components/Layout'
import Dashboard from './pages/Dashboard'
import Detections from './pages/Detections'
import Alerts from './pages/Alerts'
import Scanner from './pages/Scanner'
import Quarantine from './pages/Quarantine'
import Rules from './pages/Rules'
import Settings from './pages/Settings'
import Telemetry from './pages/Telemetry'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      gcTime: 300_000,
      retry: (failureCount, error) => {
        // Don't retry network errors aggressively — the API may be offline
        if (failureCount >= 2) return false
        const axiosError = error as { code?: string }
        if (axiosError?.code === 'ECONNREFUSED' || axiosError?.code === 'ERR_NETWORK') return false
        return true
      },
    },
    mutations: {
      retry: 0,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="detections" element={<Detections />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="scan" element={<Scanner />} />
            <Route path="quarantine" element={<Quarantine />} />
            <Route path="rules" element={<Rules />} />
            <Route path="settings" element={<Settings />} />
            <Route path="telemetry" element={<Telemetry />} />
          </Route>
        </Routes>
      </BrowserRouter>
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: '#1a2035',
            color: '#f1f5f9',
            border: '1px solid #2a3550',
            fontFamily: 'Inter, sans-serif',
            fontSize: '13px',
          },
          success: {
            iconTheme: { primary: '#4ade80', secondary: '#0f1117' },
          },
          error: {
            iconTheme: { primary: '#ef4444', secondary: '#0f1117' },
          },
        }}
      />
    </QueryClientProvider>
  )
}
