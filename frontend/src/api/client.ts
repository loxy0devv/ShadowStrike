import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios'

const BASE_URL: string = import.meta.env.VITE_API_URL ?? 'https://localhost:9443'

export const apiClient = axios.create({
  baseURL: BASE_URL,
  withCredentials: true,
  timeout: 10_000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Token storage — in real production this comes from /auth/login response
let authToken = localStorage.getItem('shadowstrike_token') ?? 'dev-token'
let csrfToken = localStorage.getItem('shadowstrike_csrf') ?? ''

export function setAuthToken(token: string, csrf: string) {
  authToken = token
  csrfToken = csrf
  localStorage.setItem('shadowstrike_token', token)
  localStorage.setItem('shadowstrike_csrf', csrf)
}

export function clearAuthToken() {
  authToken = ''
  csrfToken = ''
  localStorage.removeItem('shadowstrike_token')
  localStorage.removeItem('shadowstrike_csrf')
}

// Request interceptor: inject Authorization + CSRF
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (authToken) {
    config.headers['Authorization'] = `Bearer ${authToken}`
  }
  const method = config.method?.toUpperCase()
  if (csrfToken && method && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    config.headers['X-CSRF-Token'] = csrfToken
  }
  return config
})

// Response interceptor: normalise errors
apiClient.interceptors.response.use(
  (res) => res,
  (err: AxiosError) => {
    return Promise.reject(err)
  }
)

export default apiClient
