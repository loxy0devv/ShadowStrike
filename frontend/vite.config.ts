import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'https://localhost:9443',
        changeOrigin: true,
        secure: false,
      },
      '/auth': {
        target: 'https://localhost:9443',
        changeOrigin: true,
        secure: false,
      },
      '/health': {
        target: 'https://localhost:9443',
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
