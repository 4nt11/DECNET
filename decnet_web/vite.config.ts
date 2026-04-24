import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    // Split heavy third-party libs into their own chunks so the main
    // bundle stays small and the rarely-changing vendor code stays
    // cacheable across deploys. Recharts + asciinema-player + lucide
    // together made up most of the weight that was tripping the 500kB
    // warning.
    rollupOptions: {
      output: {
        manualChunks: (id: string) => {
          if (!id.includes('node_modules')) return undefined
          // d3-* ships alongside recharts as its plotting engine —
          // grouping them keeps tree-shaken subsets together.
          if (id.includes('recharts') || id.includes('/d3-')) return 'charts'
          if (id.includes('asciinema-player')) return 'player'
          if (id.includes('lucide-react')) return 'icons'
          if (id.includes('react-router')) return 'router'
          if (id.includes('react-dom')) return 'react-dom'
          if (id.includes('/react/') || id.endsWith('/react')) return 'react'
          return 'vendor'
        },
      },
    },
    // Legitimate ceiling for any single chunk after splitting; anything
    // larger is a real bloat regression worth investigating.
    chunkSizeWarningLimit: 600,
  },
})
