import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.d.ts', 'src/test/**', 'src/main.tsx'],
      // Baseline floors. Each refactor PR raises these; never lower.
      // Phase 3 (CanaryTokens split): page shell down from 1,334 to 210
      // LOC; hook + 3 modals + 3 list views + ui/types/helpers, 33 new
      // tests. Suite: 28 files, 131 tests, 14.51% lines / 11.43% branches.
      thresholds: {
        lines: 14,
        functions: 13,
        branches: 11,
        statements: 13,
      },
    },
  },
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
