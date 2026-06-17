// SPDX-License-Identifier: AGPL-3.0-or-later
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { existsSync } from 'node:fs'

const here = dirname(fileURLToPath(import.meta.url))
// `@pro` resolves to the real Professional registry only for an explicit pro
// build (VITE_DECNET_PRO=1) once the pro frontend is mounted at src/pro-impl/
// (git-ignored; the pro build copies decnet/pro/web there so react/lucide and
// tsc resolve normally). Otherwise the empty community stub, which tree-shakes
// the pro surface out of the bundle.
const proRealEntry = resolve(here, 'src/pro-impl/index.tsx')
const proEntry =
  process.env.VITE_DECNET_PRO === '1' && existsSync(proRealEntry)
    ? proRealEntry
    : resolve(here, 'src/pro/stub.ts')

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@pro': proEntry } },
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
      // Phase 11 (MazeNET/Inspector split): Inspector.tsx (606 LOC)
      // split into per-selection panels. Inspector/index.tsx is now
      // a 175 LOC dispatcher; NodeInspector keeps the 7 form-state
      // useStates that are node-only. 10 new dispatcher tests. Suite:
      // 51 files, 259 tests, 25.68% lines / 21.43% branches.
      thresholds: {
        lines: 25,
        functions: 22,
        branches: 21,
        statements: 24,
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
