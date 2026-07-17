import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

function spaBypass(req) {
  // Let the React app handle browser navigations; only proxy API XHR/fetch.
  if (req.headers.accept?.includes('text/html')) {
    return '/index.html'
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 3000,
    proxy: {
      // During development, proxy API calls to avoid CORS
      '/auth': { target: 'http://localhost:8000', changeOrigin: true },
      '/projects': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        bypass: spaBypass,
      },
      '/scans': { target: 'http://localhost:8000', changeOrigin: true },
      '/vulnerabilities': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        bypass: spaBypass,
      },
      '/reports': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        bypass: spaBypass,
      },
      '/ai': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split Monaco editor into its own chunk to keep main bundle small
        manualChunks(id) {
          if (id.includes('@monaco-editor') || id.includes('monaco-editor')) {
            return 'monaco-editor';
          }
          if (id.includes('recharts') || id.includes('d3-')) {
            return 'recharts';
          }
          if (id.includes('node_modules')) {
            return 'vendor';
          }
        },
      },
    },
  },

})
