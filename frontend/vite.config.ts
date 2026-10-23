
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath } from 'node:url'

const frontendRoot = fileURLToPath(new URL('.', import.meta.url))

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      react: `${frontendRoot}node_modules/react`,
      'react/jsx-runtime': `${frontendRoot}node_modules/react/jsx-runtime`,
      'react/jsx-dev-runtime': `${frontendRoot}node_modules/react/jsx-dev-runtime`,
      'lucide-react': `${frontendRoot}node_modules/lucide-react`,
    },
  },

  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,

    // Allow access from other hostnames,
    // including temporary Cloudflare tunnel URLs.
    allowedHosts: true,

    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})