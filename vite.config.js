import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Configure for WASM support
  optimizeDeps: {
    exclude: ['cert-parser-wasm']
  },
})
