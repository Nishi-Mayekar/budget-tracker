import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Manifest and SW are in public/ — served as static files (PWABuilder-compatible)
export default defineConfig({
  plugins: [react()],
})
