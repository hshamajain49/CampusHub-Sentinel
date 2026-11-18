import path from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Development: the dashboard runs on :5180 and proxies the API, so the session cookie stays same-origin (exactly as in
// production, where the API serves this build). Set the backend's APP_ORIGIN=http://localhost:5180 for local work.
const api = 'http://localhost:4100';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: [{ find: /^@\//, replacement: `${path.resolve(__dirname, 'src')}/` }] },
  server: {
    port: 5180,
    strictPort: true,
    proxy: { '/api': { target: api, changeOrigin: false }, '/health': api },
  },
  build: { target: 'es2022', sourcemap: false, chunkSizeWarningLimit: 900 },
  test: { environment: 'jsdom', setupFiles: ['./src/test-setup.ts'], css: false },
} as any);
