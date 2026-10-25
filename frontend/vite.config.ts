import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The kbsync worker is loaded as an ES module.
  worker: {
    format: 'es',
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
      '/wisp': { target: 'ws://localhost:8080', ws: true },
    },
  },
});
