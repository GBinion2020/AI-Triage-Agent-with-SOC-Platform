import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    // Preserve older hashed bundles so stale cached index files do not white-screen.
    emptyOutDir: false,
  },
});
