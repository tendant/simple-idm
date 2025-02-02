import { defineConfig } from 'vite';
import solidPlugin from 'vite-plugin-solid';
import tailwindcss from '@tailwindcss/vite';

import path from "path";

export default defineConfig({
  plugins: [
    solidPlugin(),
    tailwindcss({
      config: './tailwind.config.js',
    }),
  ],
  server: {
    port: 3000,
    proxy: {
      '/api/admin/auth': {
        target: 'http://localhost:4001',
        changeOrigin: true,
      },
      '/api/': {
        target: 'http://localhost:4000',
        changeOrigin: true,
      },
      '/idm': {
        target: 'http://localhost:4000',
        changeOrigin: true,
      }
    },
  },
  build: {
    target: 'esnext',
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src")
    }
  }
});
