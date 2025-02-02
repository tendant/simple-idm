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
      '/auth': {
        target: 'http://localhost:4001',
        changeOrigin: true,
        configure: (proxy, _options) => {
          proxy.on('error', (err, _req, _res) => {
            console.log('proxy error', err);
          });
          proxy.on('proxyReq', (proxyReq, req, _res) => {
            console.log('Sending Request to the Target:', req.method, req.url);
          });
          proxy.on('proxyRes', (proxyRes, req, _res) => {
            console.log('Received Response from the Target:', proxyRes.statusCode, req.url);
          });
        },
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
