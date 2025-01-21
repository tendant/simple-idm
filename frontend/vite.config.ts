import { defineConfig } from 'vite';
import solidPlugin from 'vite-plugin-solid';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [
    solidPlugin(),
    tailwindcss({
      config: './tailwind.config.cjs',
    }),
  ],
  server: {
    port: 3000,
    proxy: {
      '/auth': {
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
});
