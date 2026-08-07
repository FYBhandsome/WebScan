import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5175,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8081',
        changeOrigin: true,
        ws: true,
        configure: (proxy, options) => {
          proxy.on('error', (err, req, res) => {
            if (err.code !== 'ECONNREFUSED') console.warn('proxy error', err.message);
          });
          proxy.on('proxyReq', (proxyReq, req, res) => {
            console.log('Sending Request:', req.url);
          });
          proxy.on('proxyRes', (proxyRes, req, res) => {
            console.log('Received Response:', proxyRes.statusCode, req.url);
          });
        },
      },
    },
  },
})
