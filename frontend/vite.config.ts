import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  return {
    base: '/',
    server: {
      port: 3000,
      host: '0.0.0.0',
      headers: {
        'Cross-Origin-Opener-Policy': 'same-origin-allow-popups'
      },
      proxy: {
        '/socket.io': {
          target: 'http://localhost:5000',
          ws: true,
          changeOrigin: true
        },
        '/api': {
          target: 'http://localhost:5000',
          changeOrigin: true
        },
        '/login': 'http://localhost:5000',
        '/google_login': 'http://localhost:5000',
        '/register': 'http://localhost:5000',
        '/logout': 'http://localhost:5000',
        '/me': 'http://localhost:5000',
        '/users': 'http://localhost:5000',
        '/user': 'http://localhost:5000',
        '/friend-request': 'http://localhost:5000',
        '/friend-requests': 'http://localhost:5000',
        '/friends': 'http://localhost:5000',
        '/messages': 'http://localhost:5000',
        '/encrypt': 'http://localhost:5000',
        '/decrypt': 'http://localhost:5000',
        '/sign': 'http://localhost:5000',
        '/verify': 'http://localhost:5000',
        '/initiate_qke': 'http://localhost:5000',
        '/prepare_message': 'http://localhost:5000',
        '/upload': 'http://localhost:5000',
        '/uploads': 'http://localhost:5000',
      }
    },
    plugins: [
      tailwindcss(),
      react({
        jsxRuntime: 'automatic',
      }),
      VitePWA({
        registerType: 'autoUpdate',
        includeAssets: ['pwa-192x192.png', 'pwa-512x512.png', 'favicon.ico', 'apple-touch-icon.png'],
        manifest: {
          name: 'PROJECT AGIS',
          short_name: 'AGIS',
          description: 'Secure Messaging with Post-Quantum Cryptography',
          theme_color: '#10b981',
          icons: [
            {
              src: 'pwa-192x192.png',
              sizes: '192x192',
              type: 'image/png'
            },
            {
              src: 'pwa-512x512.png',
              sizes: '512x512',
              type: 'image/png'
            }
          ]
        }
      })
    ],
    define: {
      'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY),
      'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY)
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      }
    }
  };
});

