import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  return {
    server: {
      port: 3000,
      host: '0.0.0.0',
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
        // Proxy all other requests that might be API calls if they don't match static assets
        // However, be careful not to proxy frontend routes.
        // Since we use specific endpoints like /login, /register, etc., we might need to list them or use a prefix.
        // The backend uses root-level routes (e.g. /login, /register).
        // We should add specific proxies for them.
        '/login': 'http://localhost:5000',
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
    plugins: [react()],
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
