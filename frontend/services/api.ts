import axios from 'axios';

// Central place to compute the API base URL so Axios and Socket.IO stay in sync
export const getApiBaseUrl = (): string => {
    const DEFAULT_PROD_API = 'https://projectageis.onrender.com';

    // Highest priority: explicit env override
    if (import.meta.env.VITE_API_URL) {
        return import.meta.env.VITE_API_URL.replace(/\/$/, '');
    }

    const protocol = window.location.protocol; // 'http:' or 'https:'
    const hostname = window.location.hostname || 'localhost';
    const port = import.meta.env.VITE_API_PORT || '5000';

    // Detect typical local dev hostnames and private LAN IPs (IPv4 and IPv6 loopback)
    const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
    const isPrivateLan = /^10\./.test(hostname) || /^192\.168\./.test(hostname) ||
        /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostname);

    // Local dev: talk to the backend on port 5000 on the same host
    if (isLocalhost || isPrivateLan) {
        return `${protocol}//${hostname}:${port}`;
    }

    // Vercel or any public host: default to known backend if env not provided
    if (/vercel\.app$/.test(hostname) || /netlify\.app$/.test(hostname) || /\.onrender\.com$/.test(hostname)) {
        return DEFAULT_PROD_API;
    }

    // Fallback: try same host with provided port (useful for custom domains in dev)
    // Only append port if it's non-empty and not the standard port for the protocol
    const isStandardPort = (proto: string, p: string) => (
        (proto === 'http:' && p === '80') ||
        (proto === 'https:' && p === '443')
    );
    const portSuffix = (port && !isStandardPort(protocol, String(port))) ? `:${port}` : '';
    return `${protocol}//${hostname}${portSuffix}`;
};

const api = axios.create({
    baseURL: getApiBaseUrl(),
    withCredentials: true, // Required for session cookies
    headers: {
        'Content-Type': 'application/json',
    },
});

// Always log the API URL once for easier troubleshooting
console.log('API Base URL:', api.defaults.baseURL);

export default api;
