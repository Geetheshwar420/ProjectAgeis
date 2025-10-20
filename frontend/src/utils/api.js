import axios from 'axios';

// Dynamically determine the API base URL
// This allows the app to work both on localhost and network access
// and prevents mixed-content issues when served over HTTPS
const getApiBaseUrl = () => {
    // Check if there's an environment variable (for production builds)
    if (process.env.REACT_APP_API_URL) {
        return process.env.REACT_APP_API_URL;
    }
    
    // Use the page's current protocol to prevent mixed-content blocking
    // This ensures HTTP pages use HTTP backend and HTTPS pages use HTTPS backend
    const protocol = window.location.protocol; // 'http:' or 'https:'
    const hostname = window.location.hostname || 'localhost';
    
    // Get configurable port from environment or default to 5000
    const port = process.env.REACT_APP_API_PORT || '5000';
    
    // Handle empty hostname cases and avoid duplicate slashes
    if (!hostname) {
        console.warn('Unable to determine hostname, falling back to localhost');
        return `${protocol}//localhost:${port}`;
    }
    
    // Construct URL: protocol already includes ':' (e.g., 'http:')
    // Use '//' after protocol, avoiding duplicate slashes
    return `${protocol}//${hostname}:${port}`;
};

const api = axios.create({
    baseURL: getApiBaseUrl(),
});

api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('access_token');
        if (token) {
            config.headers['Authorization'] = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

export default api;