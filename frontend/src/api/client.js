import axios from 'axios';

// Use relative baseURL so Vite's dev proxy (vite.config.js) forwards all
// /auth, /projects, /scans, /vulnerabilities, /reports, /ai requests to
// http://localhost:8000. In production the nginx reverse proxy does the same.
// Do NOT set this to http://localhost:8000 — that bypasses the proxy and
// causes CORS failures in the browser.
const client = axios.create({
  baseURL: '',
  headers: {
    'Content-Type': 'application/json',
  },
});


// Request interceptor to dynamically inject the JWT bearer token
client.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('sast_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to intercept authorization failures and redirect
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('sast_token');
      if (window.location.pathname !== '/login' && window.location.pathname !== '/signup') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export default client;
