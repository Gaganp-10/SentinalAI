# SentinelAI Frontend

Modern, high-performance security vulnerability management frontend built with TypeScript, React, TanStack Router, and Tailwind CSS.

---

## ⚙️ Environment & API Configuration

API requests are managed by an environment-aware configuration in [`src/config/api.ts`](file:///c:/Users/HP-PC/Desktop/security%20vulnerability%20decoder%20and%20fixer/frontend/src/config/api.ts).

### 🛠️ Development Mode (`npm run dev`)
In development, `VITE_API_BASE_URL` is kept empty (`""`). All API requests use relative paths (e.g. `/auth/login`, `/projects`, `/files`), which are automatically forwarded to the backend running at `http://localhost:8000` by the **Vite Dev Server Proxy** configured in [`vite.config.ts`](file:///c:/Users/HP-PC/Desktop/security%20vulnerability%20decoder%20and%20fixer/frontend/vite.config.ts).

#### Vite Proxy Setup (`vite.config.ts`):
```typescript
server: {
  port: 3000,
  proxy: {
    "/auth": { target: "http://localhost:8000", changeOrigin: true },
    "/projects": { target: "http://localhost:8000", changeOrigin: true },
    "/scans": { target: "http://localhost:8000", changeOrigin: true },
    "/vulnerabilities": { target: "http://localhost:8000", changeOrigin: true },
    "/reports": { target: "http://localhost:8000", changeOrigin: true },
    "/ai": { target: "http://localhost:8000", changeOrigin: true },
    "/files": { target: "http://localhost:8000", changeOrigin: true },
  },
}
```

### 🚀 Production Mode (`npm run build`)
For production deployments (e.g., Vercel, Netlify, AWS S3 + CloudFront, Docker + NGINX):
Set `VITE_API_BASE_URL` in your build environment or `.env` file to your deployed backend URL.

```sh
# .env or build environment variable
VITE_API_BASE_URL=https://api.sentinelai.com
```

If deploying behind a reverse proxy (e.g., NGINX forwarding `/auth` and `/api` to the backend), leave `VITE_API_BASE_URL=` empty to continue using relative origin routing.

---

## 🏃 Local Development Quickstart

1. **Install dependencies**:
   ```sh
   npm install
   ```

2. **Start the development server**:
   ```sh
   npm run dev
   ```
   The application will run at `http://localhost:3000`. Ensure your FastAPI backend is running on `http://localhost:8000`.

3. **Build for production**:
   ```sh
   npm run build
   ```
