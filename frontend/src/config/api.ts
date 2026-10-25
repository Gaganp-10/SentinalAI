/**
 * Backend API base URL configuration.
 *
 * - Development (import.meta.env.DEV): Defaults to "" (empty string) so API calls
 *   starting with /api (e.g., /api/auth/login) are relative to origin http://localhost:3000/api/...
 *   and proxied by Vite's dev server to http://localhost:8000/api/...
 *
 * - Production (import.meta.env.PROD): MUST have VITE_API_BASE_URL explicitly set
 *   (e.g., VITE_API_BASE_URL=https://api.sentinelai.com).
 *   If missing or empty in production, throws a clear Error at startup to prevent silent failures.
 */

function resolveApiBaseUrl(): string {
  const rawEnvUrl = import.meta.env["VITE_API_BASE_URL"];

  if (rawEnvUrl && rawEnvUrl.trim() !== "") {
    return rawEnvUrl.trim().replace(/\/+$/, "");
  }

  // When empty or unset, use relative paths ("") so requests go to current origin /api/...
  // Nginx reverse-proxies /api/ to backend:8000 in Docker, and Vite proxies it in dev.
  return "";
}

export const API_BASE_URL: string = resolveApiBaseUrl();
