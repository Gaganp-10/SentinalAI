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

  if (import.meta.env.PROD) {
    throw new Error(
      "[SentinelAI Config Error] VITE_API_BASE_URL is missing or empty in the production build environment! " +
        "You must set VITE_API_BASE_URL in your build environment (e.g., VITE_API_BASE_URL=https://api.sentinelai.com)."
    );
  }

  // Development default: relative paths proxied by Vite dev server
  return "";
}

export const API_BASE_URL: string = resolveApiBaseUrl();
