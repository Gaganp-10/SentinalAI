import axios from "axios";
import { API_BASE_URL } from "../config/api";

export const TOKEN_STORAGE_KEY = "access_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_STORAGE_KEY) || window.localStorage.getItem("sast_token");
}

export function setToken(token: string) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
  window.localStorage.setItem("sast_token", token);
}

export function clearToken() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  window.localStorage.removeItem("sast_token");
}

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "ngrok-skip-browser-warning": "true",
  },
});

// Attach JWT token to every request after login
apiClient.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

/** Turns any backend/network failure into a real, human-readable message. */
export function toApiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const detail = (error.response?.data as { detail?: unknown } | undefined)?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      const first = detail[0] as { msg?: string; loc?: unknown[] } | undefined;
      if (first?.msg) return `${(first.loc ?? []).slice(-1).join("")} ${first.msg}`.trim();
    }
    if (error.response) return `${error.response.status} ${error.response.statusText}`;
    return error.message;
  }
  return error instanceof Error ? error.message : String(error);
}
