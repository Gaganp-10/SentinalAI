import { apiClient, setToken } from "./client";

export type LoginResponse = { access_token: string; token_type: string };
export type CurrentUser = {
  id?: number | string;
  username?: string;
  email?: string;
  [key: string]: unknown;
};

export async function login(username: string, password: string): Promise<LoginResponse> {
  const { data } = await apiClient.post<LoginResponse>("/api/auth/login", { username, password });
  if (data?.access_token) setToken(data.access_token);
  return data;
}

export async function signup(username: string, email: string, password: string) {
  const { data } = await apiClient.post("/api/auth/signup", { username, email, password });
  return data;
}

export async function getCurrentUser(): Promise<CurrentUser> {
  const { data } = await apiClient.get<CurrentUser>("/api/auth/me");
  return data;
}
