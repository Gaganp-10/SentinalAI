import { apiClient } from "./client";

export type Project = {
  id: string;
  user_id: string;
  project_name: string;
  scan_date?: string | null;
};

export type ScanHistory = {
  id: string;
  project_id: string;
  scan_time: string;
  total_issues: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  status: string;
};

export async function listProjects(): Promise<Project[]> {
  const { data } = await apiClient.get<Project[]>("/api/projects");
  return Array.isArray(data) ? data : [];
}

export async function getProject(projectId: string): Promise<Project> {
  const { data } = await apiClient.get<Project>(`/api/projects/${projectId}`);
  return data;
}

export async function createProject(project_name: string): Promise<Project> {
  const { data } = await apiClient.post<Project>("/api/projects", { project_name });
  return data;
}

export async function listScans(projectId: string): Promise<ScanHistory[]> {
  const { data } = await apiClient.get<ScanHistory[]>(`/api/projects/${projectId}/scans`);
  return Array.isArray(data) ? data : [];
}

export function latestScan(scans: ScanHistory[] | undefined): ScanHistory | undefined {
  if (!scans?.length) return undefined;
  return [...scans].sort(
    (a, b) => new Date(b.scan_time).getTime() - new Date(a.scan_time).getTime(),
  )[0];
}

export function formatScanDate(value?: string | null): string {
  if (!value) return "No scans yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No scans yet";
  return date.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}
