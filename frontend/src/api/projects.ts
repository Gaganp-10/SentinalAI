import { apiClient } from "./client";

export type Project = {
  id: string;
  user_id: string;
  project_name: string;
  scan_date?: string | null;
};

export type DependencySummary = {
  checked: number;
  failed?: number;
  not_checked: number;
  manifests: number;
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
  warnings?: string[] | null;
  dependency_summary?: DependencySummary | null;
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

export type DiffFindingItem = {
  id: string;
  file: string;
  line: number;
  type: string;
  severity: string;
  cwe?: string | null;
  source_tools?: string[];
  vulnerability_id?: string | null;
  package_name?: string | null;
  old_version?: string | null;
  new_version?: string | null;
  note?: string | null;
  reason?: string | null;
};

export type ScanDiffResponse = {
  baseline?: boolean;
  scan_id?: string;
  base_scan_id?: string;
  summary?: {
    new: number;
    resolved: number;
    persisting: number;
    regressed: number;
    not_comparable: number;
  };
  score_before?: number | null;
  score_after?: number | null;
  severity_delta?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  } | null;
  items?: {
    new: DiffFindingItem[];
    resolved: DiffFindingItem[];
    persisting: DiffFindingItem[];
    regressed: DiffFindingItem[];
    not_comparable: DiffFindingItem[];
  };
  notes?: string[];
};

export async function getScanDiff(
  projectId: string,
  scanId: string,
  baseId?: string
): Promise<ScanDiffResponse> {
  const url = baseId
    ? `/api/projects/${projectId}/scans/${scanId}/diff?base=${baseId}`
    : `/api/projects/${projectId}/scans/${scanId}/diff`;
  const { data } = await apiClient.get<ScanDiffResponse>(url);
  return data;
}
