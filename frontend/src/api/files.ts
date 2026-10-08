import { apiClient } from "./client";
import type { ScanHistory } from "./projects";

export type ProjectFile = {
  id: string;
  project_id: string;
  filename: string;
  filepath: string;
  language?: string | null;
  size?: number | null;
};

export const ACCEPTED_EXTENSIONS = [
  ".py",
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".java",
  ".c",
  ".cpp",
  ".h",
  ".php",
  ".zip",
] as const;

export async function listFiles(projectId: string): Promise<ProjectFile[]> {
  const { data } = await apiClient.get<ProjectFile[]>(`/api/projects/${projectId}/files`);
  return Array.isArray(data) ? data : [];
}

export async function uploadFile(
  projectId: string,
  file: File,
  onProgress?: (percent: number) => void,
): Promise<ProjectFile[]> {
  const form = new FormData();
  form.append("file", file);

  const { data } = await apiClient.post<ProjectFile | ProjectFile[]>(
    `/api/projects/${projectId}/files`,
    form,
    {
      onUploadProgress: (event) => {
        if (!onProgress) return;
        if (event.total) onProgress(Math.round((event.loaded / event.total) * 100));
      },
    },
  );
  // Backend returns a list for ZIPs and also a list for single files (response_model=List[FileOut])
  return Array.isArray(data) ? data : [data];
}

export async function startScan(projectId: string): Promise<ScanHistory> {
  const { data } = await apiClient.post<ScanHistory>(`/api/projects/${projectId}/scan`);
  return data;
}

export async function getScan(scanId: string): Promise<ScanHistory> {
  const { data } = await apiClient.get<ScanHistory>(`/api/scans/${scanId}`);
  return data;
}

export function formatBytes(size?: number | null): string {
  if (size == null || Number.isNaN(size)) return "—";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatScanTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}
