import { apiClient } from "./client";
import type { ProjectFile } from "./files";

export type Vulnerability = {
  id: string;
  file_id: string;
  file?: ProjectFile | null;
  type: string;
  line_number: number;
  severity: string;
  description: string;
  recommendation?: string | null;
  explanation?: string | null;
  code_snippet?: string | null;
  suggested_fix?: string | null;
  cwe_id?: string | null;
  owasp_category?: string | null;
  confidence: number;
  source_tool: string;
  fixed: boolean;
  auto_fixable?: boolean;
  fix_source?: string | null;
};

export type ApplyFixResult = {
  vulnerability: Vulnerability;
  file: { id: string; size: number };
  apply_status?: string;
};

export const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

export async function listVulnerabilities(
  projectId: string,
  params?: { severity?: string; type?: string; search?: string },
): Promise<Vulnerability[]> {
  const { data } = await apiClient.get<Vulnerability[]>("/api/vulnerabilities", {
    params: { project_id: projectId, ...params },
  });
  return Array.isArray(data) ? data : [];
}

export async function getVulnerability(vulnId: string): Promise<Vulnerability> {
  const { data } = await apiClient.get<Vulnerability>(`/api/vulnerabilities/${vulnId}`);
  return data;
}

export async function setVulnerabilityFixed(
  vulnId: string,
  fixed: boolean,
): Promise<Vulnerability> {
  const { data } = await apiClient.patch<Vulnerability>(`/api/vulnerabilities/${vulnId}`, { fixed });
  return data;
}

export async function regenerateFix(vulnId: string): Promise<Vulnerability> {
  const { data } = await apiClient.post<Vulnerability>(
    `/api/vulnerabilities/${vulnId}/regenerate-fix`,
  );
  return data;
}

/** Applies the suggested fix to the real uploaded file on the backend. */
export async function applyFix(vulnId: string): Promise<ApplyFixResult> {
  const { data } = await apiClient.post<ApplyFixResult>(`/api/vulnerabilities/${vulnId}/apply-fix`);
  return data;
}

/** Downloads the current (possibly patched) file content from the backend. */
export async function downloadFile(fileId: string, filename: string): Promise<void> {
  const response = await apiClient.get<Blob>(`/api/files/${fileId}/download`, {
    responseType: "blob",
  });
  const url = URL.createObjectURL(response.data);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function severityTone(severity?: string | null): string {
  if (!severity) return "text-muted-foreground";
  switch (severity.toLowerCase()) {
    case "critical":
      return "text-destructive";
    case "high":
      return "text-[oklch(0.72_0.15_60)]";
    case "medium":
      return "text-[oklch(0.82_0.13_95)]";
    default:
      return "text-muted-foreground";
  }
}
