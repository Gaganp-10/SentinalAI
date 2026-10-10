import { apiClient } from "./client";

export interface OwaspCategory {
  id: string;        // e.g. "A03"
  name: string;      // e.g. "Injection"
  open: number;
  fixed: number;
  cwes: string[];
  coverage: "partial" | "limited" | "none";
  coverage_note: string;
}

export interface OwaspCoverage {
  version: string;          // "2021"
  categories: OwaspCategory[];
  unmapped_findings: number;
}

export async function getOwaspCoverage(projectId: string): Promise<OwaspCoverage> {
  const res = await apiClient.get<OwaspCoverage>(`/projects/${projectId}/owasp`);
  return res.data;
}
