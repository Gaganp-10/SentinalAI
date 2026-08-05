import { apiClient } from "./client";

export async function downloadReport(projectId: string, format: "html" | "pdf" | "json" | "csv", projectName: string): Promise<void> {
  const response = await apiClient.get<Blob>(`/api/reports/${projectId}`, {
    params: { format },
    responseType: "blob",
  });

  let mimeType = "text/html";
  if (format === "pdf") mimeType = "application/pdf";
  else if (format === "json") mimeType = "application/json";
  else if (format === "csv") mimeType = "text/csv";

  const blob = new Blob([response.data], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;

  const cleanName = projectName.replace(/\s+/g, "_");
  link.setAttribute("download", `sast_report_${cleanName}.${format}`);
  document.body.appendChild(link);
  link.click();

  link.remove();
  window.URL.revokeObjectURL(url);
}
