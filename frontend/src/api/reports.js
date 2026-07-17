import client from './client';

export const downloadReport = async (projectId, format, projectName) => {
  /**
   * Fetches the report file from the backend as a Blob, attaching
   * the authorization header. Then, triggers a native browser download.
   */
  const { data } = await client.get(`/reports/${projectId}`, {
    params: { format },
    responseType: 'blob',
  });
  
  // Set MIME type
  let mimeType = 'text/html';
  if (format === 'pdf') mimeType = 'application/pdf';
  else if (format === 'json') mimeType = 'application/json';
  else if (format === 'csv') mimeType = 'text/csv';

  const blob = new Blob([data], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  
  const cleanName = projectName.replace(/\s+/g, '_');
  link.setAttribute('download', `sast_report_${cleanName}.${format}`);
  document.body.appendChild(link);
  link.click();
  
  // Cleanup
  link.remove();
  window.URL.revokeObjectURL(url);
};
