import client from './client';

export const getVulnerabilities = async ({ projectId, severity, type, search }) => {
  const params = { project_id: projectId };
  if (severity) params.severity = severity;
  if (type) params.type = type;
  if (search) params.search = search;
  
  const { data } = await client.get('/vulnerabilities', { params });
  return data;
};

export const updateVulnerabilityStatus = async (vulnId, fixed) => {
  const { data } = await client.patch(`/vulnerabilities/${vulnId}`, { fixed });
  return data;
};

export const regenerateFix = async (vulnId) => {
  const { data } = await client.post(`/vulnerabilities/${vulnId}/regenerate-fix`);
  return data;
};
