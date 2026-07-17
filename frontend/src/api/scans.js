import client from './client';

export const triggerScan = async (projectId) => {
  const { data } = await client.post(`/projects/${projectId}/scan`);
  return data;
};

export const getScanStatus = async (scanId) => {
  const { data } = await client.get(`/scans/${scanId}`);
  return data;
};

export const getProjectScans = async (projectId) => {
  const { data } = await client.get(`/projects/${projectId}/scans`);
  return data;
};
