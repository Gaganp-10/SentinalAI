import client from './client';

export const getFiles = async (projectId) => {
  const { data } = await client.get(`/projects/${projectId}/files`);
  return data;
};

export const uploadFiles = async (projectId, file, onUploadProgress) => {
  const formData = new FormData();
  formData.append('file', file);
  
  const { data } = await client.post(`/projects/${projectId}/files`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress,
  });
  return data;
};
