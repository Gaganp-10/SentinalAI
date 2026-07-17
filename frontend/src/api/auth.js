import client from './client';

export const signup = async (username, email, password) => {
  const { data } = await client.post('/auth/signup', { username, email, password });
  return data;
};

export const login = async (username, password) => {
  const { data } = await client.post('/auth/login', { username, password });
  return data;
};

export const getMe = async () => {
  const { data } = await client.get('/auth/me');
  return data;
};
