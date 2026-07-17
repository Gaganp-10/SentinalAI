import client from './client';

export const askMentor = async (vulnId, question) => {
  const { data } = await client.post('/ai/ask', {
    vuln_id: vulnId,
    question: question
  });
  return data;
};
