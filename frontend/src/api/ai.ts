import { apiClient } from "./client";

export type ChatMessage = {
  role: "user" | "assistant";
  content: string;
};

export type AskMentorRequest = {
  vuln_id?: string | undefined;
  project_id?: string | undefined;
  question: string;
  history?: ChatMessage[] | undefined;
};

export type MentorAnswer = {
  answer: string;
};

export async function askMentor(payload: AskMentorRequest): Promise<MentorAnswer> {
  const { data } = await apiClient.post<MentorAnswer>("/api/ai/ask", payload);
  return data;
}
