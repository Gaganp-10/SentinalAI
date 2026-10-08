import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useMutation } from "@tanstack/react-query";
import {
  Sparkles,
  X,
  Send,
  RotateCcw,
  Bot,
  AlertCircle,
  ShieldAlert,
  ChevronDown,
  CornerDownLeft,
} from "lucide-react";
import { toast } from "sonner";
import { Markdown } from "./Markdown";
import { askMentor, type ChatMessage } from "../../api/ai";
import { toApiErrorMessage } from "../../api/client";

interface SecurityCopilotProps {
  vulnId?: string;
  findingContext?: {
    type?: string;
    severity?: string;
    filename?: string;
  };
}

export function SecurityCopilot({ vulnId, findingContext }: SecurityCopilotProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom of conversation
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isOpen]);

  // Focus textarea when panel opens
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => textareaRef.current?.focus(), 150);
    }
  }, [isOpen]);

  const askMutation = useMutation({
    mutationFn: (userQuestion: string) => {
      return askMentor({
        vuln_id: vulnId,
        question: userQuestion,
        history: messages,
      });
    },
    onSuccess: (data) => {
      setErrorMessage(null);
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: data.answer },
      ]);
    },
    onError: (err: any) => {
      const errText = toApiErrorMessage(err);
      setErrorMessage(errText);
      if (err?.response?.status === 429) {
        toast.error("AI Provider rate limit reached. Please wait a moment before asking again.");
      } else {
        toast.error(errText || "Failed to receive response from Security Copilot");
      }
    },
  });

  const handleSend = () => {
    const trimmed = input.trim();
    if (!trimmed || askMutation.isPending) return;

    if (trimmed.length > 2000) {
      toast.error("Question must be 2,000 characters or fewer.");
      return;
    }

    setErrorMessage(null);
    const newMsg: ChatMessage = { role: "user", content: trimmed };
    setMessages((prev) => [...prev, newMsg]);
    setInput("");
    askMutation.mutate(trimmed);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleClearHistory = () => {
    setMessages([]);
    setErrorMessage(null);
    toast.info("Conversation cleared");
  };

  const defaultSuggestions = vulnId
    ? [
        "Why is this finding dangerous?",
        "How should I fix this vulnerability?",
        "Can you explain the suggested fix in detail?",
        "Are there any subtle edge cases or bypasses for this?",
      ]
    : [
        "What are common OWASP Top 10 vulnerabilities in modern web apps?",
        "How do I prevent SQL injection with parameterized queries?",
        "What is the best way to safely store secrets in production?",
        "Explain Cross-Site Scripting (XSS) and effective defenses",
      ];

  return (
    <>
      {/* Floating Action Button */}
      <motion.button
        id="security-copilot-trigger"
        onClick={() => setIsOpen((prev) => !prev)}
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2.5 rounded-full px-4 py-3 text-sm font-medium text-foreground transition-all duration-300 shadow-xl cursor-pointer group"
        style={{
          background: "radial-gradient(120% 180% at 50% -40%, oklch(1 0 0 / 22%) 0%, oklch(1 0 0 / 8%) 100%)",
          backdropFilter: "blur(20px)",
          border: "1px solid oklch(1 0 0 / 18%)",
          boxShadow: "0 18px 36px -12px oklch(0 0 0 / 75%), inset 0 1px 0 oklch(1 0 0 / 25%)",
        }}
        whileHover={{ scale: 1.04 }}
        whileTap={{ scale: 0.96 }}
        aria-label="Open Security Copilot"
      >
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
        </span>
        <Sparkles className="h-4 w-4 text-primary group-hover:rotate-12 transition-transform duration-300" />
        <span className="font-semibold tracking-tight text-[13px]">
          {vulnId ? "Ask Finding Mentor" : "Security Copilot"}
        </span>
      </motion.button>

      {/* Slide-in Chat Panel */}
      <AnimatePresence>
        {isOpen && (
          <>
            {/* Backdrop for mobile / outside click */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsOpen(false)}
              className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs sm:hidden"
            />

            {/* Slide-in Panel */}
            <motion.aside
              id="security-copilot-panel"
              initial={{ x: "100%", opacity: 0.5 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: "100%", opacity: 0.5 }}
              transition={{ type: "spring", damping: 28, stiffness: 280 }}
              className="fixed top-0 right-0 bottom-0 z-50 flex w-full flex-col border-l sm:w-[460px]"
              style={{
                backgroundColor: "oklch(0.12 0.02 260 / 92%)",
                backdropFilter: "blur(28px) saturate(130%)",
                borderColor: "oklch(1 0 0 / 14%)",
                boxShadow: "-12px 0 40px -15px oklch(0 0 0 / 80%)",
              }}
            >
              {/* Header */}
              <div className="flex items-center justify-between border-b px-5 py-4" style={{ borderColor: "oklch(1 0 0 / 10%)" }}>
                <div className="flex items-center gap-3">
                  <div
                    className="flex h-9 w-9 items-center justify-center rounded-xl"
                    style={{
                      background: "oklch(1 0 0 / 8%)",
                      border: "1px solid oklch(1 0 0 / 15%)",
                    }}
                  >
                    <Bot className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-sm font-semibold tracking-tight text-foreground">
                        Security Copilot
                      </h2>
                      <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold tracking-wide text-emerald-400 border border-emerald-500/30 uppercase">
                        AI Mentor
                      </span>
                    </div>
                    <p className="text-[11px] text-muted-foreground line-clamp-1">
                      {vulnId
                        ? `Context: ${findingContext?.type || "Active Finding"} (${findingContext?.filename || "file source loaded"})`
                        : "General Security Guidance & Best Practices"}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-1.5">
                  {messages.length > 0 && (
                    <button
                      onClick={handleClearHistory}
                      title="Clear conversation"
                      className="rounded-lg p-2 text-muted-foreground hover:bg-foreground/[0.08] hover:text-foreground transition-colors cursor-pointer"
                    >
                      <RotateCcw className="h-4 w-4" />
                    </button>
                  )}
                  <button
                    id="close-security-copilot"
                    onClick={() => setIsOpen(false)}
                    title="Close panel"
                    className="rounded-lg p-2 text-muted-foreground hover:bg-foreground/[0.08] hover:text-foreground transition-colors cursor-pointer"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* Messages Container */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {messages.length === 0 ? (
                  <div className="flex h-full flex-col justify-center items-center text-center px-4 py-8 space-y-6">
                    <div
                      className="flex h-14 w-14 items-center justify-center rounded-2xl"
                      style={{
                        background: "oklch(1 0 0 / 6%)",
                        border: "1px solid oklch(1 0 0 / 14%)",
                      }}
                    >
                      <Sparkles className="h-7 w-7 text-primary" />
                    </div>

                    <div className="space-y-1.5 max-w-sm">
                      <h3 className="text-sm font-semibold text-foreground">
                        {vulnId ? "Vulnerability Mentorship" : "Application Security Assistant"}
                      </h3>
                      <p className="text-[12.5px] leading-relaxed text-muted-foreground">
                        {vulnId
                          ? `Ask specific questions regarding this ${findingContext?.type || "vulnerability"} finding. The mentor has access to the full source code and linter findings.`
                          : "Ask any question about vulnerability remediation, code security, secure architectures, or OWASP compliance."}
                      </p>
                    </div>

                    {/* Quick prompts */}
                    <div className="w-full space-y-2 text-left pt-2">
                      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground px-1">
                        Suggested Inquiries
                      </p>
                      <div className="space-y-1.5">
                        {defaultSuggestions.map((prompt, idx) => (
                          <button
                            key={idx}
                            onClick={() => {
                              setInput(prompt);
                              setTimeout(() => textareaRef.current?.focus(), 50);
                            }}
                            className="w-full text-left text-[12px] text-foreground/80 hover:text-foreground rounded-xl px-3 py-2.5 transition-all duration-200 cursor-pointer"
                            style={{
                              background: "oklch(1 0 0 / 4%)",
                              border: "1px solid oklch(1 0 0 / 8%)",
                            }}
                          >
                            <span className="text-primary mr-1.5 font-bold">→</span>
                            {prompt}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <>
                    {messages.map((msg, index) => {
                      const isUser = msg.role === "user";
                      return (
                        <div
                          key={index}
                          className={`flex flex-col ${isUser ? "items-end" : "items-start"}`}
                        >
                          <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground mb-1 px-1">
                            {isUser ? "You" : "Security Mentor"}
                          </span>
                          <div
                            className={`rounded-2xl px-4 py-3 text-[13px] leading-relaxed ${
                              isUser
                                ? "max-w-[85%] rounded-tr-xs text-foreground"
                                : "w-full rounded-tl-xs text-foreground/90 border border-white/10"
                            }`}
                            style={{
                              background: isUser
                                ? "oklch(1 0 0 / 12%)"
                                : "oklch(1 0 0 / 5%)",
                              backdropFilter: "blur(16px)",
                              boxShadow: isUser
                                ? "0 4px 14px -3px oklch(0 0 0 / 40%)"
                                : "0 8px 24px -6px oklch(0 0 0 / 50%)",
                            }}
                          >
                            {isUser ? (
                              <p className="whitespace-pre-wrap">{msg.content}</p>
                            ) : (
                              <div className="prose prose-invert max-w-none">
                                <Markdown text={msg.content} />
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}

                    {/* Typing Indicator */}
                    {askMutation.isPending && (
                      <div className="flex flex-col items-start">
                        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground mb-1 px-1">
                          Security Mentor
                        </span>
                        <div
                          className="flex items-center gap-2 rounded-2xl rounded-tl-xs px-4 py-3 text-xs text-muted-foreground"
                          style={{
                            background: "oklch(1 0 0 / 5%)",
                            border: "1px solid oklch(1 0 0 / 10%)",
                          }}
                        >
                          <div className="flex items-center gap-1">
                            <span className="h-1.5 w-1.5 rounded-full bg-primary animate-bounce [animation-delay:-0.3s]" />
                            <span className="h-1.5 w-1.5 rounded-full bg-primary animate-bounce [animation-delay:-0.15s]" />
                            <span className="h-1.5 w-1.5 rounded-full bg-primary animate-bounce" />
                          </div>
                          <span>Consulting security model...</span>
                        </div>
                      </div>
                    )}

                    {/* Inline Error display if call failed */}
                    {errorMessage && !askMutation.isPending && (
                      <div className="flex items-center gap-2 rounded-xl border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-xs text-destructive">
                        <AlertCircle className="h-4 w-4 shrink-0" />
                        <span className="flex-1">{errorMessage}</span>
                      </div>
                    )}

                    <div ref={messagesEndRef} />
                  </>
                )}
              </div>

              {/* Bottom Input Box */}
              <div className="border-t p-4" style={{ borderColor: "oklch(1 0 0 / 10%)" }}>
                <div
                  className="rounded-2xl p-2 transition-all focus-within:ring-2 focus-within:ring-primary/40"
                  style={{
                    background: "oklch(1 0 0 / 6%)",
                    border: "1px solid oklch(1 0 0 / 14%)",
                  }}
                >
                  <textarea
                    ref={textareaRef}
                    id="security-copilot-input"
                    rows={2}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    disabled={askMutation.isPending}
                    placeholder={
                      vulnId
                        ? "Ask about this finding (Enter to send, Shift+Enter for newline)..."
                        : "Ask a security question (Enter to send, Shift+Enter for newline)..."
                    }
                    className="w-full resize-none bg-transparent px-2 py-1 text-[13px] text-foreground placeholder:text-muted-foreground focus:outline-none disabled:opacity-50"
                  />
                  <div className="flex items-center justify-between pt-1 px-1">
                    <span className="text-[10px] text-muted-foreground">
                      {input.length > 1500 ? `${input.length}/2000` : "Shift+Enter for newline"}
                    </span>
                    <button
                      id="security-copilot-send-button"
                      onClick={handleSend}
                      disabled={!input.trim() || askMutation.isPending}
                      className="flex h-8 w-8 items-center justify-center rounded-xl bg-primary text-primary-foreground transition-all hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer shadow-md"
                    >
                      <Send className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
