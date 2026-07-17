import React, { useState, useRef, useEffect } from 'react';
import { askMentor } from '../../api/ai';
import { BotMessageSquare, Send, X, ShieldQuestion, Loader2 } from 'lucide-react';

const SecurityMentorChat = ({ vulnContext = null }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content:
        "Hello! I'm your Security Mentor. Ask me about vulnerabilities, secure coding practices, or anything security-related. I'll use the current vulnerability as context if available.",
    },
  ]);
  const [question, setQuestion] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isOpen]);

  const handleSend = async () => {
    if (!question.trim() || isLoading) return;

    const userMsg = question.trim();
    setQuestion('');
    setMessages((prev) => [...prev, { role: 'user', content: userMsg }]);
    setIsLoading(true);

    try {
      const result = await askMentor(vulnContext?.id, userMsg);
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: result.answer || result.response || 'No response received.',
        },
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ Error: ${err.response?.data?.detail || 'Failed to get a response. Please try again.'}`,
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="fixed bottom-6 right-6 z-50 p-4 rounded-full border transition-all hover:scale-105 active:scale-95"
        style={{
          background: 'var(--signal-green)',
          color: 'var(--bg-void)',
          borderColor: 'var(--border-glow-active)',
          boxShadow: '0 0 24px -4px rgba(46,204,113,0.45)',
        }}
        title="Security Mentor Chat"
      >
        {isOpen ? <X className="h-5 w-5" /> : <BotMessageSquare className="h-5 w-5" />}
      </button>

      {isOpen && (
        <div
          className="fixed bottom-20 right-6 z-50 w-80 md:w-96 h-[500px] rounded-[10px] border flex flex-col overflow-hidden"
          style={{
            background: 'var(--bg-panel)',
            borderColor: 'var(--border-glow)',
            boxShadow: '0 0 32px -8px rgba(46,204,113,0.25)',
          }}
        >
          <div
            className="flex items-center gap-3 p-4 border-b"
            style={{ borderColor: 'var(--border-glow)', background: 'var(--bg-void)' }}
          >
            <div
              className="p-1.5 rounded-lg border"
              style={{
                background: 'rgba(46,204,113,0.12)',
                borderColor: 'rgba(46,204,113,0.3)',
              }}
            >
              <ShieldQuestion className="h-4 w-4 text-[var(--signal-green)]" />
            </div>
            <div>
              <p className="text-sm font-display font-semibold text-[var(--text-primary)]">
                Security Mentor
              </p>
              <p className="text-[10px] text-[var(--text-secondary)] font-mono">
                AI-powered security Q&amp;A
              </p>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-3 text-sm">
            {messages.map((msg, idx) => (
              <div
                key={idx}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[85%] rounded-xl px-3.5 py-2.5 leading-relaxed ${
                    msg.role === 'user' ? 'rounded-br-sm' : 'rounded-bl-sm border'
                  }`}
                  style={
                    msg.role === 'user'
                      ? {
                          background: 'var(--signal-green)',
                          color: 'var(--bg-void)',
                        }
                      : {
                          background: 'var(--bg-panel-hover)',
                          color: 'var(--text-primary)',
                          borderColor: 'var(--border-glow)',
                        }
                  }
                >
                  {msg.content}
                </div>
              </div>
            ))}
            {isLoading && (
              <div className="flex justify-start">
                <div
                  className="rounded-xl rounded-bl-sm px-3.5 py-2.5 border"
                  style={{
                    background: 'var(--bg-panel-hover)',
                    borderColor: 'var(--border-glow)',
                  }}
                >
                  <Loader2 className="h-4 w-4 text-[var(--signal-green)] animate-spin" />
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          <div
            className="p-3 border-t"
            style={{ borderColor: 'var(--border-glow)', background: 'var(--bg-void)' }}
          >
            <div className="flex items-end gap-2">
              <textarea
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about this vulnerability..."
                rows={2}
                className="input-field flex-1 resize-none text-xs !rounded-xl"
                disabled={isLoading}
              />
              <button
                onClick={handleSend}
                disabled={!question.trim() || isLoading}
                className="p-2.5 rounded-xl disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0"
                style={{
                  background: 'var(--signal-green)',
                  color: 'var(--bg-void)',
                }}
              >
                <Send className="h-4 w-4" />
              </button>
            </div>
            <p className="text-[9px] text-[var(--text-secondary)] font-mono mt-1.5 text-center">
              Enter to send · Shift+Enter for newline
            </p>
          </div>
        </div>
      )}
    </>
  );
};

export default SecurityMentorChat;
