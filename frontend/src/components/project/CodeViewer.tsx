import { useMemo } from "react";
import Prism from "prismjs";
import "prismjs/components/prism-python";
import "prismjs/components/prism-javascript";
import "prismjs/components/prism-typescript";
import "prismjs/components/prism-jsx";
import "prismjs/components/prism-tsx";
import "prismjs/components/prism-java";
import "prismjs/components/prism-c";
import "prismjs/components/prism-cpp";
import "prismjs/components/prism-json";
import "prismjs/components/prism-bash";
import "prismjs/components/prism-sql";

export function normalizeLanguage(lang?: string | null): string {
  if (!lang) return "javascript";
  const lower = lang.toLowerCase().trim();
  if (lower === "py" || lower === "python") return "python";
  if (lower === "js" || lower === "javascript") return "javascript";
  if (lower === "ts" || lower === "typescript") return "typescript";
  if (lower === "tsx" || lower === "jsx") return "tsx";
  if (lower === "java") return "java";
  if (lower === "c" || lower === "h") return "c";
  if (lower === "cpp" || lower === "c++" || lower === "hpp") return "cpp";
  if (lower === "json") return "json";
  if (lower === "sh" || lower === "bash") return "bash";
  if (lower === "sql") return "sql";
  return "javascript";
}

function getSeverityBorderColor(severity?: string | null): string {
  if (!severity) return "border-l-destructive";
  switch (severity.toLowerCase()) {
    case "critical":
      return "border-l-destructive shadow-[inset_4px_0_0_0_oklch(0.62_0.21_22)]";
    case "high":
      return "border-l-[oklch(0.72_0.17_55)] shadow-[inset_4px_0_0_0_oklch(0.72_0.17_55)]";
    case "medium":
      return "border-l-[oklch(0.82_0.14_92)] shadow-[inset_4px_0_0_0_oklch(0.82_0.14_92)]";
    case "low":
      return "border-l-[oklch(0.75_0.09_200)] shadow-[inset_4px_0_0_0_oklch(0.75_0.09_200)]";
    default:
      return "border-l-foreground/40";
  }
}

export function CodeViewer({
  code,
  language,
  lineNumber,
  startLine = 1,
  severity,
  filename,
}: {
  code: string;
  language?: string | null | undefined;
  lineNumber?: number | null | undefined;
  startLine?: number;
  severity?: string | null | undefined;
  filename?: string | null | undefined;
}) {
  const normLang = normalizeLanguage(language || filename?.split(".").pop());

  const lines = useMemo(() => {
    if (!code) return [];
    return code.split("\n");
  }, [code]);

  const highlightedCode = useMemo(() => {
    if (!code) return "";
    const defaultGrammar = (Prism.languages["javascript"] || Prism.languages["clike"]) as Prism.Grammar;
    const grammar: Prism.Grammar =
      (Prism.languages[normLang] as Prism.Grammar | undefined) || defaultGrammar;
    return Prism.highlight(code, grammar, normLang);
  }, [code, normLang]);

  const highlightedLines = useMemo(() => {
    if (!highlightedCode) return [];
    return highlightedCode.split("\n");
  }, [highlightedCode]);

  const severityAccent = getSeverityBorderColor(severity);

  return (
    <div className="glass-field overflow-hidden rounded-[18px] border border-border">
      {filename && (
        <div className="flex items-center justify-between border-b border-border/60 bg-foreground/[0.03] px-4 py-2 text-[12px] text-muted-foreground">
          <span className="font-mono">{filename}</span>
          <span className="uppercase tracking-[0.06em] opacity-70">{normLang}</span>
        </div>
      )}

      <div className="overflow-x-auto p-3 font-mono text-[12.5px] leading-[1.7]">
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((_, index) => {
              const currentLineNum = startLine + index;
              const isTargetLine = lineNumber !== undefined && lineNumber !== null && currentLineNum === lineNumber;
              const lineHtml = highlightedLines[index] ?? "";

              return (
                <tr
                  key={index}
                  className={`transition-colors ${
                    isTargetLine
                      ? `bg-foreground/[0.06] ${severityAccent} font-semibold`
                      : "hover:bg-foreground/[0.02]"
                  }`}
                >
                  <td className="w-12 select-none pr-4 text-right text-[11.5px] text-muted-foreground/50">
                    {currentLineNum}
                  </td>
                  <td className="whitespace-pre text-foreground/90 pl-2">
                    <span dangerouslySetInnerHTML={{ __html: lineHtml || "&nbsp;" }} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
