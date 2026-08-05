import type { ReactNode } from "react";

/** Minimal markdown renderer for backend-provided explanation/recommendation text. */
function inline(text: string): ReactNode[] {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={i} className="font-medium text-foreground">
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code
          key={i}
          className="rounded-[6px] bg-foreground/[0.07] px-1.5 py-0.5 font-mono text-[12px] text-foreground/90"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return <span key={i}>{part}</span>;
  });
}

export function Markdown({ text }: { text: string }) {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let list: string[] = [];
  let fence: string[] | null = null;
  const fenceLines = () => fence ?? [];

  const flushList = () => {
    if (!list.length) return;
    blocks.push(
      <ul key={`ul-${blocks.length}`} className="ml-4 list-disc space-y-1.5">
        {list.map((item, i) => (
          <li key={i} className="text-[13px] leading-[1.65] text-muted-foreground">
            {inline(item)}
          </li>
        ))}
      </ul>,
    );
    list = [];
  };

  lines.forEach((raw) => {
    const line = raw.trimEnd();

    if (line.trim().startsWith("```")) {
      if (fence) {
        blocks.push(
          <pre
            key={`pre-${blocks.length}`}
            className="overflow-x-auto rounded-[16px] bg-foreground/[0.05] px-4 py-3 font-mono text-[12.5px] leading-[1.6] text-foreground/90"
          >
            <code>{fenceLines().join("\n")}</code>
          </pre>,
        );
        fence = null;
      } else {
        flushList();
        fence = [];
      }
      return;
    }
    if (fence) {
      fence.push(raw);
      return;
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flushList();
      const level = (heading[1] ?? "").length;
      blocks.push(
        <p
          key={`h-${blocks.length}`}
          className={
            level <= 2
              ? "text-[15px] font-semibold tracking-[-0.02em] text-foreground"
              : "text-[11.5px] uppercase tracking-[0.08em] text-muted-foreground"
          }
        >
          {inline(heading[2] ?? "")}
        </p>,
      );
      return;
    }

    const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
    if (bullet) {
      list.push(bullet[1] ?? "");
      return;
    }

    if (!line.trim()) {
      flushList();
      return;
    }

    flushList();
    blocks.push(
      <p key={`p-${blocks.length}`} className="text-[13px] leading-[1.7] text-muted-foreground">
        {inline(line)}
      </p>,
    );
  });

  flushList();
  if (fence) {
    blocks.push(
      <pre
        key="pre-end"
        className="overflow-x-auto rounded-[16px] bg-foreground/[0.05] px-4 py-3 font-mono text-[12.5px] leading-[1.6] text-foreground/90"
      >
        <code>{fenceLines().join("\n")}</code>
      </pre>,
    );
  }

  return <div className="space-y-3">{blocks}</div>;
}
