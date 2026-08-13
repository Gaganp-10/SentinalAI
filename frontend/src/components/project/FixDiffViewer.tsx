import { useMemo } from "react";
import { diffLines, type Change } from "diff";

export type DiffLine = {
  type: "added" | "removed" | "unchanged";
  oldLineNumber?: number;
  newLineNumber?: number;
  content: string;
};

export function computeLineDiff(originalCode: string, suggestedFix: string): DiffLine[] {
  if (!originalCode && !suggestedFix) return [];

  const changes: Change[] = diffLines(originalCode || "", suggestedFix || "");
  const result: DiffLine[] = [];

  let oldCounter = 1;
  let newCounter = 1;

  for (const change of changes) {
    // Split change value into lines, stripping trailing empty line if it was split from a trailing newline
    const rawLines = change.value.split("\n");
    if (rawLines.length > 0 && rawLines[rawLines.length - 1] === "") {
      rawLines.pop();
    }

    for (const line of rawLines) {
      if (change.added) {
        result.push({
          type: "added",
          newLineNumber: newCounter++,
          content: line,
        });
      } else if (change.removed) {
        result.push({
          type: "removed",
          oldLineNumber: oldCounter++,
          content: line,
        });
      } else {
        result.push({
          type: "unchanged",
          oldLineNumber: oldCounter++,
          newLineNumber: newCounter++,
          content: line,
        });
      }
    }
  }

  return result;
}

export function FixDiffViewer({
  originalCode,
  suggestedFix,
  filename,
}: {
  originalCode: string;
  suggestedFix: string;
  filename?: string | null | undefined;
}) {
  const diffLinesData = useMemo(
    () => computeLineDiff(originalCode, suggestedFix),
    [originalCode, suggestedFix]
  );

  return (
    <div className="glass-field overflow-hidden rounded-[18px] border border-border">
      <div className="flex items-center justify-between border-b border-border/60 bg-foreground/[0.03] px-4 py-2.5 text-[12.5px]">
        <span className="font-mono text-muted-foreground">
          {filename ? `Diff — ${filename}` : "Proposed Changes Diff"}
        </span>
        <div className="flex items-center gap-3 text-[11.5px]">
          <span className="flex items-center gap-1 text-destructive">
            <span className="inline-block size-2 rounded-full bg-destructive" />
            Original (- )
          </span>
          <span className="flex items-center gap-1 text-[oklch(0.75_0.19_145)]">
            <span className="inline-block size-2 rounded-full bg-[oklch(0.75_0.19_145)]" />
            Suggested Fix (+ )
          </span>
        </div>
      </div>

      <div className="overflow-x-auto p-3 font-mono text-[12.5px] leading-[1.7]">
        <table className="w-full border-collapse">
          <tbody>
            {diffLinesData.map((line, index) => {
              const isAdded = line.type === "added";
              const isRemoved = line.type === "removed";

              let lineBgClass = "hover:bg-foreground/[0.02]";
              let marker = " ";
              let markerClass = "text-muted-foreground/40";

              if (isRemoved) {
                lineBgClass = "bg-destructive/15 text-destructive/90";
                marker = "-";
                markerClass = "text-destructive font-bold";
              } else if (isAdded) {
                lineBgClass = "bg-[oklch(0.75_0.19_145)]/15 text-[oklch(0.85_0.15_145)]";
                marker = "+";
                markerClass = "text-[oklch(0.75_0.19_145)] font-bold";
              }

              return (
                <tr key={index} className={`transition-colors ${lineBgClass}`}>
                  <td className="w-9 select-none pr-2 text-right text-[11px] text-muted-foreground/40">
                    {line.oldLineNumber ?? ""}
                  </td>
                  <td className="w-9 select-none pr-3 text-right text-[11px] text-muted-foreground/40">
                    {line.newLineNumber ?? ""}
                  </td>
                  <td className={`w-6 select-none text-center ${markerClass}`}>
                    {marker}
                  </td>
                  <td className="whitespace-pre pl-1">{line.content || " "}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
