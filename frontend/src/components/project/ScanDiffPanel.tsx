import { useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  ExternalLink,
  FileQuestion,
  HelpCircle,
  Info,
  RotateCcw,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";
import type { ScanDiffResponse, DiffFindingItem } from "../../api/projects";

type CategoryKey = "all" | "new" | "resolved" | "persisting" | "regressed" | "not_comparable";

export function ScanDiffPanel({
  projectId,
  diff,
  loading,
  error,
  onClose,
}: {
  projectId: string;
  diff: ScanDiffResponse | null;
  loading: boolean;
  error?: string | null;
  onClose: () => void;
}) {
  const [selectedCategory, setSelectedCategory] = useState<CategoryKey>("all");
  const [expandedItems, setExpandedItems] = useState<Record<string, boolean>>({});

  if (loading) {
    return (
      <section className="glass-card mt-6 rounded-[32px] p-6 sm:p-7 animate-pulse border border-foreground/[0.08]">
        <div className="flex items-center justify-between">
          <div className="h-6 w-48 rounded-md bg-foreground/[0.08]" />
          <div className="h-8 w-8 rounded-full bg-foreground/[0.08]" />
        </div>
        <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-5">
          {[0, 1, 2, 3, 4].map((i) => (
            <div key={i} className="h-20 rounded-[20px] bg-foreground/[0.04]" />
          ))}
        </div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="glass-card mt-6 rounded-[32px] p-6 sm:p-7 border border-destructive/20 bg-destructive/[0.03]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-destructive">
            <AlertTriangle className="h-5 w-5" />
            <h2 className="text-[16px] font-semibold">Unable to compare scans</h2>
          </div>
          <button
            onClick={onClose}
            className="rounded-full p-1.5 text-muted-foreground hover:bg-foreground/[0.06] hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <p className="mt-3 text-[13.5px] text-muted-foreground">{error}</p>
      </section>
    );
  }

  if (!diff) return null;

  if (diff.baseline) {
    return (
      <section className="glass-card mt-6 rounded-[32px] p-6 sm:p-7 border border-foreground/[0.08]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-foreground">
            <Info className="h-5 w-5 text-primary" />
            <h2 className="text-[16px] font-semibold tracking-[-0.02em]">What changed</h2>
          </div>
          <button
            onClick={onClose}
            className="rounded-full p-1.5 text-muted-foreground hover:bg-foreground/[0.06] hover:text-foreground transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="mt-4 rounded-[20px] bg-foreground/[0.03] p-5 text-center sm:p-6 border border-foreground/[0.05]">
          <Clock className="mx-auto h-8 w-8 text-muted-foreground/60" />
          <h3 className="mt-2 text-[14.5px] font-medium text-foreground">Baseline Scan</h3>
          <p className="mt-1 text-[13px] text-muted-foreground max-w-md mx-auto">
            {diff.notes?.[0] || "This is your initial scan for this project. Regression and resolution comparisons will appear on subsequent scans."}
          </p>
        </div>
      </section>
    );
  }

  const summary = diff.summary ?? {
    new: 0,
    resolved: 0,
    persisting: 0,
    regressed: 0,
    not_comparable: 0,
  };

  const scoreBefore = diff.score_before ?? 0;
  const isScoreComparable = diff.score_after !== null && diff.score_after !== undefined;
  const scoreDiff = isScoreComparable ? (diff.score_after! - scoreBefore) : null;

  const toggleItem = (id: string) => {
    setExpandedItems((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const getFilteredItems = (): { category: string; item: DiffFindingItem }[] => {
    const list: { category: string; item: DiffFindingItem }[] = [];
    const items = diff.items || {};

    if (selectedCategory === "all" || selectedCategory === "regressed") {
      (items.regressed || []).forEach((item) => list.push({ category: "regressed", item }));
    }
    if (selectedCategory === "all" || selectedCategory === "new") {
      (items.new || []).forEach((item) => list.push({ category: "new", item }));
    }
    if (selectedCategory === "all" || selectedCategory === "resolved") {
      (items.resolved || []).forEach((item) => list.push({ category: "resolved", item }));
    }
    if (selectedCategory === "all" || selectedCategory === "persisting") {
      (items.persisting || []).forEach((item) => list.push({ category: "persisting", item }));
    }
    if (selectedCategory === "all" || selectedCategory === "not_comparable") {
      (items.not_comparable || []).forEach((item) => list.push({ category: "not_comparable", item }));
    }

    return list;
  };

  const filteredItems = getFilteredItems();

  return (
    <section className="glass-card mt-6 rounded-[32px] p-6 sm:p-7 border border-foreground/[0.1] shadow-xl relative overflow-hidden">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-primary" />
            <h2 className="text-[17px] font-semibold tracking-[-0.02em] text-foreground">
              What changed
            </h2>
            {summary.regressed > 0 && (
              <span className="inline-flex items-center gap-1 rounded-full bg-destructive/15 px-2.5 py-0.5 text-[11.5px] font-medium text-destructive border border-destructive/25">
                <AlertTriangle className="h-3 w-3" />
                {summary.regressed} regression{summary.regressed === 1 ? "" : "s"}
              </span>
            )}
          </div>
          <p className="mt-0.5 text-[12.5px] text-muted-foreground">
            Comparing against base scan
          </p>
        </div>

        <button
          onClick={onClose}
          className="rounded-full p-1.5 text-muted-foreground hover:bg-foreground/[0.06] hover:text-foreground transition-colors"
          title="Close comparison"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Score and Severity Delta Bar */}
      <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2">
        {/* Security Score Shift */}
        <div className="glass-field rounded-[20px] p-4 flex items-center justify-between border border-foreground/[0.06]">
          <div>
            <div className="text-[12px] font-medium uppercase tracking-[0.05em] text-muted-foreground">
              Security Score
            </div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="text-[20px] font-bold text-foreground/80">{scoreBefore}</span>
              <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" />
              {isScoreComparable ? (
                <span className="text-[22px] font-extrabold text-foreground">{diff.score_after}</span>
              ) : (
                <span className="text-[14px] font-semibold text-purple-400 uppercase tracking-wide">
                  not comparable
                </span>
              )}
            </div>
          </div>
          {isScoreComparable && scoreDiff !== null ? (
            <div
              className={`rounded-full px-3 py-1 text-[13px] font-semibold border ${
                scoreDiff > 0
                  ? "bg-[oklch(0.75_0.19_145)]/10 text-[oklch(0.75_0.19_145)] border-[oklch(0.75_0.19_145)]/20"
                  : scoreDiff < 0
                    ? "bg-destructive/10 text-destructive border-destructive/20"
                    : "bg-foreground/[0.06] text-muted-foreground border-foreground/[0.08]"
              }`}
            >
              {scoreDiff > 0 ? `+${scoreDiff}` : scoreDiff === 0 ? "No change" : scoreDiff}
            </div>
          ) : (
            <div className="rounded-full px-3 py-1 text-[12px] font-semibold border bg-purple-500/10 text-purple-400 border-purple-500/20">
              not comparable
            </div>
          )}
        </div>

        {/* Severity Delta */}
        {diff.severity_delta !== null && diff.severity_delta !== undefined ? (
          <div className="glass-field rounded-[20px] p-4 flex items-center justify-around border border-foreground/[0.06]">
            {(["critical", "high", "medium", "low"] as const).map((sev) => {
              const delta = diff.severity_delta?.[sev] ?? 0;
              return (
                <div key={sev} className="text-center">
                  <div className="text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                    {sev}
                  </div>
                  <div
                    className={`mt-1 text-[14px] font-bold ${
                      delta > 0
                        ? "text-destructive"
                        : delta < 0
                          ? "text-[oklch(0.75_0.19_145)]"
                          : "text-foreground/70"
                    }`}
                  >
                    {delta > 0 ? `+${delta}` : delta}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="glass-field rounded-[20px] p-4 flex flex-col items-center justify-center border border-foreground/[0.06] text-center">
            <div className="text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
              Severity Delta
            </div>
            <div className="mt-1 text-[14px] font-semibold text-purple-400 uppercase tracking-wide">
              not comparable
            </div>
          </div>
        )}
      </div>

      {/* Category Filter Chips */}
      <div className="mt-5 grid grid-cols-2 gap-2.5 sm:grid-cols-5">
        {/* Regressed */}
        <button
          type="button"
          onClick={() => setSelectedCategory(selectedCategory === "regressed" ? "all" : "regressed")}
          className={`flex flex-col items-start rounded-[18px] p-3 text-left transition-all border ${
            selectedCategory === "regressed"
              ? "bg-destructive/15 border-destructive/40 shadow-sm"
              : summary.regressed > 0
                ? "glass-field border-destructive/20 hover:border-destructive/40"
                : "glass-field border-foreground/[0.06] opacity-75"
          }`}
        >
          <div className="flex items-center gap-1.5 text-[11.5px] font-semibold uppercase tracking-[0.05em] text-destructive">
            <RotateCcw className="h-3.5 w-3.5" />
            Regressed
          </div>
          <div className="mt-1 text-[20px] font-extrabold text-foreground">
            {summary.regressed}
          </div>
          <div className="text-[11px] text-muted-foreground">Came back after fix</div>
        </button>

        {/* New */}
        <button
          type="button"
          onClick={() => setSelectedCategory(selectedCategory === "new" ? "all" : "new")}
          className={`flex flex-col items-start rounded-[18px] p-3 text-left transition-all border ${
            selectedCategory === "new"
              ? "bg-amber-500/15 border-amber-500/40 shadow-sm"
              : "glass-field border-foreground/[0.06] hover:border-amber-500/30"
          }`}
        >
          <div className="flex items-center gap-1.5 text-[11.5px] font-semibold uppercase tracking-[0.05em] text-amber-500">
            <ShieldAlert className="h-3.5 w-3.5" />
            New
          </div>
          <div className="mt-1 text-[20px] font-extrabold text-foreground">
            {summary.new}
          </div>
          <div className="text-[11px] text-muted-foreground">First time seen</div>
        </button>

        {/* Resolved */}
        <button
          type="button"
          onClick={() => setSelectedCategory(selectedCategory === "resolved" ? "all" : "resolved")}
          className={`flex flex-col items-start rounded-[18px] p-3 text-left transition-all border ${
            selectedCategory === "resolved"
              ? "bg-[oklch(0.75_0.19_145)]/15 border-[oklch(0.75_0.19_145)]/40 shadow-sm"
              : "glass-field border-foreground/[0.06] hover:border-[oklch(0.75_0.19_145)]/30"
          }`}
        >
          <div className="flex items-center gap-1.5 text-[11.5px] font-semibold uppercase tracking-[0.05em] text-[oklch(0.75_0.19_145)]">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Resolved
          </div>
          <div className="mt-1 text-[20px] font-extrabold text-foreground">
            {summary.resolved}
          </div>
          <div className="text-[11px] text-muted-foreground">Fixed & verified</div>
        </button>

        {/* Persisting */}
        <button
          type="button"
          onClick={() => setSelectedCategory(selectedCategory === "persisting" ? "all" : "persisting")}
          className={`flex flex-col items-start rounded-[18px] p-3 text-left transition-all border ${
            selectedCategory === "persisting"
              ? "bg-foreground/[0.1] border-foreground/30 shadow-sm"
              : "glass-field border-foreground/[0.06] hover:border-foreground/20"
          }`}
        >
          <div className="flex items-center gap-1.5 text-[11.5px] font-semibold uppercase tracking-[0.05em] text-muted-foreground">
            <Clock className="h-3.5 w-3.5" />
            Persisting
          </div>
          <div className="mt-1 text-[20px] font-extrabold text-foreground">
            {summary.persisting}
          </div>
          <div className="text-[11px] text-muted-foreground">Still present</div>
        </button>

        {/* Not Comparable */}
        <button
          type="button"
          onClick={() =>
            setSelectedCategory(selectedCategory === "not_comparable" ? "all" : "not_comparable")
          }
          className={`flex flex-col items-start rounded-[18px] p-3 text-left transition-all border col-span-2 sm:col-span-1 ${
            selectedCategory === "not_comparable"
              ? "bg-purple-500/15 border-purple-500/40 shadow-sm"
              : summary.not_comparable > 0
                ? "glass-field border-purple-500/25 hover:border-purple-500/40"
                : "glass-field border-foreground/[0.06] opacity-75"
          }`}
        >
          <div className="flex items-center gap-1.5 text-[11.5px] font-semibold uppercase tracking-[0.05em] text-purple-400">
            <HelpCircle className="h-3.5 w-3.5" />
            Not Comparable
          </div>
          <div className="mt-1 text-[20px] font-extrabold text-foreground">
            {summary.not_comparable}
          </div>
          <div className="text-[11px] text-muted-foreground">Tool/file skipped</div>
        </button>
      </div>

      {/* Notes / Honesty alerts */}
      {diff.notes && diff.notes.length > 0 && (
        <div className="mt-4 rounded-[18px] bg-amber-500/10 p-3.5 border border-amber-500/20 text-[12.5px] text-amber-200 flex items-start gap-2.5">
          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" />
          <div className="space-y-1">
            {diff.notes.map((note, i) => (
              <p key={i}>{note}</p>
            ))}
          </div>
        </div>
      )}

      {/* Items List */}
      <div className="mt-5 space-y-2.5">
        <div className="flex items-center justify-between px-1">
          <div className="text-[13px] font-medium text-muted-foreground">
            Showing {filteredItems.length} {selectedCategory === "all" ? "total" : selectedCategory} items
          </div>
          {selectedCategory !== "all" && (
            <button
              onClick={() => setSelectedCategory("all")}
              className="text-[12px] text-primary hover:underline"
            >
              Show all categories
            </button>
          )}
        </div>

        {filteredItems.length === 0 ? (
          <div className="glass-field rounded-[18px] p-6 text-center text-[13px] text-muted-foreground border border-foreground/[0.06]">
            No findings match this filter.
          </div>
        ) : (
          filteredItems.map(({ category, item }) => {
            const isExpanded = Boolean(expandedItems[item.id]);

            return (
              <div
                key={item.id}
                className="glass-field rounded-[18px] p-3.5 transition-all border border-foreground/[0.06] hover:border-foreground/[0.12]"
              >
                <div
                  className="flex flex-wrap items-center gap-x-3 gap-y-1.5 cursor-pointer"
                  onClick={() => toggleItem(item.id)}
                >
                  {/* Category Chip */}
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-[0.04em] ${
                      category === "regressed"
                        ? "bg-destructive/15 text-destructive border border-destructive/25"
                        : category === "new"
                          ? "bg-amber-500/15 text-amber-400 border border-amber-500/25"
                          : category === "resolved"
                            ? "bg-[oklch(0.75_0.19_145)]/15 text-[oklch(0.75_0.19_145)] border border-[oklch(0.75_0.19_145)]/25"
                            : category === "not_comparable"
                              ? "bg-purple-500/15 text-purple-400 border border-purple-500/25"
                              : "bg-foreground/[0.08] text-muted-foreground"
                    }`}
                  >
                    {category === "not_comparable" ? "not comparable" : category}
                  </span>

                  {/* Severity Badge */}
                  <span
                    className={`rounded-md px-2 py-0.5 text-[11px] font-medium uppercase tracking-[0.05em] ${
                      item.severity.toLowerCase() === "critical"
                        ? "bg-destructive/20 text-destructive"
                        : item.severity.toLowerCase() === "high"
                          ? "bg-amber-500/20 text-amber-400"
                          : "bg-foreground/[0.08] text-muted-foreground"
                    }`}
                  >
                    {item.severity}
                  </span>

                  {/* Finding Type */}
                  <span className="text-[13.5px] font-medium text-foreground">
                    {item.type}
                  </span>

                  {/* Resolved via apply-fix badge */}
                  {item.note?.includes("apply-fix") && (
                    <span className="rounded-full bg-[oklch(0.75_0.19_145)]/15 px-2 py-0.5 text-[11px] text-[oklch(0.75_0.19_145)] border border-[oklch(0.75_0.19_145)]/25">
                      ✓ resolved via apply-fix
                    </span>
                  )}

                  {/* File & Line */}
                  <span className="text-[12.5px] text-muted-foreground font-mono ml-auto">
                    {item.file}:{item.line}
                  </span>

                  {/* Expand Chevron */}
                  <button className="text-muted-foreground hover:text-foreground">
                    {isExpanded ? (
                      <ChevronUp className="h-4 w-4" />
                    ) : (
                      <ChevronDown className="h-4 w-4" />
                    )}
                  </button>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="mt-3.5 pt-3 border-t border-foreground/[0.06] text-[12.5px] space-y-2">
                    {item.cwe && (
                      <div className="flex items-center gap-2">
                        <span className="text-muted-foreground font-medium">CWE:</span>
                        <span className="font-mono text-foreground">{item.cwe}</span>
                      </div>
                    )}

                    {item.source_tools && item.source_tools.length > 0 && (
                      <div className="flex items-center gap-2">
                        <span className="text-muted-foreground font-medium">Detectors:</span>
                        <div className="flex gap-1.5">
                          {item.source_tools.map((t) => (
                            <span
                              key={t}
                              className="rounded px-2 py-0.5 bg-foreground/[0.06] font-mono text-[11px] text-foreground"
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Dependency Version Information */}
                    {(item.package_name || item.old_version || item.new_version) && (
                      <div className="rounded-lg bg-foreground/[0.03] p-2.5 space-y-1">
                        <div className="font-medium text-foreground">
                          Package: <span className="font-mono">{item.package_name}</span>
                        </div>
                        {item.old_version && (
                          <div className="text-muted-foreground">
                            Base Version: <span className="font-mono text-foreground">{item.old_version}</span>
                          </div>
                        )}
                        {item.new_version && (
                          <div className="text-muted-foreground">
                            Target Version: <span className="font-mono text-foreground">{item.new_version}</span>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Notes & Reasons */}
                    {item.note && (
                      <div className="text-foreground/90 font-medium bg-foreground/[0.03] p-2 rounded-md">
                        ℹ️ {item.note}
                      </div>
                    )}

                    {item.reason && (
                      <div className="text-purple-300 bg-purple-500/10 p-2 rounded-md border border-purple-500/20">
                        Reason: {item.reason}
                      </div>
                    )}

                    {/* Link to vulnerability detail page if active in latest scan */}
                    {item.vulnerability_id && (
                      <div className="pt-1">
                        <Link
                          to="/projects/$projectId/vulnerabilities/$vulnId"
                          params={{ projectId, vulnId: item.vulnerability_id }}
                          className="inline-flex items-center gap-1.5 text-primary hover:underline font-medium text-[12.5px]"
                        >
                          View vulnerability details <ExternalLink className="h-3.5 w-3.5" />
                        </Link>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
