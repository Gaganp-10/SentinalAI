import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ShieldCheck, ShieldAlert, ShieldOff, AlertCircle, Info } from "lucide-react";
import { getOwaspCoverage, type OwaspCategory } from "../../api/owasp";

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

const COVERAGE_ICON = {
  partial: ShieldAlert,
  limited: ShieldOff,
  none: ShieldOff,
};

const COVERAGE_COLOR = {
  partial: "text-amber-400",
  limited: "text-slate-400",
  none: "text-slate-600",
};

const SEVERITY_DOT = {
  partial: "bg-amber-400",
  limited: "bg-slate-400",
  none: "bg-slate-600",
};

function countBadge(cat: OwaspCategory) {
  const total = cat.open + cat.fixed;
  if (total === 0) return null;
  return (
    <span className="ml-auto flex shrink-0 items-center gap-1.5">
      {cat.open > 0 && (
        <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-[11px] font-medium text-red-400">
          {cat.open} open
        </span>
      )}
      {cat.fixed > 0 && (
        <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-400">
          {cat.fixed} fixed
        </span>
      )}
    </span>
  );
}

function CategoryRow({ cat, index }: { cat: OwaspCategory; index: number }) {
  const Icon = cat.open + cat.fixed > 0 ? ShieldAlert : COVERAGE_ICON[cat.coverage];
  const colorClass =
    cat.open + cat.fixed > 0 ? "text-red-400" : COVERAGE_COLOR[cat.coverage];
  const dotClass =
    cat.open + cat.fixed > 0 ? "bg-red-400" : SEVERITY_DOT[cat.coverage];

  return (
    <motion.li
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.35, delay: index * 0.035, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col gap-1.5 rounded-[14px] bg-foreground/[0.03] px-3.5 py-3 sm:px-4"
    >
      {/* Header row */}
      <div className="flex items-start gap-2.5">
        {/* Coverage dot */}
        <span className={`mt-[5px] size-[7px] shrink-0 rounded-full ${dotClass}`} />

        <span className="flex min-w-0 flex-1 flex-col gap-0.5">
          <span className="flex items-center gap-2 text-[13.5px] font-medium text-foreground">
            <span className="shrink-0 text-[11.5px] font-semibold uppercase tracking-wider text-muted-foreground/70">
              {cat.id}
            </span>
            {cat.name}
          </span>
          <span className="text-[11.5px] text-muted-foreground">{cat.coverage_note}</span>
        </span>

        {countBadge(cat)}
      </div>

      {/* CWE chips */}
      {cat.cwes.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1.5 pl-[19px]">
          {cat.cwes.map((cwe) => (
            <a
              key={cwe}
              href={`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`}
              target="_blank"
              rel="noopener noreferrer"
              className="icon-chip rounded-full px-2.5 py-0.5 text-[10.5px] text-sky-400 transition-colors hover:text-sky-300"
            >
              {cwe}
            </a>
          ))}
        </div>
      )}
    </motion.li>
  );
}

/* ------------------------------------------------------------------ */
/* Legend row                                                           */
/* ------------------------------------------------------------------ */
function Legend() {
  return (
    <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1.5 text-[11.5px] text-muted-foreground">
      <span className="flex items-center gap-1.5">
        <span className="size-[7px] rounded-full bg-red-400" /> Findings detected
      </span>
      <span className="flex items-center gap-1.5">
        <span className="size-[7px] rounded-full bg-amber-400" /> Partial scanner coverage
      </span>
      <span className="flex items-center gap-1.5">
        <span className="size-[7px] rounded-full bg-slate-400" /> Limited coverage
      </span>
      <span className="flex items-center gap-1.5">
        <span className="size-[7px] rounded-full bg-slate-600" /> Not assessable by static analysis
      </span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main component                                                       */
/* ------------------------------------------------------------------ */
export function OwaspCoveragePanel({ projectId }: { projectId: string }) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["projects", projectId, "owasp"],
    queryFn: () => getOwaspCoverage(projectId),
    retry: 1,
    staleTime: 30_000,
  });

  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="glass-field mt-6 rounded-[22px] p-5 sm:p-6"
      aria-label="OWASP Top 10:2021 Coverage"
    >
      {/* Title bar */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
            OWASP Top 10 : 2021 Coverage
          </h2>
          <p className="mt-0.5 text-[12.5px] text-muted-foreground">
            Static-analysis coverage per category — findings from the latest completed scan.
          </p>
        </div>

        {data && (
          <div className="flex shrink-0 flex-col items-end gap-0.5">
            {data.unmapped_findings > 0 && (
              <span className="flex items-center gap-1 text-[11.5px] text-muted-foreground">
                <Info className="size-[12px]" />
                {data.unmapped_findings} unmapped finding{data.unmapped_findings !== 1 ? "s" : ""}
              </span>
            )}
            <a
              href="https://owasp.org/Top10/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[11.5px] text-sky-500 underline-offset-2 hover:underline"
            >
              owasp.org/Top10
            </a>
          </div>
        )}
      </div>

      {/* Legend */}
      {data && <Legend />}

      {/* Loading */}
      {isLoading && (
        <div className="mt-5 space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <div
              key={i}
              className="h-[52px] animate-pulse rounded-[14px] bg-foreground/[0.04]"
            />
          ))}
        </div>
      )}

      {/* Error */}
      {isError && (
        <div className="mt-4 flex items-center gap-2 text-[13px] text-muted-foreground">
          <AlertCircle className="size-[14px]" />
          Could not load OWASP coverage.
        </div>
      )}

      {/* No completed scan yet */}
      {data && data.categories.every((c) => c.open + c.fixed === 0) && (
        <p className="mt-4 text-[13px] text-muted-foreground">
          Run a scan to see OWASP coverage results.
        </p>
      )}

      {/* Category list */}
      {data && (
        <ul className="mt-4 space-y-2">
          {data.categories.map((cat, i) => (
            <CategoryRow key={cat.id} cat={cat} index={i} />
          ))}
        </ul>
      )}
    </motion.section>
  );
}
