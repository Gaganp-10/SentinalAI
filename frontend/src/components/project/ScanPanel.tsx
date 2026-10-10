import { Link } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { CheckCircle2, Loader2, Radar, ShieldAlert } from "lucide-react";
import type { ScanHistory } from "../../api/projects";
import { PrimaryButton } from "../auth/PrimaryButton";

const SEVERITIES = [
  { key: "critical_count", label: "Critical", tone: "text-destructive" },
  { key: "high_count", label: "High", tone: "text-[oklch(0.72_0.15_60)]" },
  { key: "medium_count", label: "Medium", tone: "text-[oklch(0.82_0.13_95)]" },
  { key: "low_count", label: "Low", tone: "text-muted-foreground" },
] as const;

export function ScanPanel({
  projectId,
  hasFiles,
  scan,
  starting,
  error,
  onScan,
}: {
  projectId: string;
  hasFiles: boolean;
  scan?: ScanHistory | undefined;
  starting: boolean;
  error?: string | undefined;
  onScan: () => void;
}) {
  const status = scan?.status?.toLowerCase();
  const inProgress = starting || status === "pending" || status === "running";
  const completed = status === "completed";
  const failed = status === "failed";

  return (
    <section className="glass-card mt-6 rounded-[32px] p-6 sm:p-7">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
            Vulnerability scan
          </h2>
          <p className="mt-1.5 text-[13.5px] text-muted-foreground">
            {hasFiles
              ? "Run Bandit, Semgrep and SentinelAI's AST rules across the uploaded files."
              : "Upload at least one file before running a scan."}
          </p>
        </div>

        <div className="w-full sm:w-[190px]">
          <PrimaryButton
            type="button"
            onClick={onScan}
            disabled={!hasFiles || inProgress}
            loading={inProgress}
          >
            <Radar className="size-[17px]" />
            {inProgress ? "Scanning" : "Scan Now"}
          </PrimaryButton>
        </div>
      </div>

      {inProgress && (
        <div className="glass-field mt-6 flex items-center gap-3 rounded-[18px] px-4 py-4">
          <Loader2 className="size-[17px] animate-spin text-foreground" />
          <p className="text-[13.5px] text-foreground">
            Scan {status ?? "starting"}
            <span className="animate-pulse">…</span>
          </p>
        </div>
      )}

      {failed && (
        <div className="glass-field mt-6 flex items-start gap-3 rounded-[18px] px-4 py-4">
          <ShieldAlert className="mt-0.5 size-[17px] shrink-0 text-destructive" />
          <p className="text-[13.5px] text-destructive">
            Scan failed on the backend (status: {scan?.status}). Check the file contents and try
            again.
          </p>
        </div>
      )}

      {completed && scan && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
          className="glass-field mt-6 rounded-[22px] p-5"
        >
          <div className="flex items-center gap-2.5">
            {scan.warnings && scan.warnings.length > 0 ? (
              <ShieldAlert className="size-[18px] text-amber-400" />
            ) : (
              <CheckCircle2 className="size-[18px] text-foreground" />
            )}
            <p className="text-[14.5px] font-medium text-foreground">
              {scan.warnings && scan.warnings.length > 0
                ? `Scan completed with warnings — ${scan.total_issues} ${scan.total_issues === 1 ? "issue" : "issues"} found`
                : `Scan complete — ${scan.total_issues} ${scan.total_issues === 1 ? "issue" : "issues"} found`}
            </p>
          </div>

          {scan.warnings && scan.warnings.length > 0 && (
            <div className="mt-4 rounded-[16px] border border-amber-500/30 bg-amber-500/10 p-3.5 text-[13px]">
              <p className="font-semibold text-amber-300">
                Scan Warnings ({scan.warnings.length})
              </p>
              <ul className="mt-1.5 list-disc space-y-1 pl-5 text-[12.5px] text-amber-200/90">
                {scan.warnings.map((w, idx) => (
                  <li key={idx}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          {scan.dependency_summary && (
            <div className="mt-3 flex flex-wrap items-center gap-2 text-[12.5px] text-muted-foreground">
              <span className="font-medium text-foreground">Dependencies:</span>
              <span>{scan.dependency_summary.checked} checked</span>
              {scan.dependency_summary.not_checked > 0 && (
                <span className="text-amber-400">· {scan.dependency_summary.not_checked} not checked</span>
              )}
              <span>· across {scan.dependency_summary.manifests} {scan.dependency_summary.manifests === 1 ? "manifest" : "manifests"}</span>
            </div>
          )}

          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {SEVERITIES.map((s) => (
              <div key={s.key} className="rounded-[16px] bg-foreground/[0.05] px-3.5 py-3">
                <p className={`text-[19px] font-semibold ${s.tone}`}>{scan[s.key] ?? 0}</p>
                <p className="mt-0.5 text-[12px] text-muted-foreground">{s.label}</p>
              </div>
            ))}
          </div>

          <Link
            to="/projects/$projectId/vulnerabilities"
            params={{ projectId }}
            className="social-btn mt-5 inline-flex rounded-full px-5 py-2.5 text-[13.5px] font-medium text-foreground"
          >
            View full results
          </Link>
        </motion.div>
      )}

      {error && (
        <p role="alert" className="mt-5 text-[13px] text-destructive">
          {error}
        </p>
      )}
    </section>
  );
}
