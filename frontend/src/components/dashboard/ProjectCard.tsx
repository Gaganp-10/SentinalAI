import { motion } from "framer-motion";
import { Link } from "@tanstack/react-router";
import { ChevronRight, ShieldCheck } from "lucide-react";
import { formatScanDate, latestScan, type Project, type ScanHistory } from "../../api/projects";
import { computeSecurityScore, getScoreColor } from "../project/SecurityScoreGauge";

const SEVERITIES = [
  { key: "critical_count", label: "Critical", color: "oklch(0.62 0.21 22)" },
  { key: "high_count", label: "High", color: "oklch(0.72 0.17 55)" },
  { key: "medium_count", label: "Medium", color: "oklch(0.82 0.14 92)" },
  { key: "low_count", label: "Low", color: "oklch(0.75 0.09 200)" },
] as const;

export function ProjectCard({
  project,
  scans,
  scansLoading,
  index,
}: {
  project: Project;
  scans: ScanHistory[] | undefined;
  scansLoading: boolean;
  index: number;
}) {
  const scan = latestScan(scans);
  const score = computeSecurityScore(scan);
  const colorInfo = score !== null ? getScoreColor(score) : null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.05 * index, ease: [0.16, 1, 0.3, 1] }}
    >
      <Link
        to="/projects/$projectId"
        params={{ projectId: String(project.id) }}
        className="glass-card group flex h-full flex-col rounded-[26px] p-5 transition-transform duration-300 hover:-translate-y-1"
      >
        <div className="flex items-start gap-3">
          <span className="icon-chip flex size-[38px] shrink-0 items-center justify-center rounded-full text-foreground">
            <ShieldCheck className="size-[18px]" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h3 className="truncate text-[16.5px] font-semibold tracking-[-0.02em] text-foreground">
                {project.project_name}
              </h3>
              {score !== null && colorInfo && (
                <span
                  className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${colorInfo.badgeTone}`}
                >
                  Score: {score}
                </span>
              )}
            </div>
            <p className="mt-0.5 text-[12.5px] text-muted-foreground">
              Last scan: {scan ? formatScanDate(scan.scan_time) : "No scans yet"}
            </p>
          </div>
          <ChevronRight className="mt-2 size-[17px] shrink-0 text-muted-foreground transition-transform duration-300 group-hover:translate-x-0.5" />
        </div>

        <div className="mt-5 border-t border-border pt-4">
          {scansLoading ? (
            <div className="h-[26px] w-2/3 animate-pulse rounded-full bg-foreground/10" />
          ) : scan ? (
            <div className="flex flex-wrap items-center gap-2">
              {SEVERITIES.map((s) => (
                <span
                  key={s.key}
                  className="glass-field flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[12px] text-foreground"
                >
                  <span
                    aria-hidden="true"
                    className="size-[7px] rounded-full"
                    style={{ backgroundColor: s.color }}
                  />
                  {s.label} {scan[s.key] ?? 0}
                </span>
              ))}
              <span className="ml-auto text-[12px] text-muted-foreground">
                {scan.total_issues} total
              </span>
            </div>
          ) : (
            <p className="text-[12.5px] text-muted-foreground">Not scanned yet</p>
          )}
        </div>
      </Link>
    </motion.div>
  );
}
