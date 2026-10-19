import { GitCompare } from "lucide-react";
import { formatScanTime } from "../../api/files";
import type { ScanHistory } from "../../api/projects";

export function ScanHistoryList({
  scans,
  loading,
  error,
  activeCompareScanId,
  onCompare,
}: {
  scans: ScanHistory[];
  loading: boolean;
  error?: string | undefined;
  activeCompareScanId?: string | null;
  onCompare?: (scanId: string) => void;
}) {
  const sorted = [...scans].sort(
    (a, b) => new Date(b.scan_time).getTime() - new Date(a.scan_time).getTime(),
  );

  return (
    <section className="glass-card mt-6 rounded-[32px] p-6 sm:p-7">
      <div className="flex items-center justify-between">
        <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
          Scan history
        </h2>
        <span className="text-[12.5px] text-muted-foreground">
          {sorted.length} {sorted.length === 1 ? "scan" : "scans"} recorded
        </span>
      </div>

      {loading && (
        <div className="mt-5 space-y-3">
          {[0, 1].map((i) => (
            <div key={i} className="h-[52px] animate-pulse rounded-[18px] bg-foreground/[0.06]" />
          ))}
        </div>
      )}

      {error && !loading && (
        <p role="alert" className="mt-4 text-[13.5px] text-destructive">
          {error}
        </p>
      )}

      {!loading && !error && sorted.length === 0 && (
        <p className="mt-4 text-[13.5px] text-muted-foreground">
          No scans yet — run your first scan above.
        </p>
      )}

      {!loading && sorted.length > 0 && (
        <ul className="mt-5 space-y-3">
          {sorted.map((scan, index) => {
            const isCompleted = scan.status?.toLowerCase() === "completed";
            const isActive = activeCompareScanId === String(scan.id);

            return (
              <li
                key={String(scan.id)}
                className={`glass-field flex flex-wrap items-center gap-x-4 gap-y-2 rounded-[18px] px-4 py-3 transition-colors ${
                  isActive ? "border-primary/40 bg-primary/[0.04]" : ""
                }`}
              >
                <span className="text-[13.5px] text-foreground font-medium">
                  {formatScanTime(scan.scan_time)}
                </span>
                <span className="text-[13px] text-muted-foreground">
                  {scan.total_issues} {scan.total_issues === 1 ? "issue" : "issues"}
                </span>

                <div className="ml-auto flex items-center gap-2.5">
                  {isCompleted && onCompare && (
                    <button
                      type="button"
                      onClick={() => onCompare(String(scan.id))}
                      className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[12px] font-medium transition-all border ${
                        isActive
                          ? "bg-primary text-primary-foreground border-primary"
                          : "border-foreground/[0.1] hover:border-primary/40 hover:bg-primary/10 text-foreground"
                      }`}
                      title="Compare this scan with the previous scan"
                    >
                      <GitCompare className="h-3.5 w-3.5" />
                      {isActive ? "Comparing" : "Compare with previous"}
                    </button>
                  )}

                  <span className="icon-chip rounded-full px-3 py-1 text-[11.5px] uppercase tracking-[0.06em] text-muted-foreground">
                    {scan.status}
                  </span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
