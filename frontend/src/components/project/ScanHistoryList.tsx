import { formatScanTime } from "../../api/files";
import type { ScanHistory } from "../../api/projects";

export function ScanHistoryList({
  scans,
  loading,
  error,
}: {
  scans: ScanHistory[];
  loading: boolean;
  error?: string | undefined;
}) {
  const sorted = [...scans].sort(
    (a, b) => new Date(b.scan_time).getTime() - new Date(a.scan_time).getTime(),
  );

  return (
    <section className="glass-card mt-6 rounded-[32px] p-6 sm:p-7">
      <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
        Scan history
      </h2>

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
          {sorted.map((scan) => (
            <li
              key={String(scan.id)}
              className="glass-field flex flex-wrap items-center gap-x-4 gap-y-1 rounded-[18px] px-4 py-3"
            >
              <span className="text-[13.5px] text-foreground">
                {formatScanTime(scan.scan_time)}
              </span>
              <span className="text-[13px] text-muted-foreground">
                {scan.total_issues} {scan.total_issues === 1 ? "issue" : "issues"}
              </span>
              <span className="icon-chip ml-auto rounded-full px-3 py-1 text-[11.5px] uppercase tracking-[0.06em] text-muted-foreground">
                {scan.status}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
