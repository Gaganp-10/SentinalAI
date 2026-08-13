import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Cell } from "recharts";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "../ui/chart";
import type { ScanHistory } from "../../api/projects";

function getWorstSeverityColor(scan: ScanHistory): { color: string; severity: string } {
  if ((scan.critical_count ?? 0) > 0) {
    return { color: "oklch(0.62 0.21 22)", severity: "Critical" };
  }
  if ((scan.high_count ?? 0) > 0) {
    return { color: "oklch(0.72 0.17 55)", severity: "High" };
  }
  if ((scan.medium_count ?? 0) > 0) {
    return { color: "oklch(0.82 0.14 92)", severity: "Medium" };
  }
  if ((scan.low_count ?? 0) > 0) {
    return { color: "oklch(0.75 0.09 200)", severity: "Low" };
  }
  return { color: "oklch(0.75 0.19 145)", severity: "Clean" };
}

function formatShortDate(dateStr: string): string {
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return dateStr;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

const chartConfig = {
  total_issues: {
    label: "Total Issues",
    color: "oklch(0.72 0.17 55)",
  },
} satisfies ChartConfig;

export function ScanTimeline({
  scans,
  loading,
}: {
  scans: ScanHistory[];
  loading: boolean;
}) {
  // Chronological order (oldest to newest) for timeline
  const sortedScans = [...scans].sort(
    (a, b) => new Date(a.scan_time).getTime() - new Date(b.scan_time).getTime(),
  );

  const chartData = sortedScans.map((scan) => {
    const { color, severity } = getWorstSeverityColor(scan);
    return {
      id: scan.id,
      dateLabel: formatShortDate(scan.scan_time),
      issues: scan.total_issues ?? 0,
      fill: color,
      worstSeverity: severity,
      status: scan.status,
    };
  });

  return (
    <section className="glass-card mt-6 rounded-[32px] p-6 sm:p-7">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
            Scan History Timeline
          </h2>
          <p className="mt-1 text-[13px] text-muted-foreground">
            Historical issue counts per scan (bar color indicates highest severity found)
          </p>
        </div>
      </div>

      {loading ? (
        <div className="mt-6 h-[180px] animate-pulse rounded-[18px] bg-foreground/[0.06]" />
      ) : chartData.length === 0 ? (
        <p className="mt-4 text-[13.5px] text-muted-foreground">
          No historical scan data yet.
        </p>
      ) : (
        <div className="mt-6">
          <ChartContainer config={chartConfig} className="h-[200px] w-full">
            <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid vertical={false} stroke="oklch(1 0 0 / 8%)" />
              <XAxis
                dataKey="dateLabel"
                tickLine={false}
                tickMargin={8}
                axisLine={false}
                tickFormatter={(value) => value.split(",")[0]} // Show just date e.g. "Aug 11"
              />
              <YAxis
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
                tickMargin={8}
              />
              <ChartTooltip
                cursor={{ fill: "oklch(1 0 0 / 5%)" }}
                content={<ChartTooltipContent hideIndicator nameKey="issues" />}
              />
              <Bar dataKey="issues" radius={[6, 6, 0, 0]}>
                {chartData.map((entry) => (
                  <Cell key={entry.id} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ChartContainer>
        </div>
      )}
    </section>
  );
}
