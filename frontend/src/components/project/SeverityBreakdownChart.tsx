import { PieChart, Pie, Cell } from "recharts";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "../ui/chart";
import type { ScanHistory } from "../../api/projects";

const chartConfig = {
  critical: {
    label: "Critical",
    color: "oklch(0.62 0.21 22)",
  },
  high: {
    label: "High",
    color: "oklch(0.72 0.17 55)",
  },
  medium: {
    label: "Medium",
    color: "oklch(0.82 0.14 92)",
  },
  low: {
    label: "Low",
    color: "oklch(0.75 0.09 200)",
  },
} satisfies ChartConfig;

export function SeverityBreakdownChart({
  scan,
  loading,
}: {
  scan?: ScanHistory | undefined;
  loading: boolean;
}) {
  const data = scan
    ? [
        { severity: "critical", label: "Critical", count: scan.critical_count ?? 0, fill: "oklch(0.62 0.21 22)" },
        { severity: "high", label: "High", count: scan.high_count ?? 0, fill: "oklch(0.72 0.17 55)" },
        { severity: "medium", label: "Medium", count: scan.medium_count ?? 0, fill: "oklch(0.82 0.14 92)" },
        { severity: "low", label: "Low", count: scan.low_count ?? 0, fill: "oklch(0.75 0.09 200)" },
      ].filter((item) => item.count > 0)
    : [];

  const totalIssues = scan?.total_issues ?? 0;

  return (
    <section className="glass-card flex flex-col justify-between rounded-[32px] p-6 sm:p-7 h-full">
      <div className="flex items-center justify-between">
        <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground">
          Severity Breakdown
        </h2>
        {scan && (
          <span className="text-[12.5px] text-muted-foreground">
            {totalIssues} {totalIssues === 1 ? "issue" : "issues"} total
          </span>
        )}
      </div>

      {loading ? (
        <div className="my-6 flex h-[160px] items-center justify-center">
          <div className="size-[120px] animate-pulse rounded-full border-8 border-foreground/10" />
        </div>
      ) : !scan || data.length === 0 ? (
        <div className="my-8 flex flex-col items-center justify-center text-center">
          <p className="text-[13.5px] text-muted-foreground">
            {!scan ? "No scan history available" : "No open vulnerabilities detected!"}
          </p>
        </div>
      ) : (
        <div className="my-2 flex flex-col items-center justify-center">
          <ChartContainer config={chartConfig} className="mx-auto aspect-square h-[160px]">
            <PieChart>
              <ChartTooltip
                cursor={false}
                content={<ChartTooltipContent hideLabel nameKey="label" />}
              />
              <Pie
                data={data}
                dataKey="count"
                nameKey="label"
                innerRadius={48}
                outerRadius={70}
                strokeWidth={2}
                stroke="oklch(0.13 0 0)"
              >
                {data.map((entry) => (
                  <Cell key={entry.severity} fill={entry.fill} />
                ))}
              </Pie>
            </PieChart>
          </ChartContainer>

          <div className="mt-3 flex flex-wrap justify-center gap-x-4 gap-y-1.5">
            {data.map((item) => (
              <div key={item.severity} className="flex items-center gap-1.5 text-[12px]">
                <span
                  className="size-[8px] rounded-full"
                  style={{ backgroundColor: item.fill }}
                />
                <span className="text-muted-foreground">{item.label}:</span>
                <span className="font-medium text-foreground">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
