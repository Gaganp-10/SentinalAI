import { motion } from "framer-motion";
import type { ScanHistory } from "../../api/projects";

// NOTE: Security score calculation is currently performed client-side.
// Ideally, this calculation should move to the backend API in the future.
export function computeSecurityScore(scan?: ScanHistory | null): number | null {
  if (!scan || scan.status?.toLowerCase() !== "completed") {
    return null;
  }
  const critical = scan.critical_count ?? 0;
  const high = scan.high_count ?? 0;
  const medium = scan.medium_count ?? 0;
  const low = scan.low_count ?? 0;

  const penalty = critical * 15 + high * 8 + medium * 3 + low * 1;
  return Math.max(0, 100 - penalty);
}

export function getScoreColor(score: number): {
  stroke: string;
  badgeTone: string;
  label: string;
} {
  if (score > 80) {
    return {
      stroke: "oklch(0.72 0.19 145)", // Green
      badgeTone: "text-[oklch(0.75_0.19_145)] bg-[oklch(0.75_0.19_145)]/10 border-[oklch(0.75_0.19_145)]/20",
      label: "Good",
    };
  }
  if (score >= 50) {
    return {
      stroke: "oklch(0.78 0.16 72)", // Amber
      badgeTone: "text-[oklch(0.82_0.15_75)] bg-[oklch(0.82_0.15_75)]/10 border-[oklch(0.82_0.15_75)]/20",
      label: "Moderate Risk",
    };
  }
  return {
    stroke: "oklch(0.62 0.21 22)", // Red
    badgeTone: "text-destructive bg-destructive/10 border-destructive/20",
    label: "High Risk",
  };
}

export function SecurityScoreGauge({
  scan,
  loading,
}: {
  scan?: ScanHistory | undefined;
  loading: boolean;
}) {
  const score = computeSecurityScore(scan);
  const colorInfo = score !== null ? getScoreColor(score) : null;

  // Gauge calculation constants
  const size = 160;
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Use a 270-degree arc (75% of circumference)
  const arcLength = circumference * 0.75;
  const strokeDashoffset =
    score !== null ? arcLength - (arcLength * score) / 100 : arcLength;

  return (
    <section className="glass-card flex flex-col items-center justify-center rounded-[32px] p-6 sm:p-7 text-center h-full">
      <h2 className="text-[16px] font-semibold tracking-[-0.02em] text-foreground w-full text-left">
        Security Score
      </h2>

      {loading ? (
        <div className="my-6 flex flex-col items-center justify-center">
          <div className="size-[140px] animate-pulse rounded-full border-8 border-foreground/10" />
        </div>
      ) : score === null ? (
        <div className="my-8 flex flex-col items-center justify-center">
          <div className="icon-chip flex size-[64px] items-center justify-center rounded-full text-muted-foreground mb-3">
            <span className="text-[20px] font-semibold">--</span>
          </div>
          <p className="text-[13.5px] text-muted-foreground">
            No completed scan available
          </p>
        </div>
      ) : (
        <div className="relative my-4 flex flex-col items-center justify-center">
          <svg
            width={size}
            height={size}
            className="-rotate-225 transform"
            viewBox={`0 0 ${size} ${size}`}
          >
            {/* Background Arc */}
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="transparent"
              stroke="oklch(1 0 0 / 10%)"
              strokeWidth={strokeWidth}
              strokeDasharray={`${arcLength} ${circumference}`}
              strokeLinecap="round"
            />
            {/* Progress Arc */}
            <motion.circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="transparent"
              stroke={colorInfo?.stroke}
              strokeWidth={strokeWidth}
              strokeDasharray={`${arcLength} ${circumference}`}
              initial={{ strokeDashoffset: arcLength }}
              animate={{ strokeDashoffset }}
              transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
              strokeLinecap="round"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-[36px] font-bold tracking-tight text-foreground">
              {score}
            </span>
            <span className="text-[11px] uppercase tracking-[0.08em] text-muted-foreground">
              out of 100
            </span>
          </div>
          {colorInfo && (
            <div
              className={`mt-2 inline-flex items-center rounded-full border px-3 py-0.5 text-[12px] font-medium ${colorInfo.badgeTone}`}
            >
              {colorInfo.label}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
