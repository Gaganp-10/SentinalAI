import React, { useEffect, useId, useState } from 'react';
import { scoreRingColor } from '../../utils/securityScore';

const SIZE = 132;
const STROKE = 8;
const R = (SIZE - STROKE) / 2;
const C = 2 * Math.PI * R;

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(mq.matches);
    const onChange = () => setReduced(mq.matches);
    mq.addEventListener?.('change', onChange);
    return () => mq.removeEventListener?.('change', onChange);
  }, []);
  return reduced;
}

function ProgressRing({
  value,
  max = 100,
  color,
  center,
  label,
  inProgress = false,
}) {
  const reduced = usePrefersReducedMotion();
  const gradId = useId().replace(/:/g, '');
  const ratio = max > 0 ? value / max : 0;
  const target = Math.min(1, Math.max(0, inProgress && ratio < 0.15 ? 0.55 : ratio));
  const [progress, setProgress] = useState(reduced ? target : 0);

  useEffect(() => {
    if (reduced) {
      setProgress(target);
      return undefined;
    }
    setProgress(0);
    let raf = 0;
    const start = performance.now();
    const duration = 800;
    const tick = (now) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - (1 - t) ** 3;
      setProgress(target * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, reduced]);

  const offset = C * (1 - progress);

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative" style={{ width: SIZE, height: SIZE }}>
        <svg width={SIZE} height={SIZE} className="-rotate-90" aria-hidden>
          <defs>
            <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={color} stopOpacity="0.85" />
              <stop offset="100%" stopColor={color} stopOpacity="1" />
            </linearGradient>
          </defs>
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={R}
            fill="none"
            stroke="var(--border-glow)"
            strokeWidth={STROKE}
          />
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={R}
            fill="none"
            stroke={`url(#${gradId})`}
            strokeWidth={STROKE}
            strokeLinecap="round"
            strokeDasharray={C}
            strokeDashoffset={offset}
            style={{
              filter: `drop-shadow(0 0 6px ${color})`,
              opacity: inProgress ? 0.85 : 1,
            }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          {center}
        </div>
      </div>
      <p className="text-[10px] font-sans font-semibold uppercase tracking-[0.14em] text-[var(--text-secondary)]">
        {label}
      </p>
    </div>
  );
}

/**
 * Dual rings: Security Score + Files Scanned.
 */
const ScoreRings = ({
  score = 100,
  filesScanned = 0,
  filesTotal = 0,
  scanInProgress = false,
  className = '',
}) => {
  const scoreColor = scoreRingColor(score);
  const totalDisplay = Math.max(filesTotal, 0);
  const scannedDisplay = Math.min(totalDisplay, Math.max(filesScanned, 0));
  const ringValue = scanInProgress
    ? Math.max(scannedDisplay, totalDisplay * 0.45)
    : scannedDisplay;

  return (
    <div
      className={`flex flex-wrap items-center justify-center gap-10 sm:gap-14 ${className}`}
    >
      <ProgressRing
        value={score}
        max={100}
        color={scoreColor}
        label="Security Score"
        center={
          <p className="font-mono text-[var(--text-primary)] leading-none text-center">
            <span className="text-2xl">{score}</span>
            <span className="text-sm text-[var(--text-secondary)]">/100</span>
          </p>
        }
      />
      <ProgressRing
        value={ringValue}
        max={Math.max(totalDisplay, 1)}
        color="var(--signal-green)"
        inProgress={scanInProgress}
        label="Files Scanned"
        center={
          <p className="font-mono text-[var(--text-primary)] leading-none text-center">
            {scanInProgress ? (
              <>
                <span className="text-xl text-[var(--signal-green-bright)]">…</span>
                <span className="text-sm text-[var(--text-secondary)]">/{totalDisplay}</span>
              </>
            ) : (
              <>
                <span className="text-2xl">{scannedDisplay}</span>
                <span className="text-sm text-[var(--text-secondary)]">/{totalDisplay}</span>
              </>
            )}
          </p>
        }
      />
    </div>
  );
};

export default ScoreRings;
