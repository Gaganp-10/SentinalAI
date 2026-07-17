import React, { useMemo } from 'react';
import Panel from '../common/Panel';

/**
 * Horizontal bars of finding share per detection engine (`source_tool`).
 * Tools may be comma-separated on a single vulnerability.
 */
const DetectionBreakdownBars = ({ vulnerabilities = [] }) => {
  const rows = useMemo(() => {
    const counts = new Map();
    let total = 0;
    for (const v of vulnerabilities) {
      const raw = v.source_tool || 'unknown';
      const tools = String(raw)
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      if (tools.length === 0) continue;
      // Attribute one finding to each listed tool (common multi-detector case)
      for (const tool of tools) {
        counts.set(tool, (counts.get(tool) || 0) + 1);
        total += 1;
      }
    }
    return Array.from(counts.entries())
      .map(([name, count]) => ({
        name,
        count,
        pct: total > 0 ? Math.round((count / total) * 100) : 0,
      }))
      .sort((a, b) => b.count - a.count);
  }, [vulnerabilities]);

  return (
    <Panel title="Detection Breakdown" hoverable={false}>
      {rows.length === 0 ? (
        <p className="text-xs font-mono text-[var(--text-secondary)] py-4 text-center">
          NO_DETECTION_DATA
        </p>
      ) : (
        <ul className="space-y-4">
          {rows.map(({ name, count, pct }) => (
            <li key={name}>
              <div className="flex items-baseline justify-between gap-3 mb-1.5">
                <span className="text-sm font-sans text-[var(--text-primary)] truncate">
                  {name}
                </span>
                <span className="font-mono text-xs text-[var(--text-secondary)] shrink-0">
                  <span className="text-[var(--signal-green-bright)]">{pct}%</span>
                  {'  '}
                  <span className="opacity-80">({count} findings)</span>
                </span>
              </div>
              <div
                className="h-2 w-full rounded-full overflow-hidden"
                style={{ background: 'var(--border-glow)' }}
              >
                <div
                  className="h-full rounded-full transition-[width] duration-500 ease-out"
                  style={{
                    width: `${pct}%`,
                    background: 'var(--signal-green)',
                    boxShadow: '0 0 10px -2px rgba(46,204,113,0.55)',
                  }}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
};

export default DetectionBreakdownBars;
