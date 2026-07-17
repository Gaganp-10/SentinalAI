import React, { useRef, useEffect, useState, useCallback } from 'react';

/**
 * SignalTrace — the "Signal Room" signature element.
 *
 * Renders a waveform/oscilloscope line across the full width representing
 * a code file being scanned left-to-right. Each vulnerability is a spike
 * whose height maps to severity (critical = tallest) and color maps to the
 * severity token. Animates in as a left-to-right sweep on mount.
 *
 * Props:
 *   vulnerabilities   — array of VulnerabilityOut objects (need line_number, severity)
 *   maxLineNumber      — estimated total lines in file (for x-axis scaling)
 *   onHoverVuln        — (vulnId | null) => void — called when a spike is hovered
 *   onClickVuln        — (vulnId) => void — called when a spike is clicked
 *   activeVulnId       — vulnId that is currently highlighted
 *   height             — SVG height in px (default 72)
 */

const SEV_COLORS = {
  critical: '#E5484D',
  high:     '#F5A623',
  medium:   '#F0C94A',
  low:      '#4FD1C5',
  info:     '#7C9186',
};

const SEV_HEIGHT_RATIO = {
  critical: 0.90,
  high:     0.70,
  medium:   0.50,
  low:      0.30,
  info:     0.18,
};

const BASELINE_Y_RATIO = 0.80; // baseline sits at 80% of height

export default function SignalTrace({
  vulnerabilities = [],
  maxLineNumber = 300,
  onHoverVuln,
  onClickVuln,
  activeVulnId,
  height = 72,
}) {
  const containerRef = useRef(null);
  const [width, setWidth] = useState(0);
  const [hoveredId, setHoveredId] = useState(null);

  // Observe container width
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(entries => {
      if (entries[0]) setWidth(entries[0].contentRect.width);
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // Sort vulnerabilities by line_number for rendering
  const sorted = [...vulnerabilities].sort((a, b) => a.line_number - b.line_number);
  const maxLine = Math.max(maxLineNumber, ...sorted.map(v => v.line_number), 1);

  const baselineY = height * BASELINE_Y_RATIO;
  const availableHeight = baselineY - 4; // headroom above baseline

  // Build path data
  const buildPath = useCallback(() => {
    if (width === 0) return '';
    const pad = 16; // horizontal padding
    const usableW = width - pad * 2;

    // Start from left edge at baseline
    let d = `M ${pad} ${baselineY}`;

    let prevX = pad;

    for (const vuln of sorted) {
      const xRatio = vuln.line_number / maxLine;
      const x = pad + xRatio * usableW;
      const sev = (vuln.severity || 'info').toLowerCase();
      const ratio = SEV_HEIGHT_RATIO[sev] ?? SEV_HEIGHT_RATIO.info;
      const spikeH = availableHeight * ratio;
      const tipY = baselineY - spikeH;

      // Line to just before spike
      if (x - 3 > prevX) d += ` L ${x - 3} ${baselineY}`;
      // Spike: sharp up then back down
      d += ` L ${x} ${tipY} L ${x + 2} ${baselineY}`;
      prevX = x + 2;
    }

    // Finish to right edge
    d += ` L ${width - pad} ${baselineY}`;
    return d;
  }, [width, sorted, maxLine, baselineY, availableHeight]);

  const pathD = buildPath();

  // Compute spike hit boxes for interaction
  const spikes = sorted.map(vuln => {
    const pad = 16;
    const usableW = width - pad * 2;
    const xRatio = vuln.line_number / maxLine;
    const x = pad + xRatio * usableW;
    const sev = (vuln.severity || 'info').toLowerCase();
    const ratio = SEV_HEIGHT_RATIO[sev] ?? SEV_HEIGHT_RATIO.info;
    const spikeH = availableHeight * ratio;
    return { ...vuln, cx: x, cy: baselineY - spikeH, sev, color: SEV_COLORS[sev] ?? SEV_COLORS.info };
  });

  const handleSpikeEnter = (vuln) => {
    setHoveredId(vuln.id);
    onHoverVuln?.(vuln.id);
  };
  const handleSpikeLeave = () => {
    setHoveredId(null);
    onHoverVuln?.(null);
  };
  const handleSpikeClick = (vuln) => {
    onClickVuln?.(vuln.id);
  };

  return (
    <div
      ref={containerRef}
      className="w-full select-none"
      style={{ height }}
      aria-label={`Signal trace showing ${vulnerabilities.length} vulnerabilities`}
    >
      {width > 0 && (
        <svg
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          xmlns="http://www.w3.org/2000/svg"
          role="img"
        >
          {/* Subtle grid lines */}
          {[0.25, 0.5, 0.75].map(r => (
            <line
              key={r}
              x1={0}
              x2={width}
              y1={baselineY - availableHeight * r}
              y2={baselineY - availableHeight * r}
              stroke="var(--border-hair)"
              strokeWidth={0.5}
              strokeDasharray="3 6"
              opacity={0.4}
            />
          ))}

          {/* Baseline */}
          <line
            x1={0} x2={width} y1={baselineY} y2={baselineY}
            stroke="var(--border-hair)"
            strokeWidth={1}
          />

          {/* Waveform path — sweep-in animation via clip-path */}
          <g className="signal-sweep">
            <path
              d={pathD}
              fill="none"
              stroke="var(--signal-amber)"
              strokeWidth={1.5}
              strokeLinecap="round"
              strokeLinejoin="round"
              opacity={0.7}
            />
            {/* Amber glow layer */}
            <path
              d={pathD}
              fill="none"
              stroke="var(--signal-amber)"
              strokeWidth={4}
              strokeLinecap="round"
              strokeLinejoin="round"
              opacity={0.12}
            />
          </g>

          {/* Spike hit-boxes and spike dots */}
          {spikes.map((vuln) => {
            const isActive = activeVulnId === vuln.id || hoveredId === vuln.id;
            return (
              <g
                key={vuln.id}
                onMouseEnter={() => handleSpikeEnter(vuln)}
                onMouseLeave={handleSpikeLeave}
                onClick={() => handleSpikeClick(vuln)}
                style={{ cursor: 'pointer' }}
                aria-label={`${vuln.severity} severity: ${vuln.type} at line ${vuln.line_number}`}
              >
                {/* Larger invisible hit target */}
                <rect
                  x={vuln.cx - 8}
                  y={vuln.cy - 8}
                  width={20}
                  height={baselineY - vuln.cy + 16}
                  fill="transparent"
                />
                {/* Spike tip dot */}
                <circle
                  cx={vuln.cx}
                  cy={vuln.cy}
                  r={isActive ? 4 : 2.5}
                  fill={vuln.color}
                  opacity={isActive ? 1 : 0.85}
                  style={{ transition: 'r 150ms, opacity 150ms' }}
                />
                {/* Glow on hover */}
                {isActive && (
                  <>
                    <circle cx={vuln.cx} cy={vuln.cy} r={8} fill={vuln.color} opacity={0.15} />
                    {/* Tooltip label */}
                    <g>
                      <rect
                        x={Math.min(vuln.cx - 24, width - 80)}
                        y={vuln.cy - 26}
                        width={width > 200 ? 72 : 60}
                        height={18}
                        rx={3}
                        fill="var(--bg-panel-raised)"
                        stroke="var(--border-hair)"
                        strokeWidth={0.5}
                      />
                      <text
                        x={Math.min(vuln.cx - 24, width - 80) + 6}
                        y={vuln.cy - 13}
                        fontSize={9}
                        fontFamily="'IBM Plex Mono', monospace"
                        fontWeight={600}
                        fill={vuln.color}
                        textAnchor="start"
                      >
                        {vuln.sev.toUpperCase()} L{vuln.line_number}
                      </text>
                    </g>
                  </>
                )}
              </g>
            );
          })}

          {/* Y-axis label */}
          <text
            x={6}
            y={12}
            fontSize={8}
            fontFamily="'IBM Plex Mono', monospace"
            fill="var(--text-secondary)"
            opacity={0.6}
          >
            SIGNAL TRACE
          </text>

          {/* Vuln count */}
          <text
            x={width - 6}
            y={12}
            fontSize={8}
            fontFamily="'IBM Plex Mono', monospace"
            fill="var(--signal-amber)"
            opacity={0.8}
            textAnchor="end"
          >
            {vulnerabilities.length} FINDINGS
          </text>
        </svg>
      )}
    </div>
  );
}
