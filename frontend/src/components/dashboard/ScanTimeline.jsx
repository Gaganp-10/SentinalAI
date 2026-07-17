import React, { useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import Panel from '../common/Panel';
import { severityColor } from '../../utils/securityScore';

function barColorForScan(scan) {
  if ((scan.critical_count || 0) > 0) return severityColor('critical');
  if ((scan.high_count || 0) > 0) return severityColor('high');
  if ((scan.medium_count || 0) > 0) return severityColor('medium');
  if ((scan.low_count || 0) > 0) return severityColor('low');
  return 'var(--signal-green)';
}

/**
 * Historical scan issue counts — one bar per completed scan.
 * Bar color = worst severity present in that scan.
 */
const ScanTimeline = ({ scans = [] }) => {
  const data = useMemo(() => {
    return scans
      .filter((s) => s.status === 'completed')
      .slice()
      .sort((a, b) => new Date(a.scan_time) - new Date(b.scan_time))
      .map((scan, idx) => ({
        id: scan.id,
        label: new Date(scan.scan_time).toLocaleDateString(undefined, {
          month: 'short',
          day: 'numeric',
        }),
        fullDate: new Date(scan.scan_time).toLocaleString(),
        issues: scan.total_issues ?? 0,
        color: barColorForScan(scan),
        idx: idx + 1,
      }));
  }, [scans]);

  return (
    <Panel title="Scan Timeline" hoverable={false}>
      {data.length === 0 ? (
        <div className="h-40 flex items-center justify-center text-xs font-mono text-[var(--text-secondary)]">
          NO_SCAN_HISTORY
        </div>
      ) : (
        <div className="h-48 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-glow)" vertical={false} />
              <XAxis
                dataKey="label"
                stroke="var(--text-secondary)"
                fontSize={10}
                tickLine={false}
                axisLine={false}
                fontFamily="IBM Plex Mono, monospace"
              />
              <YAxis
                allowDecimals={false}
                stroke="var(--text-secondary)"
                fontSize={10}
                tickLine={false}
                axisLine={false}
                fontFamily="IBM Plex Mono, monospace"
              />
              <Tooltip
                cursor={{ fill: 'rgba(46,204,113,0.06)' }}
                contentStyle={{
                  backgroundColor: '#0F1613',
                  borderColor: '#1E3A2C',
                  borderRadius: '8px',
                  color: '#E7F5EC',
                  fontSize: '11px',
                  fontFamily: 'IBM Plex Mono, monospace',
                }}
                formatter={(value) => [`${value} issues`, 'Total']}
                labelFormatter={(_, payload) => payload?.[0]?.payload?.fullDate || ''}
              />
              <Bar dataKey="issues" name="Issues" radius={[4, 4, 0, 0]} maxBarSize={40}>
                {data.map((entry) => (
                  <Cell key={entry.id} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Panel>
  );
};

export default ScanTimeline;
