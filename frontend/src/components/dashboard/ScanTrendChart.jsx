import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const ScanTrendChart = ({ scans = [] }) => {
  const chartData = scans
    .slice()
    .filter((scan) => scan.status === 'completed')
    .sort((a, b) => new Date(a.scan_time) - new Date(b.scan_time))
    .map((scan, idx) => ({
      name: `#${idx + 1}`,
      issues: scan.total_issues,
      date: new Date(scan.scan_time).toLocaleDateString(),
    }));

  if (chartData.length === 0) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-xs text-[var(--text-secondary)] font-mono">
        <span>NO_TREND_DATA</span>
        <span className="text-[10px] mt-1 opacity-70">Run multiple scans to generate trend</span>
      </div>
    );
  }

  return (
    <div className="h-full w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="colorIssues" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#39FF88" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#2ECC71" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1E3A2C" vertical={false} />
          <XAxis
            dataKey="name"
            stroke="#7C9186"
            fontSize={9}
            tickLine={false}
            axisLine={false}
            fontFamily="IBM Plex Mono, monospace"
          />
          <YAxis
            stroke="#7C9186"
            fontSize={9}
            tickLine={false}
            axisLine={false}
            fontFamily="IBM Plex Mono, monospace"
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#0F1613',
              borderColor: '#1E3A2C',
              borderRadius: '8px',
              color: '#E7F5EC',
              fontSize: '11px',
              fontFamily: 'IBM Plex Mono, monospace',
            }}
          />
          <Area
            type="monotone"
            dataKey="issues"
            name="Issues"
            stroke="#39FF88"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#colorIssues)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default ScanTrendChart;
