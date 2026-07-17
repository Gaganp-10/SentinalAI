import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

const SeverityPieChart = ({ critical = 0, high = 0, medium = 0, low = 0, info = 0 }) => {
  const chartData = [
    { name: 'Critical', value: critical, color: '#E5484D' },
    { name: 'High', value: high, color: '#F5A623' },
    { name: 'Medium', value: medium, color: '#F0C94A' },
    { name: 'Low', value: low, color: '#4FD1C5' },
    { name: 'Info', value: info, color: '#7C9186' },
  ].filter((item) => item.value > 0);

  if (chartData.length === 0) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-xs text-[var(--text-secondary)] font-mono">
        <span>NO_DATA_AVAILABLE</span>
        <span className="text-[10px] mt-1 opacity-70">Scan project to view statistics</span>
      </div>
    );
  }

  return (
    <div className="h-full w-full flex items-center justify-center">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={45}
            outerRadius={65}
            paddingAngle={4}
            dataKey="value"
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
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
          <Legend
            verticalAlign="bottom"
            height={32}
            iconType="circle"
            iconSize={6}
            formatter={(value) => (
              <span className="text-[10px] text-[var(--text-secondary)] font-mono">{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};

export default SeverityPieChart;
