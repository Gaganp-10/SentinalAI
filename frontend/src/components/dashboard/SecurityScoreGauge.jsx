import React from 'react';

const SecurityScoreGauge = ({ score = 100 }) => {
  let scoreColor = 'var(--signal-green)';
  if (score < 60) {
    scoreColor = 'var(--sev-critical)';
  } else if (score < 85) {
    scoreColor = 'var(--sev-high)';
  }

  const radius = 45;
  const strokeWidth = 6;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <div className="relative flex items-center justify-center">
        <svg className="w-28 h-28 transform -rotate-90">
          <circle
            stroke="var(--border-glow)"
            fill="transparent"
            strokeWidth={strokeWidth}
            r={radius}
            cx="56"
            cy="56"
          />
          <circle
            className="transition-all duration-500 ease-out"
            stroke={scoreColor}
            fill="transparent"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            r={radius}
            cx="56"
            cy="56"
          />
        </svg>
        <div className="absolute flex flex-col items-center justify-center">
          <span className="text-2xl font-display font-semibold text-[var(--text-primary)] font-mono">
            {score}
          </span>
          <span className="text-[8px] font-mono text-[var(--text-secondary)] uppercase tracking-wider leading-none">
            SECURITY
          </span>
        </div>
      </div>

      <span
        className="text-[9px] font-semibold font-mono px-2 py-0.5 rounded-full border mt-4"
        style={{
          color: scoreColor,
          background:
            score >= 85
              ? 'rgba(46,204,113,0.12)'
              : score >= 60
                ? 'rgba(245,166,35,0.12)'
                : 'rgba(229,72,77,0.12)',
          borderColor: scoreColor,
        }}
      >
        {score >= 85 ? 'SECURE' : score >= 60 ? 'WARNING' : 'VULNERABLE'}
      </span>
    </div>
  );
};

export default SecurityScoreGauge;
