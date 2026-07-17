import React from 'react';

const SEV = {
  critical: {
    bg: 'rgba(229, 72, 77, 0.15)',
    text: 'var(--sev-critical)',
    border: 'var(--sev-critical)',
  },
  high: {
    bg: 'rgba(245, 166, 35, 0.15)',
    text: 'var(--sev-high)',
    border: 'var(--sev-high)',
  },
  medium: {
    bg: 'rgba(240, 201, 74, 0.15)',
    text: 'var(--sev-medium)',
    border: 'var(--sev-medium)',
  },
  low: {
    bg: 'rgba(79, 209, 197, 0.15)',
    text: 'var(--sev-low)',
    border: 'var(--sev-low)',
  },
  resolved: {
    bg: 'rgba(46, 204, 113, 0.15)',
    text: 'var(--sev-resolved)',
    border: 'var(--sev-resolved)',
  },
  info: {
    bg: 'rgba(124, 145, 134, 0.15)',
    text: 'var(--text-secondary)',
    border: 'var(--text-secondary)',
  },
};

const SeverityBadge = ({ severity = 'info' }) => {
  const key = severity.toLowerCase();
  const s = SEV[key] ?? SEV.info;

  return (
    <span
      className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-widest border"
      style={{ background: s.bg, color: s.text, borderColor: s.border }}
    >
      {key.toUpperCase()}
    </span>
  );
};

export default SeverityBadge;
