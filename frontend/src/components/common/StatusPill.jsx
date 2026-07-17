import React from 'react';

const STYLES = {
  pending: {
    color: 'var(--sev-high)',
    bg: 'rgba(245, 166, 35, 0.15)',
    border: 'var(--sev-high)',
  },
  running: {
    color: 'var(--signal-green-bright)',
    bg: 'rgba(57, 255, 136, 0.12)',
    border: 'var(--signal-green)',
  },
  fixed: {
    color: 'var(--sev-resolved)',
    bg: 'rgba(46, 204, 113, 0.15)',
    border: 'var(--sev-resolved)',
  },
  resolved: {
    color: 'var(--sev-resolved)',
    bg: 'rgba(46, 204, 113, 0.15)',
    border: 'var(--sev-resolved)',
  },
  completed: {
    color: 'var(--sev-resolved)',
    bg: 'rgba(46, 204, 113, 0.15)',
    border: 'var(--sev-resolved)',
  },
  failed: {
    color: 'var(--sev-critical)',
    bg: 'rgba(229, 72, 77, 0.15)',
    border: 'var(--sev-critical)',
  },
  active: {
    color: 'var(--sev-high)',
    bg: 'rgba(245, 166, 35, 0.15)',
    border: 'var(--sev-high)',
  },
};

/**
 * Status pill for pending / fixed / resolved / scan states.
 */
const StatusPill = ({ status = 'pending', children, icon: Icon, className = '' }) => {
  const key = String(status).toLowerCase();
  const s = STYLES[key] ?? STYLES.pending;
  const label = children ?? String(status).toUpperCase();

  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-wider border ${className}`}
      style={{
        background: s.bg,
        color: s.color,
        borderColor: s.border,
      }}
    >
      {Icon && (
        <Icon
          className={`h-3 w-3 ${key === 'running' ? 'animate-spin' : ''}`}
        />
      )}
      {label}
    </span>
  );
};

export default StatusPill;
