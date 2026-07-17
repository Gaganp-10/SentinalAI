import React from 'react';

const STATUS_DOT = {
  green: 'var(--signal-green)',
  amber: 'var(--sev-high)',
  red: 'var(--sev-critical)',
};

/**
 * Shared glassmorphic panel used across Dashboard, Project, Scan Results,
 * Vulnerability Detail, and auth surfaces.
 */
const Panel = ({
  title,
  status,
  headerRight,
  hoverable = true,
  noPadding = false,
  className = '',
  children,
  onClick,
  style,
  ...rest
}) => {
  const hasHeader = title != null || headerRight;

  return (
    <div
      onClick={onClick}
      className={[
        'panel-surface relative',
        hoverable ? 'panel-surface--hoverable' : '',
        onClick ? 'cursor-pointer' : '',
        className,
      ]
        .filter(Boolean)
        .join(' ')}
      style={style}
      {...rest}
    >
      {/* Corner status dot when panel has no header title */}
      {status && STATUS_DOT[status] && !hasHeader && (
        <span
          className="absolute top-3.5 right-3.5 h-2 w-2 rounded-full z-10"
          style={{
            background: STATUS_DOT[status],
            boxShadow: `0 0 8px ${STATUS_DOT[status]}`,
          }}
          aria-hidden
        />
      )}
      {hasHeader && (
        <div className="flex items-center justify-between gap-3 border-b border-[var(--border-glow)] px-5 py-3.5">
          <div className="flex items-center gap-2.5 min-w-0">
            {status && STATUS_DOT[status] && (
              <span
                className="shrink-0 h-2 w-2 rounded-full"
                style={{
                  background: STATUS_DOT[status],
                  boxShadow: `0 0 8px ${STATUS_DOT[status]}`,
                }}
                aria-hidden
              />
            )}
            {title != null && (
              <h3 className="text-xs font-display font-semibold text-[var(--text-primary)] truncate">
                {title}
              </h3>
            )}
          </div>
          {headerRight && <div className="shrink-0">{headerRight}</div>}
        </div>
      )}
      <div className={noPadding ? '' : 'p-5'}>{children}</div>
    </div>
  );
};

export default Panel;
