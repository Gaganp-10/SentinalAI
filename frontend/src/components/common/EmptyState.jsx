import React from 'react';

const EmptyState = ({ title, description, icon: Icon, children, className = '' }) => {
  return (
    <div
      className={`flex flex-col items-center justify-center text-center py-16 px-8 border border-dashed rounded-[10px] ${className}`}
      style={{ borderColor: 'var(--border-glow)', background: 'transparent' }}
    >
      {Icon && (
        <div
          className="p-3 rounded-md mb-5 border"
          style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-glow)' }}
        >
          <Icon className="h-6 w-6" style={{ color: 'var(--text-secondary)' }} />
        </div>
      )}
      <h3
        className="text-base font-display font-semibold mb-1.5"
        style={{ color: 'var(--text-primary)' }}
      >
        {title}
      </h3>
      <p
        className="text-sm max-w-sm mb-6 leading-relaxed"
        style={{ color: 'var(--text-secondary)' }}
      >
        {description}
      </p>
      {children}
    </div>
  );
};

export default EmptyState;
