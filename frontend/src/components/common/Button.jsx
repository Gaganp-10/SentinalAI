import React from 'react';

const VARIANTS = {
  primary:
    'bg-[var(--signal-green)] hover:bg-[var(--signal-green-bright)] text-[var(--bg-void)] border border-[var(--signal-green)] font-semibold shadow-none hover:shadow-[0_0_20px_-4px_rgba(46,204,113,0.55)]',
  secondary:
    'bg-transparent hover:bg-[var(--bg-panel-hover)] text-[var(--text-primary)] border border-[var(--border-glow)] hover:border-[var(--border-glow-active)]',
  danger:
    'bg-[var(--sev-critical)] hover:brightness-110 text-white border border-transparent',
  success:
    'bg-[var(--signal-green)] hover:bg-[var(--signal-green-bright)] text-[var(--bg-void)] border border-transparent font-semibold',
  ghost:
    'bg-transparent hover:bg-[var(--bg-panel-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-transparent',
};

const SIZES = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-5 py-2.5 text-sm',
};

const Button = ({
  children,
  onClick,
  type = 'button',
  variant = 'primary',
  size = 'md',
  disabled = false,
  isLoading = false,
  className = '',
  ...props
}) => {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || isLoading}
      className={[
        'inline-flex items-center justify-center font-medium rounded-md font-sans',
        'transition-all duration-150',
        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--signal-green)] focus-visible:outline-offset-2',
        'disabled:opacity-40 disabled:cursor-not-allowed',
        VARIANTS[variant] ?? VARIANTS.primary,
        SIZES[size] ?? SIZES.md,
        className,
      ].join(' ')}
      {...props}
    >
      {isLoading && (
        <svg
          className="animate-spin -ml-0.5 mr-2 h-3.5 w-3.5 text-current shrink-0"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      )}
      {children}
    </button>
  );
};

export default Button;
