import React from 'react';
import { useLocation } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';

function getLabel(pathname) {
  if (pathname.includes('/results')) return 'Vulnerabilities';
  if (pathname.includes('/reports')) return 'Reports';
  if (pathname.includes('/vulnerabilities/')) return 'Finding Detail';
  if (pathname.includes('/projects/')) return 'Project';
  if (pathname === '/') return 'Dashboard';
  return 'Console';
}

const Navbar = () => {
  const location = useLocation();
  const label = getLabel(location.pathname);

  return (
    <header
      className="h-12 border-b border-[var(--border-glow)] bg-[var(--bg-panel)]/95 flex items-center justify-between px-6 sticky top-0 z-30 backdrop-blur-sm"
    >
      <div className="flex items-center gap-2">
        <span className="text-[11px] font-mono text-[var(--text-secondary)] uppercase tracking-widest">
          Console
        </span>
        <span className="text-[var(--border-glow)]">/</span>
        <span className="text-[11px] font-mono font-semibold text-[var(--text-primary)]">
          {label}
        </span>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-[11px] font-mono font-medium text-[var(--signal-green)] bg-[rgba(46,204,113,0.08)] px-3 py-1 rounded-full border border-[rgba(46,204,113,0.25)]">
          <ShieldCheck className="h-3 w-3" />
          <span>SYSTEM_ONLINE</span>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
