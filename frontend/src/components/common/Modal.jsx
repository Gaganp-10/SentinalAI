import React from 'react';
import { X } from 'lucide-react';

const Modal = ({ isOpen, onClose, title, children, footer, className = '' }) => {
  React.useEffect(() => {
    const handleEscape = (e) => { if (e.key === 'Escape') onClose(); };
    if (isOpen) {
      document.body.style.overflow = 'hidden';
      window.addEventListener('keydown', handleEscape);
    }
    return () => {
      document.body.style.overflow = 'unset';
      window.removeEventListener('keydown', handleEscape);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="fixed inset-0" onClick={onClose} />
      <div
        className={`relative w-full max-w-lg flex flex-col max-h-[88vh] overflow-hidden rounded-[10px] border ${className}`}
        style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-glow)' }}
      >
        <div
          className="flex items-center justify-between px-5 py-4 border-b"
          style={{ borderColor: 'var(--border-glow)' }}
        >
          <h3 className="text-sm font-display font-semibold" style={{ color: 'var(--text-primary)' }}>
            {title}
          </h3>
          <button
            onClick={onClose}
            className="p-1 rounded transition-colors hover:bg-[var(--bg-panel-hover)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5 overflow-y-auto flex-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
          {children}
        </div>

        {footer && (
          <div
            className="flex items-center justify-end gap-3 px-5 py-4 border-t"
            style={{ borderColor: 'var(--border-glow)', background: 'var(--bg-panel-hover)' }}
          >
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};

export default Modal;
