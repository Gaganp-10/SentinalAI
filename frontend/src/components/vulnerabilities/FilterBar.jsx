import React from 'react';
import { Search } from 'lucide-react';

const SEV_FILTERS = [
  { value: '', label: 'ALL', color: 'var(--text-secondary)' },
  { value: 'critical', label: 'CRITICAL', color: '#E5484D' },
  { value: 'high', label: 'HIGH', color: '#F5A623' },
  { value: 'medium', label: 'MEDIUM', color: '#F0C94A' },
  { value: 'low', label: 'LOW', color: '#4FD1C5' },
  { value: 'info', label: 'INFO', color: '#7C9186' },
];

const FilterBar = ({ severity, setSeverity, search, setSearch, type, setType }) => {
  return (
    <div className="space-y-3 mb-6">
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-[10px] font-mono text-[var(--text-secondary)] uppercase tracking-widest shrink-0">
          Severity
        </span>
        <div className="seg-control flex-wrap">
          {SEV_FILTERS.map(({ value, label, color }) => {
            const isActive = severity === value;
            return (
              <button
                key={value}
                onClick={() => setSeverity(value)}
                className="seg-btn"
                style={
                  isActive
                    ? { background: 'var(--bg-panel-hover)', color, borderColor: color }
                    : {}
                }
              >
                {label}
              </button>
            );
          })}
        </div>
      </div>

      <div className="flex gap-3 flex-col md:flex-row">
        <div className="relative flex-1">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5"
            style={{ color: 'var(--text-secondary)' }}
          />
          <input
            type="text"
            placeholder="Search by CWE, type, file path, description…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-field pl-9"
          />
        </div>

        <input
          type="text"
          placeholder="Filter by vulnerability type…"
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="input-field md:w-52"
        />
      </div>
    </div>
  );
};

export default FilterBar;
