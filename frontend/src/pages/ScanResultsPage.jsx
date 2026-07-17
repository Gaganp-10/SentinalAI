import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { useVulnerabilities } from '../hooks/useVulnerabilities';
import { useProjectDetails } from '../hooks/useProjects';
import FilterBar from '../components/vulnerabilities/FilterBar';
import VulnerabilityTable from '../components/vulnerabilities/VulnerabilityTable';
import Spinner from '../components/common/Spinner';
import EmptyState from '../components/common/EmptyState';
import Panel from '../components/common/Panel';
import { ShieldCheck, ChevronRight } from 'lucide-react';

const SEV_META = {
  Critical: { color: 'var(--sev-critical)', status: 'red' },
  High: { color: 'var(--sev-high)', status: 'amber' },
  Medium: { color: 'var(--sev-medium)', status: 'amber' },
  Low: { color: 'var(--sev-low)', status: 'green' },
};

const ScanResultsPage = () => {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { project } = useProjectDetails(projectId);

  const fileFromMap = searchParams.get('file') || '';
  const [severity, setSeverity] = useState('');
  const [search, setSearch] = useState(fileFromMap);
  const [type, setType] = useState('');

  useEffect(() => {
    if (fileFromMap) setSearch(fileFromMap);
  }, [fileFromMap]);

  const { vulnerabilities, isLoading, error } = useVulnerabilities({
    projectId,
    severity: severity || undefined,
    type: type || undefined,
    search: search || undefined,
  });

  const counts = {
    critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
    high: vulnerabilities.filter((v) => v.severity === 'high').length,
    medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
    low: vulnerabilities.filter((v) => v.severity === 'low').length,
  };

  return (
    <div className="space-y-6">
      <div className="border-b border-[var(--border-glow)] pb-6">
        <div className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] mb-2">
          <span
            className="hover:text-[var(--signal-green)] cursor-pointer"
            onClick={() => navigate('/')}
          >
            Dashboard
          </span>
          <ChevronRight className="h-3 w-3" />
          <span
            className="hover:text-[var(--signal-green)] cursor-pointer"
            onClick={() => navigate(`/projects/${projectId}`)}
          >
            {project?.project_name || 'Project'}
          </span>
          <ChevronRight className="h-3 w-3" />
          <span className="text-[var(--text-primary)]">Vulnerabilities</span>
        </div>
        <h2 className="text-xl font-display font-semibold text-[var(--text-primary)]">
          Scan Findings
        </h2>
        <p className="text-sm text-[var(--text-secondary)] mt-1">
          Review, filter, and remediate security vulnerabilities detected in your codebase.
          {fileFromMap && (
            <>
              {' '}
              Filtered to{' '}
              <span className="font-mono text-[var(--signal-green)]">{fileFromMap}</span>.
            </>
          )}
        </p>
      </div>

      {!isLoading && vulnerabilities.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Critical', count: counts.critical },
            { label: 'High', count: counts.high },
            { label: 'Medium', count: counts.medium },
            { label: 'Low', count: counts.low },
          ].map(({ label, count }) => {
            const meta = SEV_META[label];
            return (
              <Panel
                key={label}
                status={meta.status}
                onClick={() => setSeverity(label.toLowerCase())}
                hoverable
              >
                <p
                  className="text-xs font-mono font-bold uppercase tracking-widest mb-1"
                  style={{ color: meta.color }}
                >
                  {label}
                </p>
                <p className="text-3xl font-display font-semibold text-[var(--text-primary)] font-mono">
                  {count}
                </p>
              </Panel>
            );
          })}
        </div>
      )}

      <FilterBar
        severity={severity}
        setSeverity={setSeverity}
        search={search}
        setSearch={setSearch}
        type={type}
        setType={setType}
      />

      {isLoading ? (
        <div className="h-64 flex flex-col items-center justify-center gap-3">
          <Spinner size="lg" />
          <p className="text-sm font-mono text-[var(--text-secondary)]">
            LOADING_VULNERABILITIES...
          </p>
        </div>
      ) : error ? (
        <div
          className="p-6 rounded-[10px] text-sm font-mono border"
          style={{
            background: 'rgba(229,72,77,0.1)',
            borderColor: 'rgba(229,72,77,0.25)',
            color: 'var(--sev-critical)',
          }}
        >
          ERROR: {error.message}
        </div>
      ) : vulnerabilities.length === 0 ? (
        <EmptyState
          title="No vulnerabilities found"
          description={
            severity || search || type
              ? 'Try clearing filters to see all findings.'
              : 'Run a scan to detect security vulnerabilities.'
          }
          icon={ShieldCheck}
        />
      ) : (
        <VulnerabilityTable vulnerabilities={vulnerabilities} />
      )}
    </div>
  );
};

export default ScanResultsPage;
