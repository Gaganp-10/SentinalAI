import React, { useMemo, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useProjectDetails } from '../hooks/useProjects';
import { useScans, useScanStatus } from '../hooks/useScans';
import { useVulnerabilities } from '../hooks/useVulnerabilities';
import { uploadFiles, getFiles } from '../api/files';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import Button from '../components/common/Button';
import Spinner from '../components/common/Spinner';
import EmptyState from '../components/common/EmptyState';
import Panel from '../components/common/Panel';
import StatusPill from '../components/common/StatusPill';
import FileDropzone from '../components/upload/FileDropzone';
import ScoreRings from '../components/dashboard/ScoreRings';
import CodebaseVulnerabilityMap from '../components/dashboard/CodebaseVulnerabilityMap';
import DetectionBreakdownBars from '../components/dashboard/DetectionBreakdownBars';
import ScanTimeline from '../components/dashboard/ScanTimeline';
import { computeSecurityScore, scoreStatus } from '../utils/securityScore';
import {
  PlayCircle,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronRight,
  Loader2,
  FolderOpen,
  AlertTriangle,
  BarChart3,
  ArrowUpRight,
} from 'lucide-react';

const LANG_ICONS = {
  python: '🐍',
  javascript: '📜',
  typescript: '💙',
  java: '☕',
  c: '⚙️',
  cpp: '⚙️',
  php: '🐘',
  zip: '📦',
};

const StatusBadge = ({ status }) => {
  const icons = {
    pending: Clock,
    running: Loader2,
    completed: CheckCircle2,
    failed: XCircle,
  };
  const Icon = icons[status] || Clock;
  return (
    <StatusPill status={status} icon={Icon}>
      {status?.toUpperCase()}
    </StatusPill>
  );
};

const ScanPoller = ({ scanId, projectId, onDone }) => {
  const { scan } = useScanStatus(scanId);
  const queryClient = useQueryClient();

  React.useEffect(() => {
    if (scan && (scan.status === 'completed' || scan.status === 'failed')) {
      queryClient.invalidateQueries({ queryKey: ['scans', projectId] });
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      onDone(scan);
    }
  }, [scan?.status]);

  return (
    <Panel status="green" hoverable={false} className="mt-4">
      <div className="flex items-center gap-3 -my-1">
        <Loader2 className="h-5 w-5 text-[var(--signal-green)] animate-spin shrink-0" />
        <div>
          <p className="text-sm font-semibold text-[var(--signal-green-bright)]">Scan in progress...</p>
          <p className="text-xs text-[var(--text-secondary)] font-mono mt-0.5">
            Status: {scan?.status?.toUpperCase() || 'INITIALIZING'} — polling every 2s
          </p>
        </div>
      </div>
    </Panel>
  );
};

const ProjectPage = () => {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { project, isLoading: projLoading } = useProjectDetails(projectId);
  const { scans, isLoading: scansLoading, triggerScan, isTriggering } = useScans(projectId);
  const { vulnerabilities } = useVulnerabilities({ projectId });

  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadError, setUploadError] = useState('');
  const [activeScanId, setActiveScanId] = useState(null);
  const [scanError, setScanError] = useState('');

  const { data: files = [], isLoading: filesLoading, refetch: refetchFiles } = useQuery({
    queryKey: ['files', projectId],
    queryFn: () => getFiles(projectId),
    enabled: !!projectId,
  });

  const handleUpload = async (file) => {
    setIsUploading(true);
    setUploadError('');
    setUploadProgress(0);
    try {
      await uploadFiles(projectId, file, (evt) => {
        setUploadProgress(Math.round((evt.loaded * 100) / evt.total));
      });
      refetchFiles();
    } catch (err) {
      setUploadError(err.response?.data?.detail || 'Upload failed. Please try again.');
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
    }
  };

  const handleScanNow = async () => {
    setScanError('');
    try {
      const result = await triggerScan();
      setActiveScanId(result.id);
    } catch (err) {
      setScanError(err.response?.data?.detail || 'Failed to trigger scan.');
    }
  };

  const handleScanDone = (scan) => {
    setActiveScanId(null);
    if (scan.status === 'completed') {
      queryClient.invalidateQueries({ queryKey: ['scans', projectId] });
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
    }
  };

  const completedScans = scans.filter((s) => s.status === 'completed');
  const latestCompleted = useMemo(() => {
    if (completedScans.length === 0) return null;
    return completedScans
      .slice()
      .sort((a, b) => new Date(b.scan_time) - new Date(a.scan_time))[0];
  }, [completedScans]);

  const scanInProgress =
    !!activeScanId ||
    scans.some((s) => s.status === 'pending' || s.status === 'running');

  const securityScore = latestCompleted
    ? computeSecurityScore({
        critical: latestCompleted.critical_count,
        high: latestCompleted.high_count,
        medium: latestCompleted.medium_count,
        low: latestCompleted.low_count,
      })
    : 100;

  const filesTotal = files.length;
  const filesScanned = scanInProgress
    ? Math.max(0, Math.floor(filesTotal * 0.4))
    : latestCompleted
      ? filesTotal
      : 0;

  if (projLoading) {
    return (
      <div className="h-96 flex flex-col items-center justify-center gap-3">
        <Spinner size="lg" />
        <p className="text-sm font-mono text-[var(--text-secondary)]">LOADING_PROJECT...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--border-glow)] pb-6">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] mb-2">
            <span
              className="hover:text-[var(--signal-green)] cursor-pointer"
              onClick={() => navigate('/')}
            >
              Dashboard
            </span>
            <ChevronRight className="h-3 w-3" />
            <span className="text-[var(--text-primary)]">{project?.project_name}</span>
          </div>
          <h2 className="text-xl font-display font-semibold text-[var(--text-primary)]">
            {project?.project_name}
          </h2>
          <p className="text-sm text-[var(--text-secondary)] mt-1 font-mono">ID: {projectId}</p>
        </div>
        <div className="flex gap-3 self-start md:self-auto">
          <Button
            onClick={() => navigate(`/projects/${projectId}/results`)}
            variant="secondary"
            className="gap-2"
          >
            <BarChart3 className="h-4 w-4" />
            View Findings
          </Button>
          <Button
            onClick={handleScanNow}
            isLoading={isTriggering || !!activeScanId}
            disabled={files.length === 0}
            className="gap-2"
          >
            <PlayCircle className="h-4 w-4" />
            Scan Now
          </Button>
        </div>
      </div>

      <Panel title="Project Signal" status={scoreStatus(securityScore)} hoverable={false}>
        <ScoreRings
          score={securityScore}
          filesScanned={filesScanned}
          filesTotal={filesTotal}
          scanInProgress={scanInProgress}
        />
      </Panel>

      {scanError && (
        <div
          className="flex items-center gap-2 p-4 rounded-[10px] text-sm border"
          style={{
            background: 'rgba(229,72,77,0.1)',
            borderColor: 'rgba(229,72,77,0.25)',
            color: 'var(--sev-critical)',
          }}
        >
          <AlertTriangle className="h-5 w-5 shrink-0" />
          {scanError}
        </div>
      )}

      {activeScanId && (
        <ScanPoller scanId={activeScanId} projectId={projectId} onDone={handleScanDone} />
      )}

      {(files.length > 0 || vulnerabilities.length > 0) && (
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
          <div className="xl:col-span-3">
            <CodebaseVulnerabilityMap
              files={files}
              vulnerabilities={vulnerabilities}
              projectId={projectId}
            />
          </div>
          <div className="xl:col-span-2">
            <DetectionBreakdownBars vulnerabilities={vulnerabilities} />
          </div>
        </div>
      )}

      {scans.length > 0 && <ScanTimeline scans={scans} />}

      <section>
        <h3 className="text-xs font-bold font-mono uppercase tracking-widest text-[var(--text-secondary)] mb-4">
          Source Code Upload
        </h3>
        <FileDropzone
          onUpload={handleUpload}
          isUploading={isUploading}
          allowedExtensions={['py', 'js', 'ts', 'java', 'c', 'cpp', 'php', 'zip']}
        />
        {isUploading && (
          <div className="mt-3">
            <div className="flex justify-between text-xs font-mono text-[var(--text-secondary)] mb-1">
              <span>Uploading...</span>
              <span>{uploadProgress}%</span>
            </div>
            <div className="w-full bg-[var(--bg-panel-hover)] rounded-full h-1.5 border border-[var(--border-glow)]">
              <div
                className="bg-[var(--signal-green)] h-1.5 rounded-full transition-all duration-200"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
          </div>
        )}
        {uploadError && (
          <div
            className="flex items-center gap-2 mt-3 p-3 rounded-lg text-xs border"
            style={{
              background: 'rgba(229,72,77,0.1)',
              borderColor: 'rgba(229,72,77,0.25)',
              color: 'var(--sev-critical)',
            }}
          >
            <AlertTriangle className="h-4 w-4 shrink-0" />
            {uploadError}
          </div>
        )}
      </section>

      <section>
        <h3 className="text-xs font-bold font-mono uppercase tracking-widest text-[var(--text-secondary)] mb-4">
          Uploaded Files (<span className="font-mono">{files.length}</span>)
        </h3>
        {filesLoading ? (
          <Spinner size="sm" className="py-4" />
        ) : files.length === 0 ? (
          <EmptyState
            title="No files uploaded"
            description="Upload source files or a ZIP archive to begin scanning."
            icon={FolderOpen}
          />
        ) : (
          <Panel noPadding hoverable={false}>
            {files.map((file, idx) => {
              const ext = file.filename?.split('.').pop()?.toLowerCase() || 'file';
              const emoji = LANG_ICONS[ext] || '📄';
              const sizeKB = file.size ? `${(file.size / 1024).toFixed(1)} KB` : '—';
              return (
                <div
                  key={file.id}
                  className={`flex items-center gap-4 px-5 py-3 text-sm ${
                    idx > 0 ? 'border-t border-[var(--border-glow)]' : ''
                  }`}
                >
                  <span className="text-base">{emoji}</span>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-[var(--text-primary)] truncate font-mono text-xs">
                      {file.filename}
                    </p>
                    <p className="text-[10px] text-[var(--text-secondary)] font-mono">
                      {file.language} · {sizeKB}
                    </p>
                  </div>
                  <span className="text-[10px] font-mono text-[var(--text-secondary)] uppercase bg-[var(--bg-panel-hover)] border border-[var(--border-glow)] px-2 py-0.5 rounded-full">
                    {ext}
                  </span>
                </div>
              );
            })}
          </Panel>
        )}
      </section>

      <section>
        <h3 className="text-xs font-bold font-mono uppercase tracking-widest text-[var(--text-secondary)] mb-4">
          Scan History (<span className="font-mono">{scans.length}</span>)
        </h3>
        {scansLoading ? (
          <Spinner size="sm" className="py-4" />
        ) : scans.length === 0 ? (
          <EmptyState
            title="No scans run yet"
            description="Upload your code and click 'Scan Now' to detect vulnerabilities."
            icon={PlayCircle}
          />
        ) : (
          <Panel noPadding hoverable={false}>
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="border-b border-[var(--border-glow)] bg-[var(--bg-void)]/40 text-[var(--text-secondary)] text-xs font-mono uppercase tracking-wider">
                  <th className="py-4 px-6">Date</th>
                  <th className="py-4 px-6">Status</th>
                  <th className="py-4 px-6">Total Issues</th>
                  <th className="py-4 px-6">Breakdown</th>
                  <th className="py-4 px-6" />
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-glow)]">
                {scans
                  .slice()
                  .sort((a, b) => new Date(b.scan_time) - new Date(a.scan_time))
                  .map((scan) => (
                    <tr
                      key={scan.id}
                      className="hover:bg-[var(--bg-panel-hover)] transition-colors"
                    >
                      <td className="py-4 px-6 text-sm text-[var(--text-primary)] font-mono">
                        {new Date(scan.scan_time).toLocaleString()}
                      </td>
                      <td className="py-4 px-6">
                        <StatusBadge status={scan.status} />
                      </td>
                      <td className="py-4 px-6 text-sm font-bold text-[var(--text-primary)] font-mono">
                        {scan.total_issues ?? '—'}
                      </td>
                      <td className="py-4 px-6">
                        <div className="flex gap-1 text-[9px] font-mono font-bold">
                          {scan.critical_count > 0 && (
                            <span
                              className="px-1.5 py-0.5 rounded-full border"
                              style={{
                                background: 'rgba(229,72,77,0.15)',
                                color: 'var(--sev-critical)',
                                borderColor: 'var(--sev-critical)',
                              }}
                            >
                              {scan.critical_count} C
                            </span>
                          )}
                          {scan.high_count > 0 && (
                            <span
                              className="px-1.5 py-0.5 rounded-full border"
                              style={{
                                background: 'rgba(245,166,35,0.15)',
                                color: 'var(--sev-high)',
                                borderColor: 'var(--sev-high)',
                              }}
                            >
                              {scan.high_count} H
                            </span>
                          )}
                          {scan.medium_count > 0 && (
                            <span
                              className="px-1.5 py-0.5 rounded-full border"
                              style={{
                                background: 'rgba(240,201,74,0.15)',
                                color: 'var(--sev-medium)',
                                borderColor: 'var(--sev-medium)',
                              }}
                            >
                              {scan.medium_count} M
                            </span>
                          )}
                          {scan.low_count > 0 && (
                            <span
                              className="px-1.5 py-0.5 rounded-full border"
                              style={{
                                background: 'rgba(79,209,197,0.15)',
                                color: 'var(--sev-low)',
                                borderColor: 'var(--sev-low)',
                              }}
                            >
                              {scan.low_count} L
                            </span>
                          )}
                          {scan.total_issues === 0 && (
                            <span className="text-[var(--signal-green)]">Clean ✓</span>
                          )}
                        </div>
                      </td>
                      <td className="py-4 px-6">
                        {scan.status === 'completed' && (
                          <button
                            onClick={() => navigate(`/projects/${projectId}/results`)}
                            className="flex items-center gap-1 text-xs text-[var(--signal-green)] hover:text-[var(--signal-green-bright)] transition-colors"
                          >
                            View <ArrowUpRight className="h-3 w-3" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </Panel>
        )}
      </section>
    </div>
  );
};

export default ProjectPage;
