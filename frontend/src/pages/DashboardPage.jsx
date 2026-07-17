import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useProjects } from '../hooks/useProjects';
import { useAuth } from '../context/AuthContext';
import client from '../api/client';
import { getFiles } from '../api/files';
import Button from '../components/common/Button';
import Modal from '../components/common/Modal';
import Spinner from '../components/common/Spinner';
import EmptyState from '../components/common/EmptyState';
import Panel from '../components/common/Panel';
import SeverityPieChart from '../components/dashboard/SeverityPieChart';
import ScanTrendChart from '../components/dashboard/ScanTrendChart';
import ScoreRings from '../components/dashboard/ScoreRings';
import { computeSecurityScore, scoreStatus } from '../utils/securityScore';
import {
  FolderGit2,
  Plus,
  Calendar,
  ShieldAlert,
  FolderPlus,
} from 'lucide-react';

const DashboardPage = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { projects, isLoading, createProject, isCreating } = useProjects();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [projectName, setProjectName] = useState('');
  const [projectScans, setProjectScans] = useState({});
  const [projectFiles, setProjectFiles] = useState({});
  const [formError, setFormError] = useState('');

  useEffect(() => {
    const fetchAllProjectMeta = async () => {
      if (projects.length === 0) return;
      const scansData = {};
      const filesData = {};
      try {
        await Promise.all(
          projects.map(async (proj) => {
            const [{ data: scans }, files] = await Promise.all([
              client.get(`/projects/${proj.id}/scans`),
              getFiles(proj.id).catch(() => []),
            ]);
            scansData[proj.id] = scans;
            filesData[proj.id] = files;
          })
        );
        setProjectScans(scansData);
        setProjectFiles(filesData);
      } catch (err) {
        console.error('Failed to load project scans for stats:', err);
      }
    };
    fetchAllProjectMeta();
  }, [projects]);

  const handleCreateProject = async (e) => {
    e.preventDefault();
    setFormError('');
    if (!projectName.trim()) {
      setFormError('Project name cannot be empty.');
      return;
    }
    try {
      const newProj = await createProject(projectName);
      setIsModalOpen(false);
      setProjectName('');
      navigate(`/projects/${newProj.id}`);
    } catch (err) {
      setFormError(err.response?.data?.detail || 'Failed to create project.');
    }
  };

  let totalCritical = 0;
  let totalHigh = 0;
  let totalMedium = 0;
  let totalLow = 0;
  let scoreSum = 0;
  let completedScansCount = 0;
  let totalFiles = 0;
  let scannedFiles = 0;
  let anyScanRunning = false;
  const allCompletedScans = [];

  Object.entries(projectScans).forEach(([projId, scansList]) => {
    const files = projectFiles[projId] || [];
    totalFiles += files.length;

    if (scansList.some((s) => s.status === 'pending' || s.status === 'running')) {
      anyScanRunning = true;
    }

    const completedScans = scansList.filter((s) => s.status === 'completed');
    if (completedScans.length > 0) {
      scannedFiles += files.length;
      const sorted = completedScans.sort(
        (a, b) => new Date(b.scan_time) - new Date(a.scan_time)
      );
      const latest = sorted[0];
      totalCritical += latest.critical_count;
      totalHigh += latest.high_count;
      totalMedium += latest.medium_count;
      totalLow += latest.low_count;
      scoreSum += computeSecurityScore({
        critical: latest.critical_count,
        high: latest.high_count,
        medium: latest.medium_count,
        low: latest.low_count,
      });
      completedScansCount += 1;
    }
    allCompletedScans.push(...completedScans);
  });

  const averageSecurityScore =
    completedScansCount > 0 ? Math.round(scoreSum / completedScansCount) : 100;

  if (isLoading) {
    return (
      <div className="h-96 flex flex-col items-center justify-center gap-3">
        <Spinner size="lg" />
        <p className="text-sm font-mono text-[var(--text-secondary)]">LOADING_PROJECTS...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--border-glow)] pb-6">
        <div>
          <h2 className="text-xl font-display font-semibold text-[var(--text-primary)]">
            Welcome, {user?.username}
          </h2>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            Monitor and remediate code vulnerabilities in your active workspaces.
          </p>
        </div>
        <Button onClick={() => setIsModalOpen(true)} className="gap-2 self-start md:self-auto">
          <Plus className="h-4 w-4" />
          New Project
        </Button>
      </div>

      {projects.length > 0 && (
        <Panel
          title="Workspace Signal"
          status={scoreStatus(averageSecurityScore)}
          hoverable={false}
        >
          <ScoreRings
            score={averageSecurityScore}
            filesScanned={anyScanRunning ? Math.floor(scannedFiles * 0.5) : scannedFiles}
            filesTotal={totalFiles}
            scanInProgress={anyScanRunning}
          />
        </Panel>
      )}

      {projects.length > 0 && completedScansCount > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Panel title="Severity Breakdown" hoverable={false}>
            <div className="h-48">
              <SeverityPieChart
                critical={totalCritical}
                high={totalHigh}
                medium={totalMedium}
                low={totalLow}
              />
            </div>
          </Panel>

          <Panel title="Global Scan Trend" hoverable={false}>
            <div className="h-48">
              <ScanTrendChart scans={allCompletedScans} />
            </div>
          </Panel>
        </div>
      )}

      <div>
        <h3 className="text-xs font-bold font-mono text-[var(--text-secondary)] uppercase tracking-widest mb-4">
          Projects ({projects.length})
        </h3>

        {projects.length === 0 ? (
          <EmptyState
            title="No projects found"
            description="Create your first scan project space to upload codebase and inspect vulnerabilities."
            icon={FolderPlus}
          >
            <Button onClick={() => setIsModalOpen(true)} className="gap-2">
              <Plus className="h-4 w-4" />
              New Project
            </Button>
          </EmptyState>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {projects.map((proj) => {
              const scans = projectScans[proj.id] || [];
              const completed = scans.filter((s) => s.status === 'completed');
              const hasScan = completed.length > 0;

              let latestScan = null;
              let score = 100;

              if (hasScan) {
                const sorted = completed.sort(
                  (a, b) => new Date(b.scan_time) - new Date(a.scan_time)
                );
                latestScan = sorted[0];
                score = computeSecurityScore({
                  critical: latestScan.critical_count,
                  high: latestScan.high_count,
                  medium: latestScan.medium_count,
                  low: latestScan.low_count,
                });
              }

              return (
                <Panel
                  key={proj.id}
                  onClick={() => navigate(`/projects/${proj.id}`)}
                  status={hasScan ? scoreStatus(score) : undefined}
                >
                  <div className="flex justify-between items-start mb-4">
                    <div className="bg-[var(--bg-panel-hover)] p-2 rounded-lg border border-[var(--border-glow)]">
                      <FolderGit2 className="h-5 w-5 text-[var(--text-secondary)]" />
                    </div>
                    {hasScan && (
                      <span
                        className="text-[10px] font-bold font-mono px-2 py-0.5 rounded-full border"
                        style={{
                          color:
                            score > 80
                              ? 'var(--signal-green)'
                              : score >= 50
                                ? 'var(--sev-high)'
                                : 'var(--sev-critical)',
                          background:
                            score > 80
                              ? 'rgba(46,204,113,0.15)'
                              : score >= 50
                                ? 'rgba(245,166,35,0.15)'
                                : 'rgba(229,72,77,0.15)',
                          borderColor:
                            score > 80
                              ? 'var(--signal-green)'
                              : score >= 50
                                ? 'var(--sev-high)'
                                : 'var(--sev-critical)',
                        }}
                      >
                        <span className="font-mono">{score}</span> Score
                      </span>
                    )}
                  </div>

                  <h4 className="font-display font-semibold text-[var(--text-primary)] text-base truncate">
                    {proj.project_name}
                  </h4>

                  <div className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)] mt-3 font-mono">
                    <Calendar className="h-3.5 w-3.5" />
                    <span>
                      {proj.scan_date
                        ? `Scanned: ${new Date(proj.scan_date).toLocaleDateString()}`
                        : 'Never Scanned'}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 text-xs mt-4 pt-4 border-t border-[var(--border-glow)]">
                    {hasScan ? (
                      <div className="flex items-center justify-between w-full">
                        <span className="text-[var(--text-secondary)] text-xs font-semibold">
                          <span className="font-mono text-[var(--text-primary)]">
                            {latestScan.total_issues}
                          </span>{' '}
                          {latestScan.total_issues === 1 ? 'Vulnerability' : 'Vulnerabilities'}
                        </span>
                        <div className="flex gap-1.5 text-[9px] font-bold font-mono">
                          {latestScan.critical_count + latestScan.high_count > 0 && (
                            <span
                              className="px-1.5 py-0.5 rounded-full border"
                              style={{
                                background: 'rgba(229,72,77,0.15)',
                                color: 'var(--sev-critical)',
                                borderColor: 'var(--sev-critical)',
                              }}
                            >
                              {latestScan.critical_count + latestScan.high_count} H/C
                            </span>
                          )}
                          {latestScan.medium_count > 0 && (
                            <span
                              className="px-1.5 py-0.5 rounded-full border"
                              style={{
                                background: 'rgba(240,201,74,0.15)',
                                color: 'var(--sev-medium)',
                                borderColor: 'var(--sev-medium)',
                              }}
                            >
                              {latestScan.medium_count} M
                            </span>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5 text-[var(--text-secondary)] font-mono text-[10px] uppercase">
                        <ShieldAlert className="h-3.5 w-3.5" />
                        No scan findings
                      </div>
                    )}
                  </div>
                </Panel>
              );
            })}
          </div>
        )}
      </div>

      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Create New Project"
        footer={
          <>
            <Button variant="ghost" onClick={() => setIsModalOpen(false)} disabled={isCreating}>
              Cancel
            </Button>
            <Button onClick={handleCreateProject} isLoading={isCreating}>
              Create Project
            </Button>
          </>
        }
      >
        <form onSubmit={handleCreateProject} className="space-y-4">
          {formError && (
            <div
              className="p-3 text-xs rounded-lg border"
              style={{
                background: 'rgba(229,72,77,0.1)',
                borderColor: 'rgba(229,72,77,0.25)',
                color: 'var(--sev-critical)',
              }}
            >
              {formError}
            </div>
          )}
          <div>
            <label className="block text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2 font-mono">
              Project Name
            </label>
            <input
              type="text"
              placeholder="e.g. ecommerce-backend"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              className="input-field"
              required
              disabled={isCreating}
            />
          </div>
        </form>
      </Modal>
    </div>
  );
};

export default DashboardPage;
