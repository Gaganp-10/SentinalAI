import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useProjectDetails } from '../hooks/useProjects';
import { downloadReport } from '../api/reports';
import Button from '../components/common/Button';
import Spinner from '../components/common/Spinner';
import Panel from '../components/common/Panel';
import {
  ChevronRight,
  Download,
  FileText,
  FileCode,
  FileJson,
  FileSpreadsheet,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';

const REPORT_FORMATS = [
  {
    format: 'pdf',
    label: 'PDF Report',
    description:
      'Formatted executive summary with vulnerability details, severity charts, and remediation guidance.',
    icon: FileText,
    color: 'var(--sev-critical)',
    bg: 'rgba(229,72,77,0.12)',
  },
  {
    format: 'html',
    label: 'HTML Report',
    description:
      'Interactive web-based report viewable in any browser. Includes syntax-highlighted code snippets.',
    icon: FileCode,
    color: 'var(--sev-high)',
    bg: 'rgba(245,166,35,0.12)',
  },
  {
    format: 'json',
    label: 'JSON Export',
    description:
      'Machine-readable structured export. Integrate with CI/CD pipelines, SIEM tools, or dashboards.',
    icon: FileJson,
    color: 'var(--sev-low)',
    bg: 'rgba(79,209,197,0.12)',
  },
  {
    format: 'csv',
    label: 'CSV Spreadsheet',
    description:
      'Flat table of all findings. Import into Excel, Google Sheets, or your issue tracker.',
    icon: FileSpreadsheet,
    color: 'var(--signal-green)',
    bg: 'rgba(46,204,113,0.12)',
  },
];

const ReportsPage = () => {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const { project, isLoading } = useProjectDetails(projectId);

  const [downloading, setDownloading] = useState({});
  const [errors, setErrors] = useState({});
  const [success, setSuccess] = useState({});

  const handleDownload = async (format) => {
    setErrors((prev) => ({ ...prev, [format]: null }));
    setSuccess((prev) => ({ ...prev, [format]: false }));
    setDownloading((prev) => ({ ...prev, [format]: true }));
    try {
      await downloadReport(projectId, format, project?.project_name || 'project');
      setSuccess((prev) => ({ ...prev, [format]: true }));
      setTimeout(() => setSuccess((prev) => ({ ...prev, [format]: false })), 3000);
    } catch (err) {
      setErrors((prev) => ({
        ...prev,
        [format]:
          err.response?.data?.detail || `Failed to download ${format.toUpperCase()} report.`,
      }));
    } finally {
      setDownloading((prev) => ({ ...prev, [format]: false }));
    }
  };

  if (isLoading) {
    return (
      <div className="h-64 flex flex-col items-center justify-center gap-3">
        <Spinner size="lg" />
        <p className="text-sm font-mono text-[var(--text-secondary)]">LOADING...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-3xl">
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
          <span className="text-[var(--text-primary)]">Reports</span>
        </div>
        <h2 className="text-xl font-display font-semibold text-[var(--text-primary)]">
          Download Reports
        </h2>
        <p className="text-sm text-[var(--text-secondary)] mt-1">
          Export your scan findings in multiple formats for audits, CI/CD integration, or
          stakeholder reports.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {REPORT_FORMATS.map(({ format, label, description, icon: Icon, color, bg }) => (
          <Panel key={format} hoverable>
            <div className="flex flex-col gap-4 -my-1">
              <div className="flex items-start gap-4">
                <div
                  className="p-2.5 rounded-lg border shrink-0"
                  style={{ background: bg, borderColor: color }}
                >
                  <Icon className="h-5 w-5" style={{ color }} />
                </div>
                <div>
                  <h3 className="font-display font-semibold text-[var(--text-primary)] text-sm">
                    {label}
                  </h3>
                  <p className="text-xs text-[var(--text-secondary)] mt-1 leading-relaxed">
                    {description}
                  </p>
                </div>
              </div>

              {errors[format] && (
                <div
                  className="flex items-center gap-2 p-3 rounded-lg text-xs border"
                  style={{
                    background: 'rgba(229,72,77,0.1)',
                    borderColor: 'rgba(229,72,77,0.25)',
                    color: 'var(--sev-critical)',
                  }}
                >
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  {errors[format]}
                </div>
              )}
              {success[format] && (
                <div
                  className="flex items-center gap-2 p-3 rounded-lg text-xs border"
                  style={{
                    background: 'rgba(46,204,113,0.1)',
                    borderColor: 'rgba(46,204,113,0.25)',
                    color: 'var(--signal-green)',
                  }}
                >
                  <CheckCircle2 className="h-4 w-4 shrink-0" />
                  Downloaded successfully!
                </div>
              )}

              <Button
                onClick={() => handleDownload(format)}
                isLoading={downloading[format]}
                variant="secondary"
                className="gap-2 w-full justify-center"
              >
                <Download className="h-4 w-4" />
                Download {format.toUpperCase()}
              </Button>
            </div>
          </Panel>
        ))}
      </div>

      <Panel status="green" hoverable={false}>
        <div className="flex items-start gap-3 -my-1">
          <FileText className="h-5 w-5 text-[var(--signal-green)] shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-[var(--text-primary)] mb-1 text-sm">
              Reports include all vulnerabilities from the latest completed scan
            </p>
            <p className="text-xs text-[var(--text-secondary)]">
              Run a new scan before downloading to ensure the report reflects the most recent
              findings.
            </p>
          </div>
        </div>
      </Panel>
    </div>
  );
};

export default ReportsPage;
