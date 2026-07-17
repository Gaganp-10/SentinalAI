import React, { useState } from 'react';
import { NavLink, useParams, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import {
  LayoutDashboard,
  FolderGit2,
  ScanLine,
  FileText,
  LogOut,
  User as UserIcon,
  ChevronLeft,
  ChevronRight,
  Radio,
} from 'lucide-react';

const NAV_LINK_BASE =
  'flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors duration-150 group';
const NAV_ACTIVE =
  'bg-[var(--bg-panel-hover)] text-[var(--signal-green)] border border-[var(--border-glow)]';
const NAV_INACTIVE =
  'text-[var(--text-secondary)] hover:bg-[var(--bg-panel-hover)] hover:text-[var(--text-primary)]';

function NavItem({ to, end = false, icon: Icon, label, collapsed }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `${NAV_LINK_BASE} ${isActive ? NAV_ACTIVE : NAV_INACTIVE}`
      }
      title={collapsed ? label : undefined}
    >
      {({ isActive }) => (
        <>
          <Icon
            className={`h-4 w-4 shrink-0 transition-colors ${
              isActive
                ? 'text-[var(--signal-green)]'
                : 'text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]'
            }`}
          />
          {!collapsed && <span className="truncate leading-none">{label}</span>}
        </>
      )}
    </NavLink>
  );
}

const Sidebar = () => {
  const { user, logout } = useAuth();
  const { projectId } = useParams();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);

  const currentProjectId =
    projectId ||
    (location.pathname.startsWith('/projects/')
      ? location.pathname.split('/')[2]
      : null);

  const w = collapsed ? 'w-[56px]' : 'w-[220px]';

  return (
    <aside
      className={`${w} bg-[var(--bg-panel)]/95 border-r border-[var(--border-glow)] flex flex-col h-screen sticky top-0 shrink-0 transition-all duration-200 backdrop-blur-sm`}
    >
      <div className={`flex items-center gap-3 px-4 py-5 border-b border-[var(--border-glow)] ${collapsed ? 'justify-center' : ''}`}>
        <div className="shrink-0 p-1.5 rounded-md bg-[var(--bg-panel-hover)] border border-[var(--border-glow)]">
          <Radio className="h-4 w-4 text-[var(--signal-green)]" />
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <h1 className="font-display font-bold text-sm text-[var(--text-primary)] leading-none">
              Signal Room
            </h1>
            <span className="text-[10px] font-mono text-[var(--text-secondary)] uppercase tracking-widest">
              Security Scanner
            </span>
          </div>
        )}
      </div>

      <nav className="flex-1 px-2 py-4 space-y-0.5 overflow-y-auto">
        {!collapsed && (
          <p className="px-3 mb-2 text-[10px] font-mono font-semibold text-[var(--text-secondary)] uppercase tracking-widest">
            Navigation
          </p>
        )}
        <NavItem to="/" end icon={LayoutDashboard} label="Dashboard" collapsed={collapsed} />

        {currentProjectId && (
          <div className="pt-4 mt-4 border-t border-[var(--border-glow)]">
            {!collapsed && (
              <p className="px-3 mb-2 text-[10px] font-mono font-semibold text-[var(--text-secondary)] uppercase tracking-widest">
                Active Project
              </p>
            )}
            <NavItem
              to={`/projects/${currentProjectId}`}
              end
              icon={FolderGit2}
              label="Files & Scans"
              collapsed={collapsed}
            />
            <NavItem
              to={`/projects/${currentProjectId}/results`}
              icon={ScanLine}
              label="Vulnerabilities"
              collapsed={collapsed}
            />
            <NavItem
              to={`/projects/${currentProjectId}/reports`}
              icon={FileText}
              label="Reports"
              collapsed={collapsed}
            />
          </div>
        )}
      </nav>

      <div className="p-2 border-t border-[var(--border-glow)] space-y-2">
        <div
          className={`flex items-center gap-2 px-2 py-2 rounded-md bg-[var(--bg-panel-hover)] border border-[var(--border-glow)] ${
            collapsed ? 'justify-center' : 'justify-between'
          }`}
        >
          <div className="flex items-center gap-2 overflow-hidden">
            <div className="shrink-0 h-6 w-6 rounded-full bg-[var(--border-glow)] border border-[var(--border-glow)] flex items-center justify-center">
              <UserIcon className="h-3.5 w-3.5 text-[var(--text-secondary)]" />
            </div>
            {!collapsed && (
              <div className="overflow-hidden">
                <p className="text-xs font-semibold text-[var(--text-primary)] truncate leading-none">
                  {user?.username || 'User'}
                </p>
                <p className="text-[10px] text-[var(--text-secondary)] truncate font-mono">
                  {user?.email || ''}
                </p>
              </div>
            )}
          </div>
          {!collapsed && (
            <button
              onClick={logout}
              title="Log Out"
              className="p-1 rounded text-[var(--text-secondary)] hover:text-[var(--sev-critical)] hover:bg-[rgba(229,72,77,0.08)] transition-colors"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <button
          onClick={() => setCollapsed(c => !c)}
          className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-[var(--text-secondary)] hover:bg-[var(--bg-panel-hover)] hover:text-[var(--text-primary)] transition-colors text-xs font-mono ${
            collapsed ? 'justify-center' : ''
          }`}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? (
            <ChevronRight className="h-3.5 w-3.5" />
          ) : (
            <>
              <ChevronLeft className="h-3.5 w-3.5" />
              <span>Collapse</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
