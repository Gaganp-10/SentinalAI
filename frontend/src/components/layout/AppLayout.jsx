import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import Sidebar from './Sidebar';
import Navbar from './Navbar';
import Spinner from '../common/Spinner';
import AmbientBackground from './AmbientBackground';

const AppLayout = () => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div
        className="relative h-screen w-screen flex flex-col items-center justify-center gap-4"
        style={{ background: 'var(--bg-void)' }}
      >
        <AmbientBackground />
        <div className="relative z-10 flex flex-col items-center gap-4">
          <Spinner size="md" />
          <p className="text-xs font-mono text-[var(--text-secondary)] tracking-widest uppercase animate-pulse">
            Verifying credentials...
          </p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div
      className="relative flex h-screen w-screen overflow-hidden"
      style={{ background: 'var(--bg-void)' }}
    >
      <AmbientBackground />

      <div className="relative z-10 flex h-full w-full overflow-hidden">
        <Sidebar />

        <div className="flex-1 flex flex-col h-full min-w-0 overflow-hidden">
          <Navbar />

          <main
            className="flex-1 overflow-y-auto px-8 py-7"
            style={{ background: 'transparent' }}
          >
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
};

export default AppLayout;
