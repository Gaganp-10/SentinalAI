import React, { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './context/AuthContext';
import AppLayout from './components/layout/AppLayout';
import Spinner from './components/common/Spinner';
import SecurityMentorChat from './components/ai/SecurityMentorChat';

// Code-split all pages for smaller initial bundle
const LoginPage = lazy(() => import('./pages/LoginPage'));
const SignupPage = lazy(() => import('./pages/SignupPage'));
const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const ProjectPage = lazy(() => import('./pages/ProjectPage'));
const ScanResultsPage = lazy(() => import('./pages/ScanResultsPage'));
const VulnerabilityDetailPage = lazy(() => import('./pages/VulnerabilityDetailPage'));
const ReportsPage = lazy(() => import('./pages/ReportsPage'));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});

const PageLoader = () => (
  <div
    className="h-screen w-screen flex flex-col items-center justify-center gap-3"
    style={{ background: 'var(--bg-void)' }}
  >
    <Spinner size="lg" />
    <p className="text-xs font-mono text-[var(--text-secondary)] animate-pulse">LOADING_MODULE...</p>
  </div>
);

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Suspense fallback={<PageLoader />}>
            <Routes>
              {/* Public Routes */}
              <Route path="/login" element={<LoginPage />} />
              <Route path="/signup" element={<SignupPage />} />

              {/* Protected Routes — wrapped in AppLayout (auth guard) */}
              <Route element={<AppLayout />}>
                <Route index element={<DashboardPage />} />
                <Route path="projects/:projectId" element={<ProjectPage />} />
                <Route path="projects/:projectId/results" element={<ScanResultsPage />} />
                <Route path="projects/:projectId/reports" element={<ReportsPage />} />
                <Route path="vulnerabilities/:vulnId" element={<VulnerabilityDetailPage />} />
              </Route>

              {/* Fallback redirect */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>

          {/* Security Mentor — global floating chat widget for authenticated views */}
          <SecurityMentorChat />
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
