import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { signup } from '../api/auth';
import { ShieldAlert, AlertCircle, CheckCircle2 } from 'lucide-react';
import Button from '../components/common/Button';
import Panel from '../components/common/Panel';
import AmbientBackground from '../components/layout/AmbientBackground';

const SignupPage = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');

    if (password !== confirmPassword) {
      setErrorMsg('Passwords do not match.');
      return;
    }

    setIsLoading(true);
    try {
      await signup(username, email, password);
      setSuccessMsg('Account created successfully! Redirecting to login...');
      setTimeout(() => {
        navigate('/login');
      }, 2000);
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'Registration failed. Please check credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      className="relative min-h-screen flex flex-col items-center justify-center p-4"
      style={{ background: 'var(--bg-void)' }}
    >
      <AmbientBackground />
      <Panel className="relative z-10 w-full max-w-md" hoverable={false}>
        <div className="flex flex-col items-center mb-8">
          <div
            className="p-3 rounded-[10px] border mb-3"
            style={{
              background: 'rgba(46,204,113,0.1)',
              borderColor: 'rgba(46,204,113,0.3)',
            }}
          >
            <ShieldAlert className="h-8 w-8 text-[var(--signal-green)]" />
          </div>
          <h2 className="text-lg font-display font-semibold text-[var(--text-primary)]">
            Create Account
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-1 font-mono uppercase tracking-wider">
            Join Security Scanner
          </p>
        </div>

        {errorMsg && (
          <div
            className="flex items-center gap-2 mb-6 p-4 rounded-lg text-sm border"
            style={{
              background: 'rgba(229,72,77,0.1)',
              borderColor: 'rgba(229,72,77,0.25)',
              color: 'var(--sev-critical)',
            }}
          >
            <AlertCircle className="h-5 w-5 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {successMsg && (
          <div
            className="flex items-center gap-2 mb-6 p-4 rounded-lg text-sm border"
            style={{
              background: 'rgba(46,204,113,0.1)',
              borderColor: 'rgba(46,204,113,0.25)',
              color: 'var(--signal-green)',
            }}
          >
            <CheckCircle2 className="h-5 w-5 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wide mb-2 font-mono">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. secdev"
              className="input-field"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wide mb-2 font-mono">
              Email Address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="e.g. dev@company.com"
              className="input-field"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wide mb-2 font-mono">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="input-field"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wide mb-2 font-mono">
              Confirm Password
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="••••••••"
              className="input-field"
              required
            />
          </div>

          <Button type="submit" className="w-full" isLoading={isLoading}>
            Register
          </Button>
        </form>

        <div className="text-center mt-6">
          <p className="text-xs text-[var(--text-secondary)]">
            Already have an account?{' '}
            <Link
              to="/login"
              className="text-[var(--signal-green)] hover:text-[var(--signal-green-bright)] font-medium transition-colors"
            >
              Sign in
            </Link>
          </p>
        </div>
      </Panel>
    </div>
  );
};

export default SignupPage;
