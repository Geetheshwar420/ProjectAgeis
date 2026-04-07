
import React, { useState } from 'react';
import { User as UserIcon, Lock as LockIcon, ArrowRight, Eye, EyeOff, CheckCircle, AlertCircle } from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

interface LoginPageProps {
  onLogin: () => void;
  onNavigateSignup: () => void;
  onNavigateHome: () => void;
}

const LoginPage: React.FC<LoginPageProps> = ({ onLogin, onNavigateSignup, onNavigateHome }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const { login, loginWithGoogle } = useAuth(); // Import handleGoogleLogin

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!email || !password) {
      setError('Please fill in all fields');
      return;
    }

    setIsLoading(true);

    try {
      await login(email, password);
      onLogin();
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    setIsLoading(true);
    setError('');
    try {
      await loginWithGoogle();
      onLogin();
    } catch (err: any) {
      setError(err.message || 'Google Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-white dark:bg-black relative overflow-hidden px-4 font-sans selection:bg-emerald-500 selection:text-black">
      {/* Stark Background Pattern */}
      <div className="fixed inset-0 pointer-events-none z-0 opacity-[0.03] dark:opacity-[0.05]"
        style={{ backgroundImage: 'linear-gradient(to right, #000 1px, transparent 1px), linear-gradient(to bottom, #000 1px, transparent 1px)', backgroundSize: '40px 40px' }} />

      {/* Return Button */}
      <div className="absolute top-4 left-4 z-50 animate-fade-in">
        <button onClick={onNavigateHome} className="bg-white dark:bg-black text-black dark:text-white font-black hover:bg-emerald-500 hover:text-black transition-colors text-xs md:text-sm flex items-center gap-2 uppercase tracking-widest border-2 border-black dark:border-white p-2 md:p-3 shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff] hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#000] dark:hover:shadow-[2px_2px_0px_#fff] active:shadow-none active:translate-x-[4px] active:translate-y-[4px]">
          &larr; REVERT TO BASE
        </button>
      </div>

      <div className="relative w-full max-w-md z-10 animate-fade-in mt-16 md:mt-0">

        {/* Card */}
        <div className="bg-white dark:bg-black border-4 border-black dark:border-white shadow-[12px_12px_0px_#10b981] p-8 md:p-10 relative">
          {/* Decorative Corner Tabs */}
          <div className="absolute top-0 left-0 w-8 h-8 border-b-4 border-r-4 border-black dark:border-white" />
          <div className="absolute bottom-0 right-0 w-8 h-8 border-t-4 border-l-4 border-black dark:border-white" />

          <div className="text-center mb-8">
            <div className="w-16 h-16 bg-emerald-500 border-2 border-black dark:border-white mx-auto flex items-center justify-center mb-4 shadow-[4px_4px_0px_#000] dark:shadow-[4px_4px_0px_#fff]">
              <LockIcon className="w-8 h-8 text-black" />
            </div>
            <h1 className="text-4xl font-black text-black dark:text-white uppercase tracking-tighter mb-2">Identify</h1>
            <p className="font-mono text-xs text-slate-500 dark:text-slate-400 uppercase tracking-widest">Access Secure Vault</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="bg-red-500 text-black border-2 border-black font-bold p-3 flex items-center gap-3 text-sm animate-fade-in uppercase tracking-wide">
                <AlertCircle className="w-5 h-5 shrink-0" />
                {error}
              </div>
            )}

            <div className="space-y-2">
              <label className="text-xs font-bold text-black dark:text-white uppercase block tracking-wider">Cryptographic Handle or Email</label>
              <div className="relative group">
                <UserIcon className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-black dark:text-white transition-colors" />
                <input
                  type="text"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="IDENTITY..."
                  className="w-full bg-transparent border-2 border-black dark:border-white rounded-none py-3.5 pl-12 pr-4 text-black dark:text-white placeholder-slate-400 font-mono focus:outline-none focus:border-emerald-500 focus:ring-0 transition-colors"
                />
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between items-end">
                <label className="text-xs font-bold text-black dark:text-white uppercase block tracking-wider">Passphrase</label>
                <a href="#" className="font-mono text-[10px] text-emerald-600 hover:text-emerald-500 uppercase tracking-widest border-b border-transparent hover:border-emerald-500">Reset?</a>
              </div>
              <div className="relative group">
                <LockIcon className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-black dark:text-white transition-colors" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="SECURITY_KEY..."
                  className="w-full bg-transparent border-2 border-black dark:border-white rounded-none py-3.5 pl-12 pr-12 text-black dark:text-white placeholder-slate-400 font-mono focus:outline-none focus:border-emerald-500 focus:ring-0 transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-black dark:text-white hover:text-emerald-500 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <div className="relative flex items-start">
                <div className="flex items-center">
                  <input
                    id="remember"
                    name="remember"
                    type="checkbox"
                    className="h-5 w-5 rounded-none border-2 border-black dark:border-white bg-transparent text-emerald-500 focus:ring-emerald-500 focus:ring-offset-0"
                  />
                </div>
                <div className="ml-3 text-sm">
                  <label htmlFor="remember" className="font-bold text-black dark:text-white uppercase tracking-wider text-xs cursor-pointer">Persist Session</label>
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-emerald-500 text-black font-black uppercase tracking-widest py-4 border-2 border-black dark:border-white shadow-[6px_6px_0px_#000] dark:shadow-[6px_6px_0px_#fff] hover:translate-x-[3px] hover:translate-y-[3px] hover:shadow-[3px_3px_0px_#000] dark:hover:shadow-[3px_3px_0px_#fff] active:shadow-none active:translate-x-[6px] active:translate-y-[6px] transition-all disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-3"
            >
              {isLoading ? (
                <div className="w-5 h-5 border-4 border-black/30 border-t-black rounded-full animate-spin" />
              ) : (
                <>Authorize Access <ArrowRight className="w-6 h-6" /></>
              )}
            </button>
          </form>

          <div className="relative my-8">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t-2 border-black dark:border-white border-dashed"></div>
            </div>
            <div className="relative flex justify-center text-xs font-mono uppercase font-bold tracking-widest">
              <span className="bg-white dark:bg-black px-4 text-black dark:text-white">External IDP</span>
            </div>
          </div>

          <button
            onClick={handleGoogleLogin}
            disabled={isLoading}
            className="w-full bg-black dark:bg-white text-white dark:text-black font-bold uppercase tracking-widest py-3.5 border-2 border-black dark:border-white shadow-[4px_4px_0px_#10b981] hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-[2px_2px_0px_#10b981] transition-all disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-3 mb-8"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <path
                fill="currentColor"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="currentColor"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="currentColor"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"
              />
              <path
                fill="currentColor"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 12-4.53z"
              />
            </svg>
            Sign in with Google
          </button>

          <div className="text-center">
            <p className="text-black dark:text-white font-bold text-xs uppercase tracking-wide">
              No clearance?{' '}
              <button onClick={onNavigateSignup} className="text-emerald-500 font-black border-b-2 border-emerald-500 hover:bg-emerald-500 hover:text-black transition-colors px-1">
                Initialize Entry
              </button>
            </p>
          </div>

          <div className="mt-8 pt-6 border-t-2 border-black dark:border-white flex justify-center gap-6 text-black dark:text-white font-mono text-[10px] uppercase font-bold">
            <div className="flex items-center gap-1"><LockIcon className="w-3 h-3 text-emerald-500" /> PQC_READY</div>
            <div className="flex items-center gap-1"><CheckCircle className="w-3 h-3 text-emerald-500" /> ZERO_LOGS</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
