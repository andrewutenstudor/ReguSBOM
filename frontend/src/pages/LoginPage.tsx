/**
 * ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
 * Enterprise Login Page (ENISA Table 7 & NIS2 Art. 21 Compliant Authentication).
 * Supports:
 * - Local DB & Corporate LDAP/AD credentials
 * - Corporate SSO (Keycloak / OIDC)
 * - Multi-Factor Authentication (MFA / TOTP) Challenge Flow
 * - Self-Service Password Reset Modal
 */
import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import apiService from '../services/api';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, setSession } = useAuth();

  // Primary Login State
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Identity Providers Status
  const [oidcEnabled, setOidcEnabled] = useState<boolean>(false);
  const [oidcLoading, setOidcLoading] = useState<boolean>(false);

  // MFA Challenge State
  const [step, setStep] = useState<'credentials' | 'mfa'>('credentials');
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState<string>('');
  const [mfaLoading, setMfaLoading] = useState<boolean>(false);
  const [mfaError, setMfaError] = useState<string | null>(null);

  // Forgot Password Modal State
  const [isForgotModalOpen, setIsForgotModalOpen] = useState<boolean>(false);
  const [forgotEmail, setForgotEmail] = useState<string>('');
  const [forgotLoading, setForgotLoading] = useState<boolean>(false);
  const [forgotMsg, setForgotMsg] = useState<string | null>(null);

  // Return to requested page or default to dashboard
  const from = (location.state as any)?.from?.pathname || '/';

  useEffect(() => {
    const fetchProviders = async () => {
      try {
        const prov = await apiService.getAuthProviders();
        setOidcEnabled(Boolean(prov.oidc_enabled));
      } catch (err) {
        console.warn('Failed to load identity providers:', err);
      }
    };
    fetchProviders();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setErrorMsg('Inserisci sia nome utente che password.');
      return;
    }

    try {
      setLoading(true);
      setErrorMsg(null);
      const res = await login(username.trim(), password);

      if (res && res.mfa_required) {
        setMfaToken(res.mfa_token);
        setStep('mfa');
        setErrorMsg(null);
        return;
      }

      navigate(from, { replace: true });
    } catch (err: any) {
      console.error('Login failed:', err);
      const detail = err?.response?.data?.detail;
      setErrorMsg(detail || 'Credenziali non valide o account disattivato.');
    } finally {
      setLoading(false);
    }
  };

  const handleMfaVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode.trim() || !mfaToken) {
      setMfaError('Inserisci il codice di verifica a 6 cifre o il codice di recupero.');
      return;
    }

    try {
      setMfaLoading(true);
      setMfaError(null);
      const res = await apiService.verifyMfa(mfaToken, totpCode.trim());
      if (res.access_token && res.user) {
        setSession(res.access_token, res.user);
        navigate(from, { replace: true });
      } else {
        setMfaError('Verifica fallita. Riprova con un nuovo codice.');
      }
    } catch (err: any) {
      console.error('MFA verification failed:', err);
      const detail = err?.response?.data?.detail;
      setMfaError(detail || 'Codice di verifica non valido o sessione scaduta.');
    } finally {
      setMfaLoading(false);
    }
  };

  const handleOidcLogin = async () => {
    try {
      setOidcLoading(true);
      const { authorization_url } = await apiService.getOidcLoginUrl();
      if (authorization_url) {
        window.location.href = authorization_url;
      }
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || 'Single Sign-On Keycloak non disponibile.');
      setOidcLoading(false);
    }
  };

  const handleForgotPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!forgotEmail.trim()) return;

    try {
      setForgotLoading(true);
      setForgotMsg(null);
      const res = await apiService.forgotPassword(forgotEmail.trim());
      setForgotMsg(res.message);
    } catch (err: any) {
      setForgotMsg('Istruzioni di ripristino inviate se l\'indirizzo è registrato.');
    } finally {
      setForgotLoading(false);
    }
  };

  const handleQuickLogin = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-primary-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 text-slate-100">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center items-center gap-3">
          <img
            src="/logo.jpeg"
            alt="ReguBOM Logo"
            className="w-12 h-12 rounded-xl object-contain shadow-lg border border-slate-700/60 bg-slate-800"
          />
          <div>
            <h2 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
              ReguBOM
              <span className="text-xs px-2 py-0.5 rounded font-mono bg-primary-500/20 border border-primary-500/40 text-primary-300">
                v2.0
              </span>
            </h2>
            <p className="text-xs text-slate-400">Cyber Resilience &amp; Regulatory SBOM Gateway</p>
          </div>
        </div>
        <p className="mt-3 text-center text-xs text-slate-400">
          Accesso conforme a <span className="text-primary-300 font-semibold">ENISA Table 7</span> &amp; <span className="text-primary-300 font-semibold">NIS2 Art. 21</span>
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md px-4">
        <div className="bg-slate-800/80 backdrop-blur-md py-8 px-6 shadow-2xl rounded-2xl border border-slate-700/80 sm:px-10">

          {/* STEP 1: CREDENTIALS ENTRY */}
          {step === 'credentials' && (
            <form className="space-y-5" onSubmit={handleSubmit}>
              {errorMsg && (
                <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg text-sm flex items-start gap-2 animate-shake">
                  <span className="text-lg">⚠️</span>
                  <span>{errorMsg}</span>
                </div>
              )}

              {oidcEnabled && (
                <div className="pb-3 border-b border-slate-700/60">
                  <button
                    type="button"
                    onClick={handleOidcLogin}
                    disabled={oidcLoading}
                    className="w-full flex justify-center items-center gap-2 py-2.5 px-4 rounded-lg bg-indigo-600/90 hover:bg-indigo-600 text-white font-semibold text-sm transition-all border border-indigo-500/40 shadow-sm"
                  >
                    <span>🔑</span>
                    <span>{oidcLoading ? 'Reindirizzamento...' : 'Accedi con Corporate SSO (Keycloak)'}</span>
                  </button>
                  <div className="relative my-4 text-center">
                    <span className="bg-slate-800 px-2 text-[11px] text-slate-400 uppercase tracking-wider">oppure credenziali locali</span>
                  </div>
                </div>
              )}

              <div>
                <label htmlFor="username" className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Nome Utente o UPN LDAP
                </label>
                <div className="mt-1 relative rounded-lg shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                    👤
                  </div>
                  <input
                    id="username"
                    name="username"
                    type="text"
                    autoComplete="username"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="block w-full pl-10 pr-3 py-2.5 bg-slate-900/60 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent text-sm transition-all"
                    placeholder="admin, operator o auditor"
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center">
                  <label htmlFor="password" className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      setIsForgotModalOpen(true);
                      setForgotMsg(null);
                    }}
                    className="text-xs text-primary-400 hover:text-primary-300 transition-colors"
                  >
                    Password dimenticata?
                  </button>
                </div>
                <div className="mt-1 relative rounded-lg shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                    🔒
                  </div>
                  <input
                    id="password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="block w-full pl-10 pr-10 py-2.5 bg-slate-900/60 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent text-sm transition-all"
                    placeholder="••••••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200"
                  >
                    {showPassword ? '👁️' : '🙈'}
                  </button>
                </div>
              </div>

              <div>
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-bold text-white bg-primary-600 hover:bg-primary-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  {loading ? (
                    <span className="flex items-center gap-2">
                      <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                      </svg>
                      Verifica credenziali...
                    </span>
                  ) : (
                    'Accedi alla Piattaforma'
                  )}
                </button>
              </div>

              {/* Air-Gap Sovereign Quick Role Helper */}
              <div className="mt-6 pt-5 border-t border-slate-700/60">
                <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2 text-center">
                  Account Pre-configurati (Air-Gap)
                </p>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => handleQuickLogin('admin', 'AdminPassword2026!')}
                    className="px-2 py-1.5 text-xs bg-slate-900/80 hover:bg-slate-700 border border-slate-700 rounded text-center transition-all group"
                  >
                    <span className="font-bold text-primary-400 group-hover:text-primary-300">admin</span>
                    <span className="block text-[10px] text-slate-500">Root Access</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleQuickLogin('operator', 'OperatorPassword2026!')}
                    className="px-2 py-1.5 text-xs bg-slate-900/80 hover:bg-slate-700 border border-slate-700 rounded text-center transition-all group"
                  >
                    <span className="font-bold text-emerald-400 group-hover:text-emerald-300">operator</span>
                    <span className="block text-[10px] text-slate-500">Ingest &amp; Catalog</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleQuickLogin('auditor', 'AuditorPassword2026!')}
                    className="px-2 py-1.5 text-xs bg-slate-900/80 hover:bg-slate-700 border border-slate-700 rounded text-center transition-all group"
                  >
                    <span className="font-bold text-purple-400 group-hover:text-purple-300">auditor</span>
                    <span className="block text-[10px] text-slate-500">Read-Only</span>
                  </button>
                </div>
              </div>
            </form>
          )}

          {/* STEP 2: MFA CHALLENGE ENTRY */}
          {step === 'mfa' && (
            <form className="space-y-6" onSubmit={handleMfaVerify}>
              <div className="text-center">
                <div className="w-12 h-12 mx-auto rounded-full bg-primary-600/20 border border-primary-500/30 flex items-center justify-center text-2xl text-primary-400 mb-2">
                  📱
                </div>
                <h3 className="text-lg font-bold text-white">Autenticazione a Due Fattori (MFA)</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Inserisci il codice generato dall'app <strong>Microsoft Authenticator</strong> o <strong>Google Authenticator</strong>, oppure un codice di emergenza.
                </p>
              </div>

              {mfaError && (
                <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg text-sm flex items-start gap-2 animate-shake">
                  <span className="text-lg">⚠️</span>
                  <span>{mfaError}</span>
                </div>
              )}

              <div>
                <label htmlFor="totpCode" className="block text-xs font-semibold uppercase tracking-wider text-slate-300 text-center">
                  Codice di Sicurezza (6 cifre o XXXX-XXXX)
                </label>
                <div className="mt-2">
                  <input
                    id="totpCode"
                    name="totpCode"
                    type="text"
                    autoFocus
                    required
                    maxLength={10}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                    className="block w-full text-center tracking-widest font-mono text-xl py-3 bg-slate-900/80 border border-primary-500/50 rounded-lg text-white placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-primary-500"
                    placeholder="123456"
                  />
                </div>
              </div>

              <div className="space-y-3">
                <button
                  type="submit"
                  disabled={mfaLoading}
                  className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-bold text-white bg-primary-600 hover:bg-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500 disabled:opacity-50 transition-all"
                >
                  {mfaLoading ? 'Verifica in corso...' : 'Verifica e Accedi'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setStep('credentials');
                    setTotpCode('');
                    setMfaError(null);
                  }}
                  className="w-full py-2 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                >
                  ← Torna all'accesso con password
                </button>
              </div>
            </form>
          )}

        </div>

        <div className="mt-6 text-center text-xs text-slate-500">
          Autenticazione sovrana offline • Zero telemetria verso l'esterno
        </div>
      </div>

      {/* FORGOT PASSWORD MODAL */}
      {isForgotModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl relative">
            <h3 className="text-lg font-bold text-white mb-2">Ripristino Password</h3>
            <p className="text-xs text-slate-400 mb-4">
              Inserisci l'indirizzo email associato al tuo account per ricevere le istruzioni di ripristino password.
            </p>

            {forgotMsg ? (
              <div className="space-y-4">
                <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-4 py-3 rounded-lg text-xs">
                  {forgotMsg}
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setIsForgotModalOpen(false);
                    setForgotMsg(null);
                  }}
                  className="w-full py-2 bg-slate-700 hover:bg-slate-600 rounded text-sm font-semibold text-white transition-all"
                >
                  Chiudi
                </button>
              </div>
            ) : (
              <form onSubmit={handleForgotPasswordSubmit} className="space-y-4">
                <div>
                  <label htmlFor="forgotEmail" className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Email Account
                  </label>
                  <input
                    id="forgotEmail"
                    type="email"
                    required
                    value={forgotEmail}
                    onChange={(e) => setForgotEmail(e.target.value)}
                    className="mt-1 block w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                    placeholder="utente@azienda.local"
                  />
                </div>
                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsForgotModalOpen(false)}
                    className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-xs font-semibold text-slate-200 transition-all"
                  >
                    Annulla
                  </button>
                  <button
                    type="submit"
                    disabled={forgotLoading}
                    className="px-4 py-2 bg-primary-600 hover:bg-primary-500 rounded text-xs font-semibold text-white transition-all disabled:opacity-50"
                  >
                    {forgotLoading ? 'Invio in corso...' : 'Invia Link di Ripristino'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default LoginPage;
