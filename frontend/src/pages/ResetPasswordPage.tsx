/**
 * ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
 * Self-Service Password Reset Page.
 * Verifies one-time token and allows operator to establish a new password.
 */
import React, { useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import apiService from '../services/api';

export const ResetPasswordPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');

  const [newPassword, setNewPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const hasLength = newPassword.length >= 8;
  const hasUpper = /[A-Z]/.test(newPassword);
  const hasNumber = /[0-9]/.test(newPassword);
  const hasSpecial = /[^A-Za-z0-9]/.test(newPassword);
  const passwordsMatch = newPassword === confirmPassword && newPassword.length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) {
      setErrorMsg('Token di ripristino mancante o non valido.');
      return;
    }
    if (!hasLength) {
      setErrorMsg('La password deve contenere almeno 8 caratteri.');
      return;
    }
    if (!passwordsMatch) {
      setErrorMsg('Le password inserite non coincidono.');
      return;
    }

    try {
      setLoading(true);
      setErrorMsg(null);
      const res = await apiService.resetPassword(token, newPassword);
      setSuccessMsg(res.message);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || 'Impossibile ripristinare la password. Il link potrebbe essere scaduto.');
    } finally {
      setLoading(false);
    }
  };

  if (!token) {
    return (
      <div className="min-h-screen bg-slate-900 flex flex-col justify-center items-center py-12 px-4 text-white">
        <div className="bg-slate-800 border border-slate-700 rounded-2xl max-w-md w-full p-8 text-center shadow-2xl">
          <div className="text-4xl mb-4">⚠️</div>
          <h2 className="text-xl font-bold mb-2">Link Non Valido</h2>
          <p className="text-sm text-slate-400 mb-6">
            Nessun token di sicurezza fornito per il ripristino della password.
          </p>
          <Link
            to="/login"
            className="inline-block py-2.5 px-6 bg-primary-600 hover:bg-primary-500 rounded-lg text-sm font-semibold transition-all"
          >
            Torna alla schermata di Login
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-primary-950 flex flex-col justify-center py-12 px-4 text-slate-100">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center items-center gap-3">
          <img
            src="/logo.jpeg"
            alt="ReguBOM Logo"
            className="w-12 h-12 rounded-xl object-contain shadow-lg border border-slate-700/60 bg-slate-800"
          />
          <div>
            <h2 className="text-2xl font-extrabold tracking-tight text-white">ReguBOM</h2>
            <p className="text-xs text-slate-400">Ripristino Password Operatore</p>
          </div>
        </div>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-slate-800/80 backdrop-blur-md py-8 px-6 shadow-2xl rounded-2xl border border-slate-700/80 sm:px-10">
          {successMsg ? (
            <div className="text-center space-y-4">
              <div className="text-4xl text-emerald-400">✅</div>
              <h3 className="text-lg font-bold text-white">Password Aggiornata</h3>
              <p className="text-xs text-slate-300">{successMsg}</p>
              <div className="pt-4">
                <button
                  type="button"
                  onClick={() => navigate('/login')}
                  className="w-full py-2.5 bg-primary-600 hover:bg-primary-500 rounded-lg text-sm font-semibold text-white transition-all shadow-md"
                >
                  Accedi con la Nuova Password
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              <h3 className="text-lg font-bold text-white text-center">Imposta Nuova Password</h3>

              {errorMsg && (
                <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg text-xs flex items-center gap-2">
                  <span>⚠️</span>
                  <span>{errorMsg}</span>
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Nuova Password
                </label>
                <input
                  type="password"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="mt-1 block w-full px-3 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                  placeholder="Minimo 8 caratteri"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Conferma Password
                </label>
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="mt-1 block w-full px-3 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                  placeholder="Ripeti la nuova password"
                />
              </div>

              {/* Password complexity indicators */}
              <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-700/60 text-[11px] space-y-1">
                <div className={`flex items-center gap-1.5 ${hasLength ? 'text-emerald-400' : 'text-slate-400'}`}>
                  <span>{hasLength ? '✓' : '○'}</span>
                  <span>Almeno 8 caratteri</span>
                </div>
                <div className={`flex items-center gap-1.5 ${hasUpper ? 'text-emerald-400' : 'text-slate-400'}`}>
                  <span>{hasUpper ? '✓' : '○'}</span>
                  <span>Almeno una lettera maiuscola</span>
                </div>
                <div className={`flex items-center gap-1.5 ${hasNumber ? 'text-emerald-400' : 'text-slate-400'}`}>
                  <span>{hasNumber ? '✓' : '○'}</span>
                  <span>Almeno un numero</span>
                </div>
                <div className={`flex items-center gap-1.5 ${hasSpecial ? 'text-emerald-400' : 'text-slate-400'}`}>
                  <span>{hasSpecial ? '✓' : '○'}</span>
                  <span>Almeno un carattere speciale</span>
                </div>
                {confirmPassword && (
                  <div className={`flex items-center gap-1.5 pt-1 border-t border-slate-800 ${passwordsMatch ? 'text-emerald-400' : 'text-red-400'}`}>
                    <span>{passwordsMatch ? '✓' : '✕'}</span>
                    <span>{passwordsMatch ? 'Le password coincidono' : 'Le password non coincidono'}</span>
                  </div>
                )}
              </div>

              <button
                type="submit"
                disabled={loading || !hasLength || !passwordsMatch}
                className="w-full py-2.5 px-4 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 rounded-lg text-sm font-bold text-white transition-all shadow-md"
              >
                {loading ? 'Salvataggio in corso...' : 'Salva Nuova Password'}
              </button>

              <div className="text-center">
                <Link to="/login" className="text-xs text-slate-400 hover:text-slate-200">
                  ← Annulla e torna al login
                </Link>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

export default ResetPasswordPage;
