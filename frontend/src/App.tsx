import React, { useState, useEffect } from 'react';
import { Routes, Route, Link, useLocation, Navigate } from 'react-router-dom';
import HomePage from './pages/HomePage';
import UploadPage from './pages/UploadPage';
import ReportsPage from './pages/ReportsPage';
import ReportDetailPage from './pages/ReportDetailPage';
import AcnValidatorPage from './pages/AcnValidatorPage';
import SbomViewerPage from './pages/SbomViewerPage';
import CatalogPage from './pages/CatalogPage';
import ProductDetailPage from './pages/ProductDetailPage';
import SbomDiffPage from './pages/SbomDiffPage';
import LoginPage from './pages/LoginPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import SecuritySettingsPage from './pages/SecuritySettingsPage';
import SecuritySettingsModal from './components/SecuritySettingsModal';
import { Footer } from './components/Footer';
import apiService from './services/api';
import { LicenseInfo } from './types';
import { useAuth } from './context/AuthContext';
import { isEE, EDITION_CONFIG } from './config/edition';

function ProtectedRoute({ children }: { children: React.ReactElement }) {
  if (!isEE) {
    return children;
  }
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-32">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}

function App() {
  const location = useLocation();
  const { user, isAuthenticated, logout } = useAuth();
  const [license, setLicense] = useState<LicenseInfo | null>(null);
  const [isLicModalOpen, setIsLicModalOpen] = useState<boolean>(false);
  const [licUploadFile, setLicUploadFile] = useState<File | null>(null);
  const [licUploading, setLicUploading] = useState<boolean>(false);
  const [licUploadMsg, setLicUploadMsg] = useState<string | null>(null);
  const [isSecurityModalOpen, setIsSecurityModalOpen] = useState<boolean>(false);

  useEffect(() => {
    if (isEE && isAuthenticated) {
      fetchLicense();
    }
  }, [isAuthenticated]);

  const fetchLicense = async () => {
    try {
      const data = await apiService.getLicenseStatus();
      setLicense(data);
    } catch (err) {
      console.warn('Could not load license status:', err);
    }
  };

  const handleUploadLicense = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!licUploadFile) return;

    try {
      setLicUploading(true);
      setLicUploadMsg(null);
      const res = await apiService.uploadLicense(licUploadFile);
      setLicense(res.license);
      setLicUploadMsg('✅ Licenza Ed25519 verificata e attivata con successo!');
      setLicUploadFile(null);
    } catch (err: any) {
      setLicUploadMsg(`❌ Errore: ${err?.response?.data?.detail || 'Impossibile verificare la licenza.'}`);
    } finally {
      setLicUploading(false);
    }
  };

  const navLinks = isEE
    ? [
        { name: 'Dashboard', path: '/' },
        { name: 'Asset Catalog', path: '/catalog' },
        { name: 'Diff & Drift', path: '/diff' },
        { name: 'Audit & Validate', path: '/upload' },
        { name: 'Compliance Dossiers', path: '/reports' },
        { name: 'ACN Module', path: '/acn' },
      ]
    : [
        { name: 'Dashboard', path: '/' },
        { name: 'Audit & Validate', path: '/upload' },
        { name: 'Compliance Dossiers', path: '/reports' },
      ];

  // In CE, auth pages redirect to home
  if (!isEE && (location.pathname === '/login' || location.pathname === '/reset-password')) {
    return <Navigate to="/" replace />;
  }

  // Standalone public auth routes (bypass main layout) in EE
  if (location.pathname === '/login') {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  if (location.pathname === '/reset-password') {
    return (
      <Routes>
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans">
      {/* Header */}
      <header className="bg-slate-900 shadow-md border-b border-slate-800 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <Link to="/" className="flex-shrink-0 group">
                <div className="flex items-center gap-3">
                  <img 
                    src="/logo.jpeg" 
                    alt="ReguBOM Logo" 
                    className="h-9 w-auto rounded-md shadow-sm border border-slate-700/50 object-contain"
                  />
                  <div className="flex flex-col">
                    <div className="flex items-center gap-2">
                      <span className="text-lg font-bold tracking-tight text-white">ReguBOM</span>
                      <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                        {isEE ? 'Enterprise CRA' : 'CRA Gateway'}
                      </span>
                    </div>
                    <span className="text-[11px] text-slate-400 -mt-0.5">Regulatory SBOM Ledger</span>
                  </div>
                </div>
              </Link>
              <nav className="ml-10 flex space-x-6">
                {navLinks.map((link) => (
                  <Link
                    key={link.path}
                    to={link.path}
                    className={`${
                      location.pathname === link.path
                        ? 'border-blue-500 text-blue-400 font-bold'
                        : 'border-transparent text-slate-300 hover:text-white hover:border-slate-500 font-medium'
                    } whitespace-nowrap pb-1.5 px-1 border-b-2 text-sm transition-all`}
                  >
                    {link.name}
                  </Link>
                ))}
              </nav>
            </div>

            {/* Top Navigation Bar: EE License & User Session vs CE Open Source Pill */}
            <div className="flex items-center gap-3">
              {isEE ? (
                <>
                  {license ? (
                    <button
                      type="button"
                      onClick={() => setIsLicModalOpen(true)}
                      className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs transition-all ${
                        license.valid
                          ? 'bg-slate-800/80 border-slate-700 hover:border-slate-600 text-slate-200'
                          : 'bg-rose-950/50 border-rose-800 text-rose-300 font-bold animate-pulse'
                      }`}
                      title="Gestione Licenza Crittografica Air-Gap (Ed25519)"
                    >
                      <span className="text-sm">🔒</span>
                      <div className="text-left hidden sm:block">
                        <div className="font-bold text-[11px] leading-tight flex items-center gap-1">
                          <span className="truncate max-w-[140px] text-white">{license.customer_name}</span>
                          <span className="px-1.5 py-0.2 bg-emerald-900/60 text-emerald-300 border border-emerald-700/50 rounded text-[9px] font-black uppercase tracking-wider">
                            {license.tier || 'Air-Gapped Sovereign'}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-400 flex items-center gap-1.5">
                          {license.valid ? (
                            <>
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block shadow-[0_0_6px_rgba(52,211,153,0.6)]"></span>
                              <span>
                                {license.days_remaining > 0
                                  ? `${license.days_remaining} giorni rimasti`
                                  : 'Scade oggi'}
                              </span>
                            </>
                          ) : (
                            <span className="text-rose-400 font-bold">
                              Licenza Scaduta / Non Valida
                            </span>
                          )}
                        </div>
                      </div>
                      <span className="text-[10px] text-slate-400 ml-1">⚙️</span>
                    </button>
                  ) : null}

                  {/* User Session Profile & Role Badge */}
                  {user ? (
                    <div className="flex items-center gap-2.5 pl-3 border-l border-slate-700">
                      <div className="text-right hidden md:block">
                        <div className="text-xs font-bold text-white leading-tight">
                          {user.full_name || user.username}
                        </div>
                        <div className="flex justify-end">
                          <span className={`inline-block px-1.5 py-0.2 text-[9px] font-black uppercase rounded tracking-wider ${
                            user.role === 'admin'
                              ? 'bg-rose-950/60 text-rose-300 border border-rose-800'
                              : user.role === 'operator'
                              ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800'
                              : 'bg-purple-950/60 text-purple-300 border border-purple-800'
                          }`}>
                            {user.role}
                          </span>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => setIsSecurityModalOpen(true)}
                        className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg transition-colors text-xs font-medium flex items-center gap-1"
                        title="Impostazioni Sicurezza, MFA e Machine Tokens"
                      >
                        <span>⚙️</span>
                        <span className="hidden xl:inline text-xs">Sicurezza</span>
                      </button>
                      <button
                        type="button"
                        onClick={logout}
                        className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded-lg transition-colors text-xs font-medium flex items-center gap-1"
                        title="Disconnetti sessione"
                      >
                        <span>🚪</span>
                        <span className="hidden lg:inline text-xs">Esci</span>
                      </button>
                    </div>
                  ) : (
                    <Link
                      to="/login"
                      className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold shadow-sm transition-colors"
                    >
                      Accedi
                    </Link>
                  )}
                </>
              ) : (
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 text-xs text-slate-200">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block shadow-[0_0_8px_rgba(52,211,153,0.5)]"></span>
                    <span className="font-semibold text-slate-200">Community Edition</span>
                    <span className="text-slate-500">•</span>
                    <span className="font-mono text-[11px] text-slate-400">v2.0.0-ce (AGPLv3)</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Main content with Route Guards */}
      <main className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8 flex-1 w-full">
        <Routes>
          <Route path="/" element={<ProtectedRoute><HomePage /></ProtectedRoute>} />
          {isEE && (
            <>
              <Route path="/products" element={<ProtectedRoute><CatalogPage /></ProtectedRoute>} />
              <Route path="/products/:productId" element={<ProtectedRoute><ProductDetailPage /></ProtectedRoute>} />
              <Route path="/catalog" element={<ProtectedRoute><CatalogPage /></ProtectedRoute>} />
              <Route path="/catalog/:productId" element={<ProtectedRoute><ProductDetailPage /></ProtectedRoute>} />
              <Route path="/diff" element={<ProtectedRoute><SbomDiffPage /></ProtectedRoute>} />
              <Route path="/settings/security" element={<ProtectedRoute><SecuritySettingsPage /></ProtectedRoute>} />
              <Route path="/acn" element={<ProtectedRoute><AcnValidatorPage /></ProtectedRoute>} />
            </>
          )}
          <Route path="/upload" element={<ProtectedRoute><UploadPage /></ProtectedRoute>} />
          <Route path="/reports" element={<ProtectedRoute><ReportsPage /></ProtectedRoute>} />
          <Route path="/reports/:reportId" element={<ProtectedRoute><ReportDetailPage /></ProtectedRoute>} />
          <Route path="/sboms/:id/view" element={<ProtectedRoute><SbomViewerPage /></ProtectedRoute>} />
          <Route path="/reports/:id/view" element={<ProtectedRoute><SbomViewerPage /></ProtectedRoute>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>

      {/* Footer */}
      <Footer />

      {/* Offline Cryptographic License Modal */}
      {isEE && isLicModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full shadow-2xl border border-slate-200 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
              <div className="flex items-center gap-2">
                <span className="text-xl">🔒</span>
                <div>
                  <h3 className="text-sm font-bold text-slate-900">
                    Stato Licenza Air-Gapped &amp; Sovranità Dati
                  </h3>
                  <p className="text-[11px] text-slate-500">
                    Verifica crittografica Ed25519 offline (Zero Telemetria)
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsLicModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 text-xl font-bold leading-none"
              >
                ✕
              </button>
            </div>

            <div className="p-6 space-y-4">
              {license ? (
                <div className="bg-slate-50 rounded-xl p-4 border border-slate-200 space-y-2 text-xs">
                  <div className="flex justify-between items-center py-1 border-b border-slate-200">
                    <span className="text-slate-500">Cliente Licenziatario:</span>
                    <span className="font-bold text-slate-800">{license.customer_name}</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-slate-200">
                    <span className="text-slate-500">Customer ID:</span>
                    <span className="font-mono text-slate-700">{license.customer_id}</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-slate-200">
                    <span className="text-slate-500">Edizione &amp; Tier:</span>
                    <span className="font-bold text-primary-700">{license.tier || 'Enterprise Sovereign'}</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-slate-200">
                    <span className="text-slate-500">Data Scadenza:</span>
                    <span className="font-mono text-slate-800">{license.expiry_date}</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-slate-200">
                    <span className="text-slate-500">Stato Validità:</span>
                    <span className={`font-bold ${license.valid ? 'text-emerald-700' : 'text-rose-700'}`}>
                      {license.valid ? '✅ Attiva e Conforme' : '❌ Non Valida / Scaduta'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center py-1">
                    <span className="text-slate-500">Autorizzazione Air-Gap:</span>
                    <span className="font-bold text-slate-800">
                      {license.airgap_authorized ? '🛡️ Sovereign Air-Gap Autorizzato' : 'Standard'}
                    </span>
                  </div>
                </div>
              ) : null}

              {/* Upload New License Form */}
              <form onSubmit={handleUploadLicense} className="space-y-3 pt-2">
                <label className="block text-xs font-bold text-slate-700">
                  Aggiorna Licenza Crittografica (.lic)
                </label>
                <div className="flex items-center gap-2">
                  <input
                    type="file"
                    accept=".lic"
                    onChange={(e) => setLicUploadFile(e.target.files?.[0] || null)}
                    className="block w-full text-xs text-slate-500 file:mr-2 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-primary-50 file:text-primary-700 hover:file:bg-primary-100"
                  />
                  <button
                    type="submit"
                    disabled={!licUploadFile || licUploading}
                    className="px-3 py-1.5 bg-primary-600 hover:bg-primary-700 text-white rounded-lg text-xs font-bold disabled:opacity-50 transition-all flex items-center gap-1"
                  >
                    {licUploading ? 'Verifica...' : 'Applica'}
                  </button>
                </div>
                {licUploadMsg && (
                  <p className="text-xs mt-1 text-slate-700 font-medium">{licUploadMsg}</p>
                )}
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Security & Token Settings Modal */}
      {isEE && (
        <SecuritySettingsModal
          isOpen={isSecurityModalOpen}
          onClose={() => setIsSecurityModalOpen(false)}
        />
      )}
    </div>
  );
}

export default App;
