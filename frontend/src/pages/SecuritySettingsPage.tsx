/**
 * ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
 * Security Settings Page: Dedicated route for /settings/security.
 * 1. Multi-Factor Authentication (TOTP setup, QR code, recovery codes).
 * 2. Scoped CI/CD Machine API Tokens (Least-privilege product scope).
 */
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import apiService from '../services/api';
import { ApiKeyItem, ProductItem, MfaSetupResponse } from '../types';

export const SecuritySettingsPage: React.FC = () => {
  const { user, refreshUser, isAdmin, isOperator, role } = useAuth();

  const [activeTab, setActiveTab] = useState<'mfa' | 'apikeys'>('mfa');

  // MFA Setup State
  const [mfaSetupData, setMfaSetupData] = useState<MfaSetupResponse | null>(null);
  const [mfaCode, setMfaCode] = useState<string>('');
  const [mfaRecoveryCodes, setMfaRecoveryCodes] = useState<string[] | null>(null);
  const [mfaLoading, setMfaLoading] = useState<boolean>(false);
  const [mfaError, setMfaError] = useState<string | null>(null);

  // MFA Disable State
  const [isDisableOpen, setIsDisableOpen] = useState<boolean>(false);
  const [disablePassword, setDisablePassword] = useState<string>('');
  const [disableTotp, setDisableTotp] = useState<string>('');
  const [disableLoading, setDisableLoading] = useState<boolean>(false);
  const [disableError, setDisableError] = useState<string | null>(null);

  // API Keys State
  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([]);
  const [products, setProducts] = useState<ProductItem[]>([]);
  const [keysLoading, setKeysLoading] = useState<boolean>(false);
  const [newKeyName, setNewKeyName] = useState<string>('');
  const [newKeyRole, setNewKeyRole] = useState<string>('operator');
  const [newKeyDays, setNewKeyDays] = useState<number | ''>(30);
  const [scopeType, setScopeType] = useState<'all' | 'specific'>('all');
  const [selectedProductSlugs, setSelectedProductSlugs] = useState<string[]>([]);
  const [generatedRawToken, setGeneratedRawToken] = useState<string | null>(null);
  const [createKeyLoading, setCreateKeyLoading] = useState<boolean>(false);
  const [keyError, setKeyError] = useState<string | null>(null);

  useEffect(() => {
    if (isAdmin || isOperator) {
      fetchKeysAndProducts();
    }
  }, [isAdmin, isOperator]);

  const fetchKeysAndProducts = async () => {
    try {
      setKeysLoading(true);
      const [keysList, prodsList] = await Promise.all([
        apiService.listApiKeys().catch(() => []),
        apiService.listProducts().catch(() => []),
      ]);
      setApiKeys(keysList);
      setProducts(prodsList);
    } catch {
      // Ignored
    } finally {
      setKeysLoading(false);
    }
  };

  const handleStartMfaSetup = async () => {
    try {
      setMfaLoading(true);
      setMfaError(null);
      const res = await apiService.setupMfa();
      setMfaSetupData(res);
    } catch (err: any) {
      setMfaError(err?.response?.data?.detail || 'Errore nella generazione del secret TOTP.');
    } finally {
      setMfaLoading(false);
    }
  };

  const handleEnableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaSetupData || !mfaCode) return;
    try {
      setMfaLoading(true);
      setMfaError(null);
      const res = await apiService.enableMfa(mfaCode);
      setMfaRecoveryCodes(res.recovery_codes || []);
      setMfaSetupData(null);
      setMfaCode('');
      await refreshUser();
    } catch (err: any) {
      setMfaError(err?.response?.data?.detail || 'Codice TOTP non valido. Verifica l\'orologio del dispositivo.');
    } finally {
      setMfaLoading(false);
    }
  };

  const handleDisableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setDisableLoading(true);
      setDisableError(null);
      await apiService.disableMfa(disablePassword, disableTotp);
      setIsDisableOpen(false);
      setDisablePassword('');
      setDisableTotp('');
      await refreshUser();
    } catch (err: any) {
      setDisableError(err?.response?.data?.detail || 'Impossibile disattivare MFA. Verifica le credenziali.');
    } finally {
      setDisableLoading(false);
    }
  };

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;

    try {
      setCreateKeyLoading(true);
      setKeyError(null);
      const allowed = scopeType === 'all' ? ['*'] : selectedProductSlugs;
      const res = await apiService.createApiKey(
        newKeyName.trim(),
        newKeyRole,
        newKeyDays === '' ? undefined : Number(newKeyDays),
        allowed
      );
      setGeneratedRawToken(res.token);
      setNewKeyName('');
      setSelectedProductSlugs([]);
      setScopeType('all');
      await fetchKeysAndProducts();
    } catch (err: any) {
      setKeyError(err?.response?.data?.detail || 'Errore durante la creazione del token machine.');
    } finally {
      setCreateKeyLoading(false);
    }
  };

  const handleRevokeKey = async (keyId: number) => {
    if (!confirm('Sei sicuro di voler revocare immediatamente questa chiave API? I pipeline CI/CD associati falliranno.')) {
      return;
    }
    try {
      await apiService.revokeApiKey(keyId);
      await fetchKeysAndProducts();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Errore nella revoca del token.');
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      {/* Breadcrumb & Title */}
      <div>
        <nav className="flex items-center gap-2 text-xs text-slate-500 mb-2">
          <Link to="/" className="hover:text-primary-600 transition-colors">Home</Link>
          <span>/</span>
          <span className="text-slate-800 font-semibold">Sicurezza &amp; Token</span>
        </nav>
        <div className="flex items-center gap-3">
          <span className="text-3xl">⚙️</span>
          <div>
            <h1 className="text-2xl font-black text-slate-900 tracking-tight">
              Impostazioni di Sicurezza &amp; Machine Tokens
            </h1>
            <p className="text-xs text-slate-500 mt-0.5">
              Configura l'autenticazione a due fattori (TOTP) e gestisci le chiavi API con privilegi minimi.
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-200">
        <button
          onClick={() => setActiveTab('mfa')}
          className={`px-5 py-3 text-xs font-bold border-b-2 transition-all flex items-center gap-2 ${
            activeTab === 'mfa'
              ? 'border-primary-600 text-primary-700 bg-primary-50/30'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <span>🔐</span>
          <span>Autenticazione a Due Fattori (MFA / TOTP)</span>
          {user?.mfa_enabled && (
            <span className="ml-1 px-1.5 py-0.2 bg-emerald-100 text-emerald-800 rounded text-[9px] font-black uppercase">
              Attiva
            </span>
          )}
        </button>
        {(isAdmin || isOperator) && (
          <button
            onClick={() => setActiveTab('apikeys')}
            className={`px-5 py-3 text-xs font-bold border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'apikeys'
                ? 'border-primary-600 text-primary-700 bg-primary-50/30'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <span>🤖</span>
            <span>Machine Tokens CI/CD (Scoped Keys)</span>
            <span className="ml-1 px-1.5 py-0.2 bg-slate-200 text-slate-700 rounded-full text-[10px] font-bold">
              {apiKeys.length}
            </span>
          </button>
        )}
      </div>

      {/* Tab: MFA */}
      {activeTab === 'mfa' && (
        <div className="bg-white rounded-2xl border border-slate-200 p-6 sm:p-8 space-y-6">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-base font-bold text-slate-900">Protezione Account con TOTP</h2>
              <p className="text-xs text-slate-500 mt-1">
                Compatibile con Google Authenticator, Microsoft Authenticator e Bitwarden (RFC 6238).
              </p>
            </div>
            <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
              user?.mfa_enabled
                ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                : 'bg-slate-100 text-slate-600 border border-slate-200'
            }`}>
              {user?.mfa_enabled ? '✓ MFA Attiva' : 'MFA Non Attiva'}
            </span>
          </div>

          {user?.mfa_enabled ? (
            <div className="space-y-4">
              <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-4 text-xs text-emerald-900 flex items-center gap-3">
                <span className="text-2xl">🛡️</span>
                <div>
                  <p className="font-bold">Il tuo account è protetto con TOTP.</p>
                  <p className="text-emerald-700 text-[11px]">
                    A ogni accesso verrà richiesto il codice monouso generato dall'app di autenticazione.
                  </p>
                </div>
              </div>

              <div className="pt-2">
                <button
                  onClick={() => setIsDisableOpen(!isDisableOpen)}
                  className="px-4 py-2 border border-rose-300 text-rose-700 hover:bg-rose-50 rounded-xl text-xs font-bold transition-colors"
                >
                  Disattiva Autenticazione a Due Fattori
                </button>
              </div>

              {isDisableOpen && (
                <form onSubmit={handleDisableMfa} className="bg-rose-50/50 border border-rose-200 rounded-xl p-4 space-y-3 max-w-md">
                  <h4 className="text-xs font-bold text-rose-900">Conferma Disattivazione MFA</h4>
                  <input
                    type="password"
                    placeholder="Password attuale"
                    value={disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    className="w-full text-xs px-3 py-2 border border-slate-300 rounded-lg"
                    required
                  />
                  <input
                    type="text"
                    placeholder="Codice TOTP a 6 cifre"
                    value={disableTotp}
                    onChange={(e) => setDisableTotp(e.target.value)}
                    maxLength={6}
                    className="w-full text-xs px-3 py-2 border border-slate-300 rounded-lg font-mono text-center tracking-widest"
                    required
                  />
                  {disableError && <p className="text-xs text-rose-600 font-medium">{disableError}</p>}
                  <button
                    type="submit"
                    disabled={disableLoading}
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-xs font-bold transition-all disabled:opacity-50"
                  >
                    {disableLoading ? 'Verifica...' : 'Conferma Disattivazione'}
                  </button>
                </form>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              {!mfaSetupData ? (
                <div>
                  <button
                    onClick={handleStartMfaSetup}
                    disabled={mfaLoading}
                    className="px-5 py-2.5 bg-primary-600 hover:bg-primary-700 text-white rounded-xl text-xs font-bold shadow-sm transition-all flex items-center gap-2"
                  >
                    {mfaLoading ? 'Generazione...' : '🚀 Configura Autenticazione a Due Fattori'}
                  </button>
                  {mfaError && <p className="text-xs text-rose-600 mt-2">{mfaError}</p>}
                </div>
              ) : (
                <div className="space-y-4 max-w-md">
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl text-center space-y-3">
                    <p className="text-xs font-bold text-slate-700">1. Inquadra il QR Code con l'app di autenticazione</p>
                    {mfaSetupData.qr_code ? (
                      <img
                        src={`data:image/png;base64,${mfaSetupData.qr_code}`}
                        alt="QR Code MFA"
                        className="mx-auto w-44 h-44 border border-slate-300 rounded-lg shadow-sm"
                      />
                    ) : null}
                    <div className="text-[11px] text-slate-500">
                      Oppure inserisci manualmente la chiave segreta:<br />
                      <code className="font-mono bg-white px-2 py-1 border rounded text-xs select-all">
                        {mfaSetupData.secret}
                      </code>
                    </div>
                  </div>

                  <form onSubmit={handleEnableMfa} className="space-y-3">
                    <label className="block text-xs font-bold text-slate-700">
                      2. Inserisci il codice a 6 cifre visualizzato nell'app
                    </label>
                    <input
                      type="text"
                      maxLength={6}
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                      placeholder="000000"
                      className="w-full text-center tracking-widest text-lg font-mono px-3 py-2 border border-slate-300 rounded-xl focus:ring-2 focus:ring-primary-500"
                      required
                    />
                    {mfaError && <p className="text-xs text-rose-600 font-medium">{mfaError}</p>}
                    <button
                      type="submit"
                      disabled={mfaLoading || mfaCode.length !== 6}
                      className="w-full py-2.5 bg-primary-600 hover:bg-primary-700 text-white rounded-xl text-xs font-bold shadow-sm disabled:opacity-50 transition-all"
                    >
                      {mfaLoading ? 'Verifica in corso...' : 'Attiva e Mostra Codici di Recupero'}
                    </button>
                  </form>
                </div>
              )}

              {mfaRecoveryCodes && (
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-5 space-y-3">
                  <h4 className="text-xs font-bold text-amber-900 flex items-center gap-1.5">
                    <span>⚠️</span> Codici di Recupero di Emergenza (Salvali Ora!)
                  </h4>
                  <p className="text-xs text-amber-800">
                    Se perdi l'accesso al tuo dispositivo TOTP, questi codici sono l'unico modo per accedere al sistema.
                  </p>
                  <div className="grid grid-cols-2 gap-2 font-mono text-xs bg-white p-3 border border-amber-200 rounded-lg">
                    {mfaRecoveryCodes.map((code, idx) => (
                      <div key={idx} className="p-1 text-slate-800">{code}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab: API Keys */}
      {activeTab === 'apikeys' && (isAdmin || isOperator) && (
        <div className="bg-white rounded-2xl border border-slate-200 p-6 sm:p-8 space-y-6">
          <div>
            <h2 className="text-base font-bold text-slate-900">Machine Tokens per CI/CD</h2>
            <p className="text-xs text-slate-500 mt-1">
              Token di autenticazione per pipeline automatizzate (GitLab CI, GitHub Actions, Jenkins) con scoping granulare per prodotto.
            </p>
          </div>

          {generatedRawToken && (
            <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-4 space-y-2">
              <h4 className="text-xs font-bold text-emerald-900 flex items-center gap-1.5">
                <span>🔑</span> Token Generato con Successo (Mostrato Solo Una Volta!)
              </h4>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={generatedRawToken}
                  className="w-full text-xs font-mono bg-white px-3 py-2 border border-emerald-300 rounded-lg select-all"
                />
                <button
                  type="button"
                  onClick={() => navigator.clipboard.writeText(generatedRawToken)}
                  className="px-3 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-bold whitespace-nowrap"
                >
                  Copia
                </button>
              </div>
            </div>
          )}

          {/* Create Token Form */}
          <form onSubmit={handleCreateApiKey} className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-4">
            <h3 className="text-xs font-bold text-slate-800">Crea Nuovo Token con Scoping per Prodotto</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">Nome Token</label>
                <input
                  type="text"
                  placeholder="e.g. gitlab-c2-runner"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  className="w-full text-xs px-3 py-2 border border-slate-300 rounded-lg"
                  required
                />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">Ruolo Associato</label>
                <select
                  value={newKeyRole}
                  onChange={(e) => setNewKeyRole(e.target.value)}
                  className="w-full text-xs px-3 py-2 border border-slate-300 rounded-lg bg-white"
                >
                  <option value="operator">Operator (Caricamento &amp; Audit)</option>
                  {isAdmin && <option value="admin">Admin (Completo)</option>}
                  <option value="auditor">Auditor (Sola Lettura)</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">Validità (Giorni)</label>
                <input
                  type="number"
                  placeholder="30 (vuoto = illimitato)"
                  value={newKeyDays}
                  onChange={(e) => setNewKeyDays(e.target.value === '' ? '' : Number(e.target.value))}
                  className="w-full text-xs px-3 py-2 border border-slate-300 rounded-lg"
                />
              </div>
            </div>

            {/* Product Scoping */}
            <div>
              <label className="block text-[11px] font-semibold text-slate-600 mb-1">Ambito Prodotti (Least Privilege)</label>
              <div className="flex items-center gap-4 text-xs text-slate-700 mb-2">
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="scope"
                    checked={scopeType === 'all'}
                    onChange={() => setScopeType('all')}
                  />
                  <span>Tutti i Prodotti (<code>["*"]</code>)</span>
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="scope"
                    checked={scopeType === 'specific'}
                    onChange={() => setScopeType('specific')}
                  />
                  <span>Prodotti Selezionati</span>
                </label>
              </div>

              {scopeType === 'specific' && (
                <div className="border border-slate-200 bg-white rounded-lg p-3 max-h-36 overflow-y-auto space-y-1.5">
                  {products.map((p) => (
                    <label key={p.id} className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedProductSlugs.includes(p.slug)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedProductSlugs([...selectedProductSlugs, p.slug]);
                          } else {
                            setSelectedProductSlugs(selectedProductSlugs.filter((s) => s !== p.slug));
                          }
                        }}
                      />
                      <span className="font-semibold">{p.name}</span>
                      <span className="text-slate-400 font-mono text-[10px]">({p.slug})</span>
                    </label>
                  ))}
                  {products.length === 0 && (
                    <p className="text-xs text-slate-400 italic">Nessun prodotto disponibile a catalogo.</p>
                  )}
                </div>
              )}
            </div>

            {keyError && <p className="text-xs text-rose-600 font-medium">{keyError}</p>}

            <button
              type="submit"
              disabled={createKeyLoading || !newKeyName.trim()}
              className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg text-xs font-bold transition-all disabled:opacity-50"
            >
              {createKeyLoading ? 'Creazione...' : '+ Genera Token Machine'}
            </button>
          </form>

          {/* Tokens List */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold text-slate-800">Token Attivi</h3>
            {keysLoading ? (
              <div className="text-xs text-slate-400 py-4">Caricamento chiavi...</div>
            ) : apiKeys.length === 0 ? (
              <div className="text-xs text-slate-400 py-4 italic">Nessuna chiave API attiva.</div>
            ) : (
              <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden">
                {apiKeys.map((k) => (
                  <div key={k.id} className="p-3.5 flex items-center justify-between text-xs hover:bg-slate-50 transition-colors">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-900">{k.name}</span>
                        <span className="px-1.5 py-0.2 bg-slate-100 text-slate-700 rounded text-[9px] font-mono">
                          {k.key_prefix}••••••••
                        </span>
                        <span className="px-1.5 py-0.2 bg-primary-50 text-primary-700 rounded text-[9px] font-bold uppercase">
                          {k.role}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 mt-0.5">
                        Scope: {Array.isArray(k.allowed_products) && k.allowed_products.includes('*')
                          ? 'Tutti i prodotti'
                          : (k.allowed_products || []).join(', ') || 'Nessuno'}
                        {k.expires_at ? ` • Scade il: ${k.expires_at.split('T')[0]}` : ' • Scadenza: Illimitata'}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleRevokeKey(k.id)}
                      className="px-2.5 py-1 text-rose-600 hover:bg-rose-50 rounded text-xs font-bold transition-colors"
                    >
                      Revoca
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SecuritySettingsPage;
