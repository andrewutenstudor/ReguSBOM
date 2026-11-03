/**
 * ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
 * Security Settings Modal:
 * 1. Two-Factor Authentication (TOTP setup with QR code + emergency recovery codes).
 * 2. Scoped CI/CD Machine API Tokens (Least-privilege product scope).
 */
import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import apiService from '../services/api';
import { ApiKeyItem, ProductItem, MfaSetupResponse } from '../types';

interface SecuritySettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SecuritySettingsModal: React.FC<SecuritySettingsModalProps> = ({ isOpen, onClose }) => {
  const { user, refreshUser, isAdmin, isOperator } = useAuth();

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
    if (isOpen) {
      if (isAdmin || isOperator) {
        fetchKeysAndProducts();
      }
    }
  }, [isOpen]);

  const fetchKeysAndProducts = async () => {
    try {
      setKeysLoading(true);
      const [keysList, prodsList] = await Promise.all([
        apiService.listApiKeys().catch(() => []),
        apiService.listProducts().catch(() => []),
      ]);
      setApiKeys(keysList);
      setProducts(prodsList);
    } catch (err) {
      console.warn('Failed to load keys/products:', err);
    } finally {
      setKeysLoading(false);
    }
  };

  const handleStartMfaSetup = async () => {
    try {
      setMfaLoading(true);
      setMfaError(null);
      const data = await apiService.setupMfa();
      setMfaSetupData(data);
    } catch (err: any) {
      setMfaError(err?.response?.data?.detail || 'Impossibile iniziare la configurazione MFA.');
    } finally {
      setMfaLoading(false);
    }
  };

  const handleConfirmMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaCode.trim()) return;

    try {
      setMfaLoading(true);
      setMfaError(null);
      const res = await apiService.enableMfa(mfaCode.trim());
      setMfaRecoveryCodes(res.recovery_codes);
      setMfaSetupData(null);
      setMfaCode('');
      await refreshUser();
    } catch (err: any) {
      setMfaError(err?.response?.data?.detail || 'Codice non valido. Verifica l\'orario del dispositivo.');
    } finally {
      setMfaLoading(false);
    }
  };

  const handleDisableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setDisableLoading(true);
      setDisableError(null);
      await apiService.disableMfa(disablePassword, disableTotp.trim());
      setIsDisableOpen(false);
      setDisablePassword('');
      setDisableTotp('');
      await refreshUser();
    } catch (err: any) {
      setDisableError(err?.response?.data?.detail || 'Disattivazione fallita: verifica password e codice.');
    } finally {
      setDisableLoading(false);
    }
  };

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;

    const allowedProducts = scopeType === 'all' ? ['*'] : selectedProductSlugs;
    if (scopeType === 'specific' && allowedProducts.length === 0) {
      setKeyError('Seleziona almeno un prodotto per limitare l\'accesso.');
      return;
    }

    try {
      setCreateKeyLoading(true);
      setKeyError(null);
      const res = await apiService.createApiKey(
        newKeyName.trim(),
        newKeyRole,
        newKeyDays === '' ? undefined : Number(newKeyDays),
        allowedProducts
      );
      setGeneratedRawToken(res.token);
      setNewKeyName('');
      setSelectedProductSlugs([]);
      setScopeType('all');
      await fetchKeysAndProducts();
    } catch (err: any) {
      setKeyError(err?.response?.data?.detail || 'Impossibile creare il token API.');
    } finally {
      setCreateKeyLoading(false);
    }
  };

  const handleRevokeKey = async (keyId: number) => {
    if (!window.confirm('Sei sicuro di voler revocare definitivamente questo Machine Token?')) return;
    try {
      await apiService.revokeApiKey(keyId);
      await fetchKeysAndProducts();
    } catch (err) {
      alert('Impossibile revocare il token.');
    }
  };

  const toggleProductSelection = (slug: string) => {
    setSelectedProductSlugs((prev) =>
      prev.includes(slug) ? prev.filter((s) => s !== slug) : [...prev, slug]
    );
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full p-6 text-white shadow-2xl my-8">
        {/* Header */}
        <div className="flex justify-between items-center pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <span className="text-xl">⚙️</span>
            <div>
              <h2 className="text-lg font-bold">Impostazioni di Sicurezza &amp; Accesso</h2>
              <p className="text-xs text-slate-400">
                Utente: <strong>{user?.username}</strong> • Ruolo: <span className="uppercase text-primary-400">{user?.role}</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white text-xl p-1 rounded-lg hover:bg-slate-800"
          >
            ✕
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 my-4 border-b border-slate-800">
          <button
            onClick={() => setActiveTab('mfa')}
            className={`pb-2 px-3 text-sm font-semibold border-b-2 transition-all ${
              activeTab === 'mfa'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            📱 Autenticazione a Due Fattori (MFA)
          </button>
          {(isAdmin || isOperator) && (
            <button
              onClick={() => setActiveTab('apikeys')}
              className={`pb-2 px-3 text-sm font-semibold border-b-2 transition-all ${
                activeTab === 'apikeys'
                  ? 'border-primary-500 text-primary-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              🔑 Machine Tokens Scoped (CI/CD)
            </button>
          )}
        </div>

        {/* TAB 1: MFA MANAGEMENT */}
        {activeTab === 'mfa' && (
          <div className="space-y-4 py-2">
            {user?.mfa_enabled ? (
              <div className="bg-emerald-950/40 border border-emerald-500/30 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">🛡️</span>
                    <div>
                      <h4 className="text-sm font-bold text-emerald-300">Autenticazione a Due Fattori Attiva</h4>
                      <p className="text-xs text-emerald-400/80">
                        Il tuo account è protetto con TOTP (Microsoft / Google Authenticator).
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setIsDisableOpen(!isDisableOpen)}
                    className="px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 rounded text-xs font-semibold transition-all"
                  >
                    Disattiva MFA
                  </button>
                </div>

                {/* Disable Form Dropdown */}
                {isDisableOpen && (
                  <form onSubmit={handleDisableMfa} className="mt-3 pt-3 border-t border-emerald-800/40 space-y-3">
                    <p className="text-xs text-slate-300">
                      Conferma la password e inserisci un codice per disattivare l'MFA:
                    </p>
                    {disableError && (
                      <div className="p-2 bg-red-500/20 border border-red-500/40 text-red-300 text-xs rounded">
                        {disableError}
                      </div>
                    )}
                    <div className="grid grid-cols-2 gap-2">
                      <input
                        type="password"
                        required
                        placeholder="Password attuale"
                        value={disablePassword}
                        onChange={(e) => setDisablePassword(e.target.value)}
                        className="px-3 py-2 bg-slate-900 border border-slate-700 rounded text-xs text-white"
                      />
                      <input
                        type="text"
                        required
                        placeholder="Codice 6 cifre"
                        value={disableTotp}
                        onChange={(e) => setDisableTotp(e.target.value)}
                        className="px-3 py-2 bg-slate-900 border border-slate-700 rounded text-xs text-white"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={disableLoading}
                      className="px-4 py-1.5 bg-red-600 hover:bg-red-500 rounded text-xs font-bold text-white transition-all disabled:opacity-50"
                    >
                      {disableLoading ? 'Disattivazione...' : 'Conferma Disattivazione'}
                    </button>
                  </form>
                )}
              </div>
            ) : (
              <div>
                {!mfaSetupData && !mfaRecoveryCodes && (
                  <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 space-y-4">
                    <div className="flex items-start gap-3">
                      <span className="text-3xl">📱</span>
                      <div>
                        <h4 className="text-sm font-bold text-white">Configura Multi-Factor Authentication</h4>
                        <p className="text-xs text-slate-400 mt-1">
                          Proteggi il tuo account ReguBOM con uno strato di sicurezza aggiuntivo compatibile con le raccomandazioni <strong>ENISA 2026</strong> e <strong>NIS2 Art. 21</strong>.
                        </p>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={handleStartMfaSetup}
                      disabled={mfaLoading}
                      className="py-2.5 px-4 bg-primary-600 hover:bg-primary-500 rounded-lg text-sm font-bold text-white transition-all flex items-center gap-2"
                    >
                      {mfaLoading ? 'Generazione...' : 'Inizia Configurazione MFA'}
                    </button>
                  </div>
                )}

                {/* Setup in progress: QR code + verification code */}
                {mfaSetupData && (
                  <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 space-y-4">
                    <h4 className="text-sm font-bold text-white">1. Scansiona il QR Code con la tua App</h4>
                    <p className="text-xs text-slate-300">
                      Apri <strong>Microsoft Authenticator</strong> o <strong>Google Authenticator</strong> e inquadra il codice sottostante:
                    </p>

                    <div className="flex flex-col sm:flex-row items-center gap-6 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
                      <div className="bg-white p-2 rounded-lg shadow-md inline-block">
                        <img src={mfaSetupData.qr_code} alt="TOTP QR Code" className="w-36 h-36" />
                      </div>
                      <div className="text-xs space-y-2">
                        <p className="text-slate-400">Non riesci a scansionare? Inserisci la chiave manuale:</p>
                        <code className="block p-2 bg-slate-900 border border-slate-700 rounded font-mono text-primary-300 break-all select-all">
                          {mfaSetupData.secret}
                        </code>
                        <p className="text-[11px] text-slate-500">Tipo: Basato sul tempo (TOTP, 30s) • Cifre: 6</p>
                      </div>
                    </div>

                    <form onSubmit={handleConfirmMfa} className="space-y-3 pt-2">
                      <h4 className="text-sm font-bold text-white">2. Verifica e Attiva</h4>
                      {mfaError && (
                        <div className="p-2 bg-red-500/20 border border-red-500/30 text-red-300 text-xs rounded">
                          {mfaError}
                        </div>
                      )}
                      <div className="flex gap-2">
                        <input
                          type="text"
                          required
                          maxLength={6}
                          value={mfaCode}
                          onChange={(e) => setMfaCode(e.target.value)}
                          placeholder="Codice a 6 cifre (es. 123456)"
                          className="px-3 py-2 bg-slate-900 border border-slate-700 rounded text-sm text-white font-mono tracking-wider w-48 text-center"
                        />
                        <button
                          type="submit"
                          disabled={mfaLoading || mfaCode.length < 6}
                          className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded text-sm font-bold text-white transition-all"
                        >
                          {mfaLoading ? 'Verifica...' : 'Conferma e Attiva MFA'}
                        </button>
                      </div>
                    </form>
                  </div>
                )}

                {/* Newly activated recovery codes */}
                {mfaRecoveryCodes && (
                  <div className="bg-slate-800 border border-emerald-500/50 rounded-xl p-5 space-y-4">
                    <div className="flex items-center gap-2 text-emerald-400">
                      <span className="text-xl">✅</span>
                      <h4 className="text-sm font-bold">MFA Attivata con Successo!</h4>
                    </div>
                    <div className="bg-amber-500/10 border border-amber-500/30 text-amber-300 p-3 rounded text-xs">
                      <strong>⚠️ Salva questi codici di recupero d'emergenza in un luogo sicuro.</strong>
                      <br />Ciascun codice può essere usato una sola volta se perdi l'accesso all'app authenticator:
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 bg-slate-950 p-3 rounded font-mono text-center text-xs text-primary-300">
                      {mfaRecoveryCodes.map((c, i) => (
                        <div key={i} className="p-1 bg-slate-900 rounded border border-slate-800 select-all">
                          {c}
                        </div>
                      ))}
                    </div>
                    <button
                      type="button"
                      onClick={() => setMfaRecoveryCodes(null)}
                      className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-xs font-semibold text-white transition-all"
                    >
                      Ho salvato i codici
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* TAB 2: SCOPED API KEYS MANAGEMENT */}
        {activeTab === 'apikeys' && (isAdmin || isOperator) && (
          <div className="space-y-5 py-2">
            {/* Show generated token once */}
            {generatedRawToken && (
              <div className="bg-amber-500/10 border border-amber-500/40 rounded-xl p-4 space-y-2">
                <div className="flex items-center gap-2 text-amber-400 text-sm font-bold">
                  <span>⚠️</span>
                  <span>Nuovo Token Machine Generato con Successo</span>
                </div>
                <p className="text-xs text-slate-300">
                  Copia e salva questo token in un segreto CI/CD (es. <code>REGUBOM_API_KEY</code>). Non verrà mostrato nuovamente:
                </p>
                <div className="flex gap-2 items-center">
                  <input
                    type="text"
                    readOnly
                    value={generatedRawToken}
                    className="w-full px-3 py-2 bg-slate-950 border border-amber-500/50 rounded font-mono text-xs text-amber-300 select-all"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(generatedRawToken);
                      alert('Token copiato negli appunti!');
                    }}
                    className="px-3 py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold rounded text-xs whitespace-nowrap"
                  >
                    Copia
                  </button>
                </div>
                <button
                  type="button"
                  onClick={() => setGeneratedRawToken(null)}
                  className="text-xs text-slate-400 hover:text-white underline pt-1"
                >
                  Chiudi questo avviso
                </button>
              </div>
            )}

            {/* Creation form */}
            <form onSubmit={handleCreateKey} className="bg-slate-800/80 border border-slate-700 rounded-xl p-4 space-y-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                + Genera Nuovo Machine Token (CI/CD)
              </h4>

              {keyError && (
                <div className="p-2 bg-red-500/20 border border-red-500/30 text-red-300 text-xs rounded">
                  {keyError}
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Nome Pipeline / Runner</label>
                  <input
                    type="text"
                    required
                    placeholder="es. GitLab-Runner-Core"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs text-white"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Ruolo Associato</label>
                  <select
                    value={newKeyRole}
                    onChange={(e) => setNewKeyRole(e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs text-white"
                  >
                    <option value="operator">operator (Upload &amp; Catalog)</option>
                    {isAdmin && <option value="admin">admin (Full Control)</option>}
                    <option value="auditor">auditor (Read-Only)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Scadenza (Giorni)</label>
                  <input
                    type="number"
                    min="1"
                    placeholder="Nessuna scadenza"
                    value={newKeyDays}
                    onChange={(e) => setNewKeyDays(e.target.value === '' ? '' : Number(e.target.value))}
                    className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs text-white"
                  />
                </div>
              </div>

              {/* Product Scope Selector (Least-Privilege) */}
              <div className="pt-2 border-t border-slate-700/60">
                <label className="block text-[11px] font-semibold text-slate-300 mb-1.5">
                  Ambito di Accesso (Product Scope - Least Privilege)
                </label>
                <div className="flex gap-4 text-xs mb-2">
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="radio"
                      name="scopeType"
                      checked={scopeType === 'all'}
                      onChange={() => setScopeType('all')}
                      className="text-primary-500"
                    />
                    <span>Tutti i Prodotti (Accesso Globale [*])</span>
                  </label>
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="radio"
                      name="scopeType"
                      checked={scopeType === 'specific'}
                      onChange={() => setScopeType('specific')}
                      className="text-primary-500"
                    />
                    <span>Limita a Prodotti Specifici</span>
                  </label>
                </div>

                {scopeType === 'specific' && (
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800 max-h-32 overflow-y-auto space-y-1">
                    {products.length === 0 ? (
                      <p className="text-xs text-slate-500">Nessun prodotto trovato nel catalogo.</p>
                    ) : (
                      products.map((p) => (
                        <label key={p.id} className="flex items-center gap-2 text-xs text-slate-300 hover:text-white cursor-pointer">
                          <input
                            type="checkbox"
                            checked={selectedProductSlugs.includes(p.slug)}
                            onChange={() => toggleProductSelection(p.slug)}
                            className="rounded border-slate-700 text-primary-500"
                          />
                          <span><strong>{p.name}</strong> <code className="text-slate-500 text-[10px]">({p.slug})</code></span>
                        </label>
                      ))
                    )}
                  </div>
                )}
              </div>

              <div className="pt-1">
                <button
                  type="submit"
                  disabled={createKeyLoading}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white font-bold text-xs rounded transition-all"
                >
                  {createKeyLoading ? 'Generazione...' : 'Crea Token Machine'}
                </button>
              </div>
            </form>

            {/* Existing Keys Table */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Token Attivi</h4>
              {keysLoading ? (
                <p className="text-xs text-slate-500">Caricamento token in corso...</p>
              ) : apiKeys.length === 0 ? (
                <p className="text-xs text-slate-500">Nessun token registrato.</p>
              ) : (
                <div className="border border-slate-800 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-800/80 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="p-2">Nome</th>
                        <th className="p-2">Prefisso</th>
                        <th className="p-2">Ruolo</th>
                        <th className="p-2">Scope Prodotti</th>
                        <th className="p-2">Ultimo Uso</th>
                        <th className="p-2 text-right">Azioni</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {apiKeys.map((k) => (
                        <tr key={k.id} className="hover:bg-slate-800/30">
                          <td className="p-2 font-semibold text-white">{k.name}</td>
                          <td className="p-2 font-mono text-slate-400">{k.key_prefix}...</td>
                          <td className="p-2">
                            <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-slate-300">
                              {k.role}
                            </span>
                          </td>
                          <td className="p-2 text-slate-300">
                            {k.allowed_products && k.allowed_products.includes('*') ? (
                              <span className="text-emerald-400 font-mono text-[11px]">[*] Globale</span>
                            ) : (
                              <span className="text-primary-300 font-mono text-[11px]">
                                {k.allowed_products?.join(', ') || '[*]'}
                              </span>
                            )}
                          </td>
                          <td className="p-2 text-slate-400 text-[11px]">
                            {k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'Mai'}
                          </td>
                          <td className="p-2 text-right">
                            <button
                              type="button"
                              onClick={() => handleRevokeKey(k.id)}
                              className="px-2 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded text-[11px] transition-all"
                            >
                              Revoca
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="pt-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs font-semibold text-slate-300 transition-all"
          >
            Chiudi
          </button>
        </div>
      </div>
    </div>
  );
};

export default SecuritySettingsModal;
