import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import apiService from '../services/api';
import { useAuth } from '../context/AuthContext';
import { ProductItem, ProductReleaseItem, SBOMArtifactItem, SystemTier, LifecycleStatus } from '../types';

const TIERS: { id: SystemTier; label: string; icon: string; desc: string }[] = [
  { id: 'OS', label: 'Operating System', icon: '💻', desc: 'Kernel, pacchetti di sistema, librerie OS e runtime base' },
  { id: 'CONTAINER', label: 'Container Image', icon: '📦', desc: 'Layer Docker/OCI, immagini base e dipendenze filesystem' },
  { id: 'APPLICATION', label: 'Application & Services', icon: '⚡', desc: 'Librerie applicative proprietarie e di terze parti (OSS)' },
  { id: 'FIRMWARE', label: 'Firmware & Hardware', icon: '🔌', desc: 'Componenti embedded, microcodice e interfacce hardware' },
];

const ProductDetailPage: React.FC = () => {
  const { productId } = useParams<{ productId: string }>();
  const navigate = useNavigate();
  const { canMutate } = useAuth();

  const [product, setProduct] = useState<ProductItem | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Release Modal
  const [isReleaseModalOpen, setIsReleaseModalOpen] = useState<boolean>(false);
  const [releaseVersion, setReleaseVersion] = useState<string>('');
  const [releaseStatus, setReleaseStatus] = useState<LifecycleStatus>('DRAFT');
  const [releaseSubmitting, setReleaseSubmitting] = useState<boolean>(false);
  const [releaseError, setReleaseError] = useState<string | null>(null);

  // Upload SBOM Modal
  const [isUploadModalOpen, setIsUploadModalOpen] = useState<boolean>(false);
  const [targetReleaseVersion, setTargetReleaseVersion] = useState<string>('');
  const [selectedTier, setSelectedTier] = useState<SystemTier>('APPLICATION');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [propPrefix, setPropPrefix] = useState<string>('regubom:proprietary');
  const [propSupplier, setPropSupplier] = useState<string>('');
  const [uploading, setUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadResult, setUploadResult] = useState<any | null>(null);

  // Copied hash tooltip state
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    if (productId) {
      loadProduct();
    }
  }, [productId]);

  const loadProduct = async () => {
    if (!productId) return;
    try {
      setLoading(true);
      setError(null);
      const data = await apiService.getProduct(productId);
      setProduct(data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Impossibile caricare il prodotto richiesto.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateRelease = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!product || !releaseVersion.trim()) return;

    try {
      setReleaseSubmitting(true);
      setReleaseError(null);
      await apiService.createRelease(product.id, {
        version: releaseVersion.trim(),
        lifecycle_status: releaseStatus,
      });

      setReleaseVersion('');
      setReleaseStatus('DRAFT');
      setIsReleaseModalOpen(false);
      await loadProduct();
    } catch (err: any) {
      setReleaseError(err?.response?.data?.detail || 'Impossibile registrare il rilascio.');
    } finally {
      setReleaseSubmitting(false);
    }
  };

  const handleUpdateReleaseStatus = async (releaseId: number, newStatus: LifecycleStatus) => {
    if (!product) return;
    try {
      await apiService.updateRelease(product.id, releaseId, {
        lifecycle_status: newStatus,
      });
      await loadProduct();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Impossibile aggiornare lo stato del rilascio.');
    }
  };

  const handleDeleteRelease = async (releaseId: number, versionStr: string) => {
    if (!product) return;
    if (!window.confirm(`Sei sicuro di voler eliminare il rilascio ${versionStr} e tutti i suoi SBOM?`)) {
      return;
    }

    try {
      await apiService.deleteRelease(product.id, releaseId);
      await loadProduct();
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Impossibile eliminare il rilascio.');
    }
  };

  const handleDeleteProduct = async () => {
    if (!product) return;
    if (!window.confirm(`ATTENZIONE: Stai per eliminare il prodotto "${product.name}" e tutti i suoi rilasci. Questa azione è irreversibile. Continuare?`)) {
      return;
    }

    try {
      await apiService.deleteProduct(product.id);
      navigate('/catalog');
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Impossibile eliminare il prodotto.');
    }
  };

  const openUploadModal = (releaseVer: string, preselectedTier?: SystemTier) => {
    setTargetReleaseVersion(releaseVer);
    if (preselectedTier) setSelectedTier(preselectedTier);
    setSelectedFile(null);
    setUploadResult(null);
    setUploadError(null);
    setIsUploadModalOpen(true);
  };

  const handleUploadSbom = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!product || !selectedFile || !targetReleaseVersion) return;

    try {
      setUploading(true);
      setUploadError(null);
      setUploadResult(null);

      const res = await apiService.uploadSbomToRelease(
        product.id,
        targetReleaseVersion,
        selectedFile,
        selectedTier,
        propPrefix.trim() || undefined,
        propSupplier.trim() || undefined
      );

      setUploadResult(res);
      await loadProduct();
    } catch (err: any) {
      setUploadError(err?.response?.data?.detail || 'Errore durante l\'ingestione e audit dello SBOM.');
    } finally {
      setUploading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2500);
  };

  const getVerdictBadge = (verdict?: string | null) => {
    switch (verdict) {
      case 'PASS':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
            ✓ Conforme
          </span>
        );
      case 'WARNING':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-200">
            ! Avviso Non Bloccante
          </span>
        );
      case 'FAIL':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-200">
            ✕ Non Conforme
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">
            Nessun Artifact
          </span>
        );
    }
  };

  if (loading) {
    return (
      <div className="text-center py-20 bg-white rounded-xl border border-slate-200 shadow-sm max-w-7xl mx-auto">
        <div className="inline-block animate-spin text-3xl">⏳</div>
        <p className="mt-2 text-sm text-slate-600 font-medium">Caricamento gerarchia prodotto in corso...</p>
      </div>
    );
  }

  if (error || !product) {
    return (
      <div className="max-w-7xl mx-auto space-y-4">
        <Link to="/catalog" className="text-sm font-bold text-primary-600 hover:text-primary-800">
          &larr; Torna al Catalogo Prodotti
        </Link>
        <div className="p-6 bg-rose-50 border border-rose-200 rounded-xl text-rose-800 text-sm">
          ⚠️ {error || 'Prodotto non trovato.'}
        </div>
      </div>
    );
  }

  const releases = product.releases || [];

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Breadcrumb Navigation */}
      <div className="flex items-center justify-between text-xs">
        <nav className="flex items-center gap-2 text-slate-500 font-medium">
          <Link to="/catalog" className="hover:text-primary-600 transition-colors">
            Catalogo Prodotti
          </Link>
          <span>/</span>
          <span className="text-slate-900 font-bold">{product.name}</span>
        </nav>
        {canMutate && (
          <button
            onClick={handleDeleteProduct}
            className="text-rose-600 hover:text-rose-800 font-bold transition-colors"
          >
            🗑️ Elimina Prodotto
          </button>
        )}
      </div>

      {/* Product Hero Header */}
      <div className="bg-white p-6 sm:p-8 rounded-2xl border border-slate-200 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-2xl sm:text-3xl font-black text-slate-900 tracking-tight">
              {product.name}
            </h1>
            <span className="font-mono text-xs px-2.5 py-1 bg-slate-100 text-slate-700 border border-slate-200 rounded-md">
              slug: {product.slug}
            </span>
            {product.business_unit && (
              <span className="px-2.5 py-1 bg-primary-50 text-primary-700 border border-primary-200 rounded-md text-xs font-bold">
                {product.business_unit}
              </span>
            )}
          </div>
          <p className="text-sm text-slate-600 mt-2 max-w-3xl leading-relaxed">
            {product.description || 'Nessuna descrizione architetturale disponibile per questo prodotto.'}
          </p>
          <div className="flex items-center gap-4 mt-4 text-xs text-slate-400">
            <span>Data creazione: {new Date(product.created_at).toLocaleDateString()}</span>
            <span>•</span>
            <span>Rilasci mappati: <strong className="text-slate-700">{releases.length}</strong></span>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <button
            onClick={() => setIsReleaseModalOpen(true)}
            className="px-5 py-2.5 bg-primary-600 hover:bg-primary-700 text-white font-bold text-sm rounded-xl shadow-sm transition-all focus:ring-2 focus:ring-primary-500 flex items-center justify-center gap-2"
          >
            <span>+</span> Registra Rilascio
          </button>
        </div>
      </div>

      {/* System Tiers Reference Cards */}
      <div className="bg-slate-50 p-5 rounded-2xl border border-slate-200">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-600">
            Modello Architetturale a 4 Livelli (Multi-Tier SBOM Hierarchy)
          </h3>
          <span className="text-[11px] font-semibold text-slate-400">ENISA Advisory 2026 &amp; BSI TR-03183-2</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          {TIERS.map((tier) => (
            <div key={tier.id} className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-2xs">
              <div className="flex items-center gap-2 font-bold text-slate-900">
                <span className="text-lg">{tier.icon}</span>
                <span>{tier.label}</span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 bg-slate-100 rounded text-slate-600 ml-auto">
                  {tier.id}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-1 leading-snug">{tier.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Version Releases Tree */}
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-black text-slate-900 tracking-tight flex items-center gap-2">
            <span>🏷️</span> Rilasci e Albero dei Livelli di Sistema ({releases.length})
          </h2>
          {releases.length > 0 && (
            <button
              onClick={() => setIsReleaseModalOpen(true)}
              className="text-xs font-bold text-primary-600 hover:text-primary-800"
            >
              + Aggiungi un'altra versione
            </button>
          )}
        </div>

        {releases.length === 0 ? (
          <div className="p-12 text-center bg-white rounded-2xl border border-slate-200 shadow-sm">
            <span className="text-4xl">🏷️</span>
            <h3 className="text-base font-bold text-slate-900 mt-2">Nessun rilascio registrato</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
              Registra una versione di rilascio (es. v1.0.0, v2.1.0) per associare gli SBOM dei singoli livelli architetturali.
            </p>
            <button
              onClick={() => setIsReleaseModalOpen(true)}
              className="mt-4 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white font-bold text-xs rounded-lg shadow-sm"
            >
              + Registra Primo Rilascio
            </button>
          </div>
        ) : (
          <div className="space-y-6">
            {releases.map((rel) => {
              const artifacts = rel.artifacts || [];

              return (
                <div
                  key={rel.id}
                  className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden"
                >
                  {/* Release Version Header */}
                  <div className="p-5 bg-slate-50/80 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="flex flex-wrap items-center gap-3">
                      <span className="text-lg font-black font-mono text-slate-900 bg-white px-3 py-1 rounded-lg border border-slate-200 shadow-2xs">
                        {rel.version}
                      </span>
                      {getVerdictBadge(rel.overall_verdict)}

                      {/* Lifecycle Status Selector */}
                      <div className="flex items-center gap-1.5 ml-2">
                        <span className="text-[11px] font-bold text-slate-400">Stato:</span>
                        <select
                          value={rel.lifecycle_status}
                          onChange={(e) =>
                            handleUpdateReleaseStatus(rel.id, e.target.value as LifecycleStatus)
                          }
                          className="text-xs font-bold px-2.5 py-1 bg-white border border-slate-300 rounded-lg focus:ring-1 focus:ring-primary-500"
                        >
                          <option value="DRAFT">DRAFT</option>
                          <option value="VALIDATED">VALIDATED</option>
                          <option value="RELEASED">RELEASED</option>
                          <option value="EOL">END-OF-LIFE (EOL)</option>
                        </select>
                      </div>

                      {rel.release_date && (
                        <span className="text-xs text-slate-400">
                          Data: {new Date(rel.release_date).toLocaleDateString()}
                        </span>
                      )}
                    </div>

                    {canMutate && (
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => openUploadModal(rel.version)}
                          className="px-3.5 py-1.5 bg-primary-600 hover:bg-primary-700 text-white font-bold text-xs rounded-lg shadow-sm transition-colors flex items-center gap-1.5"
                        >
                          <span>+</span> Carica SBOM Tier
                        </button>
                        <button
                          onClick={() => handleDeleteRelease(rel.id, rel.version)}
                          className="px-2.5 py-1.5 text-slate-400 hover:text-rose-600 transition-colors text-xs font-semibold"
                          title="Elimina rilascio"
                        >
                          ✕
                        </button>
                      </div>
                    )}
                  </div>

                  {/* 4 Tiers Grid */}
                  <div className="p-5">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                      {TIERS.map((tier) => {
                        const artifact = artifacts.find((a) => a.tier === tier.id);

                        return (
                          <div
                            key={tier.id}
                            className={`rounded-xl border p-4 flex flex-col justify-between transition-all ${
                              artifact
                                ? 'bg-white border-slate-200 shadow-2xs'
                                : 'bg-slate-50/50 border-dashed border-slate-200 hover:border-slate-300'
                            }`}
                          >
                            <div>
                              <div className="flex items-center justify-between">
                                <span className="font-bold text-xs text-slate-800 flex items-center gap-1.5">
                                  <span>{tier.icon}</span> {tier.label}
                                </span>
                                {artifact && getVerdictBadge(artifact.overall_status)}
                              </div>

                              {artifact ? (
                                <div className="mt-3 space-y-2 text-xs">
                                  <div className="flex items-center justify-between text-[11px] text-slate-500">
                                    <span>Formato:</span>
                                    <span className="font-bold text-slate-800">
                                      {artifact.format.toUpperCase()} {artifact.spec_version}
                                    </span>
                                  </div>

                                  <div className="pt-1">
                                    <span className="text-[10px] text-slate-400 block uppercase font-bold">
                                      Impronta SHA-256:
                                    </span>
                                    <div className="flex items-center justify-between font-mono text-[10px] bg-slate-50 p-1.5 rounded border border-slate-100 mt-0.5">
                                      <span className="truncate mr-1" title={artifact.sha256_hash}>
                                        {artifact.sha256_hash.substring(0, 16)}...
                                      </span>
                                      <button
                                        onClick={() => copyToClipboard(artifact.sha256_hash)}
                                        className="text-primary-600 hover:text-primary-800 font-bold ml-1 text-[10px]"
                                      >
                                        {copiedHash === artifact.sha256_hash ? '✓' : 'Copia'}
                                      </button>
                                    </div>
                                  </div>
                                </div>
                              ) : (
                                <div className="mt-4 text-center py-4">
                                  <span className="text-slate-400 text-xs block">Nessun SBOM associato</span>
                                  {canMutate && (
                                    <button
                                      onClick={() => openUploadModal(rel.version, tier.id)}
                                      className="mt-2 text-xs font-bold text-primary-600 hover:text-primary-800 hover:underline"
                                    >
                                      + Associa {tier.label}
                                    </button>
                                  )}
                                </div>
                              )}
                            </div>

                            {/* Quick Links for Present Artifacts */}
                            {artifact && artifact.validation_report_id && (
                              <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between gap-1">
                                <Link
                                  to={`/reports/${artifact.validation_report_id}`}
                                  className="text-xs font-bold text-primary-700 hover:text-primary-900 inline-flex items-center gap-1"
                                >
                                  <span>📊 Matrice 8 Colonne</span> &rarr;
                                </Link>
                                <a
                                  href={apiService.downloadCertificate(artifact.validation_report_id)}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-[11px] font-bold text-slate-500 hover:text-slate-800"
                                  title="Scarica Certificato di Conformità JSON"
                                >
                                  Certificato
                                </a>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* CREATE RELEASE MODAL */}
      {isReleaseModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-md w-full shadow-2xl border border-slate-200 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
              <h3 className="text-base font-bold text-slate-900">Registra Rilascio Software</h3>
              <button
                onClick={() => setIsReleaseModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 text-xl font-bold leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateRelease} className="p-6 space-y-4">
              {releaseError && (
                <div className="p-3 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded-lg">
                  {releaseError}
                </div>
              )}

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1">
                  Versione Rilascio *
                </label>
                <input
                  type="text"
                  required
                  placeholder="es. v2.1.0, 1.4.2-rc1..."
                  value={releaseVersion}
                  onChange={(e) => setReleaseVersion(e.target.value)}
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-primary-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1">
                  Stato Ciclo di Vita (Lifecycle Status)
                </label>
                <select
                  value={releaseStatus}
                  onChange={(e) => setReleaseStatus(e.target.value as LifecycleStatus)}
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-lg text-sm bg-white focus:ring-2 focus:ring-primary-500 focus:outline-none"
                >
                  <option value="DRAFT">DRAFT — In sviluppo / test iniziale</option>
                  <option value="VALIDATED">VALIDATED — SBOM auditato e conforme</option>
                  <option value="RELEASED">RELEASED — Rilasciato in produzione</option>
                  <option value="EOL">END-OF-LIFE — Dismesso / non supportato</option>
                </select>
              </div>

              <div className="pt-3 border-t border-slate-200 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsReleaseModalOpen(false)}
                  className="px-4 py-2 border border-slate-300 rounded-lg text-xs font-bold text-slate-700 hover:bg-slate-100"
                >
                  Annulla
                </button>
                <button
                  type="submit"
                  disabled={releaseSubmitting}
                  className="px-5 py-2 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 text-white rounded-lg text-xs font-bold shadow-sm"
                >
                  {releaseSubmitting ? 'Salvataggio...' : 'Crea Rilascio'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* UPLOAD TIER SBOM MODAL */}
      {isUploadModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-xl w-full shadow-2xl border border-slate-200 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
              <div>
                <h3 className="text-base font-bold text-slate-900">
                  Carica SBOM nel Rilascio {targetReleaseVersion}
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Audit automatico ENISA October 2026, BSI TR-03183-2 e CRA Art. 13
                </p>
              </div>
              <button
                onClick={() => setIsUploadModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 text-xl font-bold leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleUploadSbom} className="p-6 space-y-4">
              {uploadError && (
                <div className="p-3 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded-lg">
                  {uploadError}
                </div>
              )}

              {/* Success Result Box */}
              {uploadResult && (
                <div className="p-4 bg-emerald-50 border border-emerald-200 text-emerald-900 rounded-xl space-y-2">
                  <div className="flex items-center justify-between font-bold text-sm">
                    <span>✅ SBOM Ingestito ed Auditato con Successo!</span>
                    {getVerdictBadge(uploadResult.overall_status)}
                  </div>
                  <p className="text-xs text-emerald-800">
                    Checklist CRA: {uploadResult.checklist_summary?.passed} superati, {uploadResult.checklist_summary?.warning} avvisi, {uploadResult.checklist_summary?.fail} falliti.
                  </p>
                  <div className="pt-2 flex gap-2">
                    <Link
                      to={uploadResult.report_url}
                      className="px-4 py-1.5 bg-emerald-600 text-white rounded-lg text-xs font-bold hover:bg-emerald-700 transition-colors"
                    >
                      Apri Dossier e Matrice 8 Colonne &rarr;
                    </Link>
                    <button
                      type="button"
                      onClick={() => setIsUploadModalOpen(false)}
                      className="px-3 py-1.5 bg-white border border-emerald-300 text-emerald-800 rounded-lg text-xs font-bold"
                    >
                      Chiudi
                    </button>
                  </div>
                </div>
              )}

              {!uploadResult && (
                <>
                  <div>
                    <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1">
                      Livello Architetturale di Sistema (System Tier) *
                    </label>
                    <div className="grid grid-cols-2 gap-2">
                      {TIERS.map((tier) => (
                        <button
                          key={tier.id}
                          type="button"
                          onClick={() => setSelectedTier(tier.id)}
                          className={`p-2.5 rounded-xl border text-left flex items-center gap-2 transition-all ${
                            selectedTier === tier.id
                              ? 'border-primary-600 bg-primary-50 text-primary-900 font-bold ring-1 ring-primary-500'
                              : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                          }`}
                        >
                          <span className="text-base">{tier.icon}</span>
                          <span className="text-xs">{tier.label}</span>
                        </button>
                      ))}
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1">
                      File SBOM (CycloneDX v1.6/v1.7 o SPDX v2.3/v3.0.1) *
                    </label>
                    <input
                      type="file"
                      required
                      accept=".json,.cdx,.spdx"
                      onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                      className="w-full text-xs text-slate-500 file:mr-3 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-bold file:bg-primary-50 file:text-primary-700 hover:file:bg-primary-100 border border-slate-300 rounded-lg p-1.5"
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                    <div>
                      <label className="block text-[11px] font-bold text-slate-600 mb-1">
                        Prefisso Componenti Core / Proprietari
                      </label>
                      <input
                        type="text"
                        value={propPrefix}
                        onChange={(e) => setPropPrefix(e.target.value)}
                        className="w-full px-3 py-1.5 border border-slate-300 rounded-lg text-xs font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-bold text-slate-600 mb-1">
                        Fornitore / Produttore Proprietario
                      </label>
                      <input
                        type="text"
                        placeholder={product.name}
                        value={propSupplier}
                        onChange={(e) => setPropSupplier(e.target.value)}
                        className="w-full px-3 py-1.5 border border-slate-300 rounded-lg text-xs"
                      />
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-200 flex justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => setIsUploadModalOpen(false)}
                      className="px-4 py-2 border border-slate-300 rounded-lg text-xs font-bold text-slate-700 hover:bg-slate-100"
                    >
                      Annulla
                    </button>
                    <button
                      type="submit"
                      disabled={uploading || !selectedFile}
                      className="px-5 py-2 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 text-white rounded-lg text-xs font-bold shadow-sm flex items-center gap-2"
                    >
                      {uploading ? (
                        <>
                          <span className="animate-spin">⏳</span> Audit ENISA in corso...
                        </>
                      ) : (
                        'Ingestisci & Valida SBOM'
                      )}
                    </button>
                  </div>
                </>
              )}
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProductDetailPage;
