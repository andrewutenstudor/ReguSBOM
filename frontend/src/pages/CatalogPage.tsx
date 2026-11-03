import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import apiService from '../services/api';
import { useAuth } from '../context/AuthContext';
import { ProductItem, ComponentSearchMatch, SystemTier, LifecycleStatus } from '../types';

const CatalogPage: React.FC = () => {
  const { canMutate, role } = useAuth();
  const [products, setProducts] = useState<ProductItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Search & Filter state
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedBu, setSelectedBu] = useState<string>('all');

  // New Product Modal state
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [newProdName, setNewProdName] = useState<string>('');
  const [newProdSlug, setNewProdSlug] = useState<string>('');
  const [newProdDesc, setNewProdDesc] = useState<string>('');
  const [newProdBu, setNewProdBu] = useState<string>('');
  const [createSubmitting, setCreateSubmitting] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Global Component Search state
  const [activeTab, setActiveTab] = useState<'catalog' | 'component_search'>('catalog');
  const [compSearchQuery, setCompSearchQuery] = useState<string>('');
  const [compSearchVersion, setCompSearchVersion] = useState<string>('');
  const [compSearchResults, setCompSearchResults] = useState<ComponentSearchMatch[]>([]);
  const [compSearchLoading, setCompSearchLoading] = useState<boolean>(false);
  const [compSearchPerformed, setCompSearchPerformed] = useState<boolean>(false);

  useEffect(() => {
    fetchProducts();
  }, []);

  const fetchProducts = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await apiService.listProducts();
      setProducts(data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Errore nel caricamento del catalogo prodotti.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateProduct = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newProdName.trim()) {
      setCreateError('Il nome del prodotto è obbligatorio.');
      return;
    }

    try {
      setCreateSubmitting(true);
      setCreateError(null);
      await apiService.createProduct({
        name: newProdName.trim(),
        slug: newProdSlug.trim() || undefined,
        description: newProdDesc.trim() || undefined,
        business_unit: newProdBu.trim() || undefined,
      });

      // Reset form and close modal
      setNewProdName('');
      setNewProdSlug('');
      setNewProdDesc('');
      setNewProdBu('');
      setIsModalOpen(false);

      // Refresh products list
      await fetchProducts();
    } catch (err: any) {
      setCreateError(err?.response?.data?.detail || 'Impossibile creare il prodotto.');
    } finally {
      setCreateSubmitting(false);
    }
  };

  const handleComponentSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!compSearchQuery.trim()) return;

    try {
      setCompSearchLoading(true);
      setCompSearchPerformed(true);
      const res = await apiService.searchCatalogComponents(
        compSearchQuery.trim(),
        compSearchVersion.trim() || undefined
      );
      setCompSearchResults(res.matches);
    } catch (err: any) {
      console.error('Component search error:', err);
      setCompSearchResults([]);
    } finally {
      setCompSearchLoading(false);
    }
  };

  // Derive unique business units
  const businessUnits = Array.from(
    new Set(products.map((p) => p.business_unit).filter((bu): bu is string => Boolean(bu)))
  );

  // Filtered products
  const filteredProducts = products.filter((p) => {
    const matchesSearch =
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.slug.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (p.description && p.description.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesBu = selectedBu === 'all' || p.business_unit === selectedBu;
    return matchesSearch && matchesBu;
  });

  // Calculate Aggregated Metrics
  const totalReleases = products.reduce((acc, p) => acc + (p.release_count || 0), 0);
  const compliantProducts = products.filter((p) => p.latest_verdict === 'PASS').length;
  const warningProducts = products.filter((p) => p.latest_verdict === 'WARNING').length;

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
            In attesa di Release
          </span>
        );
    }
  };

  const getLifecycleBadge = (status?: LifecycleStatus | null) => {
    switch (status) {
      case 'RELEASED':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-100 text-blue-800 border border-blue-200">
            RELEASED
          </span>
        );
      case 'VALIDATED':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
            VALIDATED
          </span>
        );
      case 'DRAFT':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-100 text-slate-700 border border-slate-300">
            DRAFT
          </span>
        );
      case 'EOL':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-gray-200 text-gray-700 border border-gray-300">
            END-OF-LIFE
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-3xl">📦</span>
            <h1 className="text-2xl font-black text-slate-900 tracking-tight">
              Regulatory Product &amp; Release Asset Catalog
            </h1>
          </div>
          <p className="text-sm text-slate-600 mt-1 max-w-3xl">
            Censimento gerarchico dei prodotti software aziendali per la conformità al CRA (Art. 13) ed ENISA 2026.
            Organizza i rilasci versionati su 4 livelli architetturali (OS, Container, Application, Firmware) con audit automatico degli SBOM.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {canMutate ? (
            <button
              onClick={() => setIsModalOpen(true)}
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-primary-600 hover:bg-primary-700 text-white font-semibold text-sm rounded-lg shadow-sm transition-all focus:ring-2 focus:ring-primary-500"
            >
              <span className="text-lg leading-none">+</span> Nuovo Prodotto
            </button>
          ) : (
            <span
              title="Azione disabilitata per il ruolo Auditor (sola lettura)"
              className="inline-flex items-center gap-2 px-4 py-2 bg-slate-100 text-slate-400 font-semibold text-xs rounded-lg border border-slate-200 cursor-not-allowed"
            >
              🔒 Sola Lettura (Auditor)
            </span>
          )}
        </div>
      </div>

      {/* Aggregated KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-wider text-slate-500">Prodotti a Catalogo</p>
            <p className="text-2xl font-black text-slate-900 mt-1">{products.length}</p>
            <p className="text-[11px] text-slate-400 mt-0.5">Asset registrati</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-primary-50 text-primary-600 flex items-center justify-center text-xl font-bold">
            🏢
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-wider text-slate-500">Rilasci Mappati</p>
            <p className="text-2xl font-black text-slate-900 mt-1">{totalReleases}</p>
            <p className="text-[11px] text-slate-400 mt-0.5">Versioni complessive</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center text-xl font-bold">
            🏷️
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-wider text-slate-500">Prodotti Conformance PASS</p>
            <p className="text-2xl font-black text-emerald-600 mt-1">{compliantProducts}</p>
            <p className="text-[11px] text-slate-400 mt-0.5">Ultimo rilascio conforme</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center text-xl font-bold">
            ✓
          </div>
        </div>

        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-wider text-slate-500">Avvisi Terze Parti</p>
            <p className="text-2xl font-black text-amber-600 mt-1">{warningProducts}</p>
            <p className="text-[11px] text-slate-400 mt-0.5">Avvisi non bloccanti</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center text-xl font-bold">
            !
          </div>
        </div>
      </div>

      {/* View Tabs: Products Catalog vs Global Component Search */}
      <div className="flex border-b border-slate-200">
        <button
          onClick={() => setActiveTab('catalog')}
          className={`pb-3 px-4 text-sm font-bold border-b-2 transition-colors ${
            activeTab === 'catalog'
              ? 'border-primary-600 text-primary-700'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          📂 Catalogo Prodotti ({products.length})
        </button>
        <button
          onClick={() => setActiveTab('component_search')}
          className={`pb-3 px-4 text-sm font-bold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'component_search'
              ? 'border-primary-600 text-primary-700'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          🔍 Ricerca Globale Componenti &amp; Librerie
          {compSearchResults.length > 0 && (
            <span className="px-1.5 py-0.5 text-[10px] bg-primary-100 text-primary-800 rounded-full">
              {compSearchResults.length}
            </span>
          )}
        </button>
      </div>

      {/* TAB 1: PRODUCT CATALOG */}
      {activeTab === 'catalog' && (
        <div className="space-y-6">
          {/* Search & Filters */}
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex flex-col sm:flex-row gap-4 items-center justify-between">
            <div className="relative w-full sm:w-96">
              <input
                type="text"
                placeholder="Filtra per nome o slug prodotto..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-4 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
              <span className="absolute left-3 top-2.5 text-slate-400 text-sm">🔍</span>
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-600 text-sm"
                >
                  ✕
                </button>
              )}
            </div>

            <div className="flex items-center gap-3 w-full sm:w-auto">
              <label className="text-xs font-semibold text-slate-600 whitespace-nowrap">
                Business Unit:
              </label>
              <select
                value={selectedBu}
                onChange={(e) => setSelectedBu(e.target.value)}
                className="w-full sm:w-auto px-3 py-2 border border-slate-300 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <option value="all">Tutte le Divisioni</option>
                {businessUnits.map((bu) => (
                  <option key={bu} value={bu}>
                    {bu}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Loading & Error States */}
          {loading && (
            <div className="text-center py-12 bg-white rounded-xl border border-slate-200">
              <div className="inline-block animate-spin text-3xl">⏳</div>
              <p className="mt-2 text-sm text-slate-600 font-medium">Caricamento catalogo in corso...</p>
            </div>
          )}

          {error && (
            <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl text-rose-800 text-sm flex items-center justify-between">
              <span>⚠️ {error}</span>
              <button onClick={fetchProducts} className="font-bold underline hover:text-rose-900">
                Riprova
              </button>
            </div>
          )}

          {/* Products Grid */}
          {!loading && !error && filteredProducts.length === 0 && (
            <div className="text-center py-16 bg-white rounded-xl border border-slate-200 shadow-sm">
              <span className="text-4xl">📦</span>
              <h3 className="text-lg font-bold text-slate-800 mt-2">Nessun prodotto trovato</h3>
              <p className="text-sm text-slate-500 max-w-md mx-auto mt-1">
                {searchTerm || selectedBu !== 'all'
                  ? 'Nessun prodotto corrisponde ai criteri di ricerca selezionati.'
                  : 'Il catalogo è attualmente vuoto. Registra il primo prodotto software per iniziare il tracciamento gerarchico.'}
              </p>
              <button
                onClick={() => setIsModalOpen(true)}
                className="mt-4 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white font-semibold text-sm rounded-lg shadow-sm"
              >
                + Registra Primo Prodotto
              </button>
            </div>
          )}

          {!loading && !error && filteredProducts.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredProducts.map((prod) => (
                <div
                  key={prod.id}
                  className="bg-white rounded-xl border border-slate-200 shadow-sm hover:shadow-md transition-shadow flex flex-col justify-between overflow-hidden"
                >
                  <div className="p-5">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <h3 className="text-base font-bold text-slate-900 leading-snug">
                          {prod.name}
                        </h3>
                        <p className="font-mono text-xs text-slate-400 mt-0.5">/{prod.slug}</p>
                      </div>
                      {prod.business_unit && (
                        <span className="px-2 py-0.5 bg-slate-100 text-slate-700 border border-slate-200 rounded text-[11px] font-semibold whitespace-nowrap">
                          {prod.business_unit}
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-slate-600 mt-3 line-clamp-2 leading-relaxed">
                      {prod.description || 'Nessuna descrizione specificata.'}
                    </p>

                    <div className="mt-4 pt-4 border-t border-slate-100 grid grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                          Rilasci Attivi
                        </span>
                        <span className="font-bold text-slate-800">
                          {prod.release_count} {prod.release_count === 1 ? 'versione' : 'versioni'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">
                          Ultimo Rilascio
                        </span>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          <span className="font-mono font-bold text-slate-800">
                            {prod.latest_release || 'N/D'}
                          </span>
                          {getLifecycleBadge(prod.latest_status)}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="px-5 py-3.5 bg-slate-50 border-t border-slate-100 flex items-center justify-between">
                    <div>{getVerdictBadge(prod.latest_verdict)}</div>
                    <Link
                      to={`/catalog/${prod.slug}`}
                      className="inline-flex items-center gap-1 text-xs font-bold text-primary-700 hover:text-primary-900"
                    >
                      Dettaglio Rilasci &rarr;
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: GLOBAL COMPONENT SEARCH */}
      {activeTab === 'component_search' && (
        <div className="space-y-6">
          <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
            <h2 className="text-base font-bold text-slate-900">
              Ricerca Trasversale Librerie &amp; Componenti
            </h2>
            <p className="text-xs text-slate-500 mt-1 max-w-2xl">
              Cerca in tutti gli SBOM censiti a catalogo (tutti i prodotti, tutte le versioni e tutti i livelli OS, Container, Application, Firmware) dove è presente una determinata dipendenza software.
            </p>

            <form onSubmit={handleComponentSearch} className="mt-4 flex flex-col sm:flex-row gap-3">
              <div className="flex-1">
                <input
                  type="text"
                  placeholder="Nome libreria (es. openssl, log4j-core, axios, jinja2)..."
                  value={compSearchQuery}
                  onChange={(e) => setCompSearchQuery(e.target.value)}
                  className="w-full px-4 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
              <div className="w-full sm:w-48">
                <input
                  type="text"
                  placeholder="Versione (opzionale)"
                  value={compSearchVersion}
                  onChange={(e) => setCompSearchVersion(e.target.value)}
                  className="w-full px-4 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
              <button
                type="submit"
                disabled={compSearchLoading || !compSearchQuery.trim()}
                className="px-5 py-2 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 text-white font-semibold text-sm rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                {compSearchLoading ? (
                  <>
                    <span className="animate-spin">⏳</span> Ricerca...
                  </>
                ) : (
                  <>
                    <span>🔍</span> Cerca nel Catalogo
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Search Results Display */}
          {compSearchPerformed && (
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
              <div className="p-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
                <div className="text-xs font-bold text-slate-700">
                  Risultati per: <span className="font-mono text-primary-700">"{compSearchQuery}"</span>
                  {compSearchVersion && <span> (versione: <span className="font-mono">{compSearchVersion}</span>)</span>}
                </div>
                <span className="px-2.5 py-0.5 bg-slate-200 text-slate-800 rounded-full text-xs font-bold">
                  {compSearchResults.length} occorrenze individuate
                </span>
              </div>

              {compSearchResults.length === 0 ? (
                <div className="p-12 text-center text-slate-500 text-sm">
                  Nessun componente corrispondente trovato negli SBOM analizzati del catalogo.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-slate-200 text-xs text-left">
                    <thead className="bg-slate-50 text-slate-500 font-bold uppercase tracking-wider text-[10px]">
                      <tr>
                        <th className="px-4 py-3">Componente / Versione</th>
                        <th className="px-4 py-3">Prodotto</th>
                        <th className="px-4 py-3">Rilascio</th>
                        <th className="px-4 py-3">Livello Sistema (Tier)</th>
                        <th className="px-4 py-3">Licenza</th>
                        <th className="px-4 py-3">Fornitore</th>
                        <th className="px-4 py-3 text-right">Dossier / Matrice</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-sans">
                      {compSearchResults.map((match, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                          <td className="px-4 py-3">
                            <div className="font-bold text-slate-900">{match.component.name}</div>
                            <div className="font-mono text-[11px] text-slate-500">
                              v{match.component.version || 'N/D'}
                            </div>
                            {match.component.purl && (
                              <div className="font-mono text-[10px] text-slate-400 truncate max-w-xs" title={match.component.purl}>
                                {match.component.purl}
                              </div>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <Link
                              to={`/catalog/${match.product_slug}`}
                              className="font-bold text-primary-700 hover:underline"
                            >
                              {match.product_name}
                            </Link>
                            {match.business_unit && (
                              <span className="block text-[10px] text-slate-400">{match.business_unit}</span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <span className="font-mono font-bold text-slate-800">{match.release_version}</span>
                            <div className="mt-0.5">{getLifecycleBadge(match.release_status)}</div>
                          </td>
                          <td className="px-4 py-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                              {match.tier}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span className="font-mono text-[11px] text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded">
                              {match.component.license || 'N/D'}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-slate-600 truncate max-w-[150px]">
                            {match.component.supplier || 'N/D'}
                          </td>
                          <td className="px-4 py-3 text-right">
                            {match.validation_report_id ? (
                              <Link
                                to={`/reports/${match.validation_report_id}`}
                                className="inline-flex items-center gap-1 px-2.5 py-1 bg-slate-100 hover:bg-slate-200 text-slate-800 font-bold rounded text-[11px] transition-colors"
                              >
                                Apri Matrice 8 Colonne &rarr;
                              </Link>
                            ) : (
                              <span className="text-slate-400 text-[11px]">Nessun report</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* CREATE PRODUCT MODAL */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full shadow-2xl border border-slate-200 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
              <h3 className="text-base font-bold text-slate-900">Registra Nuovo Prodotto Software</h3>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 text-xl font-bold leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateProduct} className="p-6 space-y-4">
              {createError && (
                <div className="p-3 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded-lg">
                  {createError}
                </div>
              )}

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1">
                  Nome Prodotto *
                </label>
                <input
                  type="text"
                  required
                  placeholder="es. ReguBOM Gateway Appliance"
                  value={newProdName}
                  onChange={(e) => setNewProdName(e.target.value)}
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1">
                  Slug Identificativo (Opzionale)
                </label>
                <input
                  type="text"
                  placeholder="es. regubom-gateway (generato automaticamente se vuoto)"
                  value={newProdSlug}
                  onChange={(e) => setNewProdSlug(e.target.value)}
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-primary-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1">
                  Business Unit / Divisione
                </label>
                <input
                  type="text"
                  placeholder="es. Enterprise Cyber Defense, Cloud Platform..."
                  value={newProdBu}
                  onChange={(e) => setNewProdBu(e.target.value)}
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-700 mb-1">
                  Descrizione Architetturale
                </label>
                <textarea
                  rows={3}
                  placeholder="Descrizione sintetica del prodotto, perimetro e target normativo CRA..."
                  value={newProdDesc}
                  onChange={(e) => setNewProdDesc(e.target.value)}
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 focus:outline-none"
                />
              </div>

              <div className="pt-3 border-t border-slate-200 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 border border-slate-300 rounded-lg text-xs font-bold text-slate-700 hover:bg-slate-100"
                >
                  Annulla
                </button>
                <button
                  type="submit"
                  disabled={createSubmitting}
                  className="px-5 py-2 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 text-white rounded-lg text-xs font-bold shadow-sm"
                >
                  {createSubmitting ? 'Salvataggio...' : 'Crea Prodotto'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default CatalogPage;
