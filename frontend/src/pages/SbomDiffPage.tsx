import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import apiService from '../services/api';
import { DiffCandidate, DiffResult } from '../types';

const SbomDiffPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [candidates, setCandidates] = useState<DiffCandidate[]>([]);
  const [loadingCandidates, setLoadingCandidates] = useState<boolean>(true);

  // Selected base and target IDs
  const [baseId, setBaseId] = useState<string>(searchParams.get('base') || '');
  const [targetId, setTargetId] = useState<string>(searchParams.get('target') || '');

  // Diff calculation state
  const [diffResult, setDiffResult] = useState<DiffResult | null>(null);
  const [calculating, setCalculating] = useState<boolean>(false);
  const [diffError, setDiffError] = useState<string | null>(null);

  // Table filtering
  const [activeFilter, setActiveFilter] = useState<'all' | 'added' | 'removed' | 'modified' | 'license_drift' | 'hash_drop'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    fetchCandidates();
  }, []);

  const fetchCandidates = async () => {
    try {
      setLoadingCandidates(true);
      const data = await apiService.getDiffCandidates();
      setCandidates(data);

      // Pre-select if query params exist or default to first two
      const qBase = searchParams.get('base');
      const qTarget = searchParams.get('target');

      if (qBase && qTarget) {
        setBaseId(qBase);
        setTargetId(qTarget);
        executeDiff(parseInt(qBase, 10), parseInt(qTarget, 10));
      } else if (data.length >= 2) {
        setBaseId(String(data[1].id));
        setTargetId(String(data[0].id));
      } else if (data.length === 1) {
        setBaseId(String(data[0].id));
        setTargetId(String(data[0].id));
      }
    } catch (err) {
      console.error('Error loading candidates:', err);
    } finally {
      setLoadingCandidates(false);
    }
  };

  const executeDiff = async (bId: number, tId: number) => {
    if (!bId || !tId) return;
    try {
      setCalculating(true);
      setDiffError(null);
      const res = await apiService.getSbomDiff(bId, tId);
      setDiffResult(res);
      setSearchParams({ base: String(bId), target: String(tId) });
    } catch (err: any) {
      setDiffError(err?.response?.data?.detail || 'Errore nel calcolo del differenziale tra gli SBOM selezionati.');
      setDiffResult(null);
    } finally {
      setCalculating(false);
    }
  };

  const handleCompareSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!baseId || !targetId) return;
    executeDiff(parseInt(baseId, 10), parseInt(targetId, 10));
  };

  const handleSwap = () => {
    const temp = baseId;
    setBaseId(targetId);
    setTargetId(temp);
    if (temp && targetId) {
      executeDiff(parseInt(targetId, 10), parseInt(temp, 10));
    }
  };

  // Group candidates for cleaner dropdown presentation
  const catalogArtifacts = candidates.filter((c) => c.type === 'artifact');
  const historicalReports = candidates.filter((c) => c.type !== 'artifact');

  // Filter diff items
  const summary = diffResult?.summary;

  const allItems: Array<{
    type: 'ADDED' | 'REMOVED' | 'MODIFIED';
    name: string;
    item: any;
  }> = [];

  if (diffResult) {
    diffResult.added_components.forEach((c) => allItems.push({ type: 'ADDED', name: c.name, item: c }));
    diffResult.removed_components.forEach((c) => allItems.push({ type: 'REMOVED', name: c.name, item: c }));
    diffResult.modified_components.forEach((c) => allItems.push({ type: 'MODIFIED', name: c.name, item: c }));
  }

  const filteredItems = allItems.filter(({ type, name, item }) => {
    // 1. Text Search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      const matchName = name.toLowerCase().includes(q);
      const matchPurl =
        (item.purl && item.purl.toLowerCase().includes(q)) ||
        (item.target?.purl && item.target.purl.toLowerCase().includes(q));
      if (!matchName && !matchPurl) return false;
    }

    // 2. Tab Filter
    if (activeFilter === 'all') return true;
    if (activeFilter === 'added') return type === 'ADDED';
    if (activeFilter === 'removed') return type === 'REMOVED';
    if (activeFilter === 'modified') return type === 'MODIFIED';
    if (activeFilter === 'license_drift') {
      return type === 'MODIFIED' && item.drift?.license_changed;
    }
    if (activeFilter === 'hash_drop') {
      return type === 'MODIFIED' && item.drift?.hash_dropped;
    }
    return true;
  });

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-200 pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-3xl">⚖️</span>
            <h1 className="text-2xl font-black text-slate-900 tracking-tight">
              SBOM Differential &amp; Architectural Drift Engine
            </h1>
          </div>
          <p className="text-sm text-slate-600 mt-1 max-w-3xl">
            Confronto semantico bidirezionale tra versioni di rilascio o singoli tier SBOM.
            Rileva l'aggiunta o rimozione di librerie, mutazioni di licenza, variazioni di fornitori, regressioni crittografiche (hash drops) e delta del grafo delle dipendenze.
          </p>
        </div>

        <Link
          to="/catalog"
          className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-bold transition-colors self-start md:self-auto"
        >
          <span>📂</span> Vai al Catalogo Asset
        </Link>
      </div>

      {/* Dual Selector Panel */}
      <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
        <form onSubmit={handleCompareSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-11 gap-4 items-center">
            {/* Base Selector (A) */}
            <div className="md:col-span-5 space-y-1.5">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center justify-between">
                <span>Rilascio Base (Versione A)</span>
                <span className="text-[10px] text-slate-400 font-normal">Punto di partenza</span>
              </label>
              <select
                value={baseId}
                onChange={(e) => setBaseId(e.target.value)}
                disabled={loadingCandidates}
                className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-300 rounded-xl text-xs font-medium text-slate-900 focus:ring-2 focus:ring-primary-500 focus:bg-white"
              >
                <option value="">Seleziona SBOM Base...</option>
                {catalogArtifacts.length > 0 && (
                  <optgroup label="📦 Livelli Architetturali a Catalogo (Prodotti)">
                    {catalogArtifacts.map((c) => (
                      <option key={`a-${c.id}`} value={c.id}>
                        {c.label}
                      </option>
                    ))}
                  </optgroup>
                )}
                {historicalReports.length > 0 && (
                  <optgroup label="📋 Report e Dossier di Convalida">
                    {historicalReports.map((c) => (
                      <option key={`r-${c.id}`} value={c.id}>
                        {c.label}
                      </option>
                    ))}
                  </optgroup>
                )}
              </select>
            </div>

            {/* Swap Button */}
            <div className="md:col-span-1 flex justify-center pt-5">
              <button
                type="button"
                onClick={handleSwap}
                disabled={loadingCandidates || !baseId || !targetId}
                className="w-10 h-10 rounded-full border border-slate-200 bg-slate-50 hover:bg-slate-100 flex items-center justify-center text-slate-600 hover:text-slate-900 shadow-2xs transition-all disabled:opacity-40"
                title="Inverti Base e Target"
              >
                ⇄
              </button>
            </div>

            {/* Target Selector (B) */}
            <div className="md:col-span-5 space-y-1.5">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-600 flex items-center justify-between">
                <span>Rilascio Target (Versione B)</span>
                <span className="text-[10px] text-slate-400 font-normal">Nuovo rilascio</span>
              </label>
              <select
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                disabled={loadingCandidates}
                className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-300 rounded-xl text-xs font-medium text-slate-900 focus:ring-2 focus:ring-primary-500 focus:bg-white"
              >
                <option value="">Seleziona SBOM Target...</option>
                {catalogArtifacts.length > 0 && (
                  <optgroup label="📦 Livelli Architetturali a Catalogo (Prodotti)">
                    {catalogArtifacts.map((c) => (
                      <option key={`a-target-${c.id}`} value={c.id}>
                        {c.label}
                      </option>
                    ))}
                  </optgroup>
                )}
                {historicalReports.length > 0 && (
                  <optgroup label="📋 Report e Dossier di Convalida">
                    {historicalReports.map((c) => (
                      <option key={`r-target-${c.id}`} value={c.id}>
                        {c.label}
                      </option>
                    ))}
                  </optgroup>
                )}
              </select>
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={calculating || !baseId || !targetId}
              className="px-6 py-2.5 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 text-white rounded-xl text-xs font-bold shadow-sm transition-all flex items-center gap-2"
            >
              {calculating ? (
                <>
                  <span className="animate-spin">⏳</span> Calcolo Differenziale in corso...
                </>
              ) : (
                <>
                  <span>🔍</span> Calcola Differenziale &amp; Drift
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {diffError && (
        <div className="p-4 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded-xl flex items-center justify-between">
          <span>⚠️ {diffError}</span>
        </div>
      )}

      {/* KPI Summary Cards */}
      {summary && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Added Card */}
            <div className="bg-white p-5 rounded-xl border border-emerald-200 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-700">
                  Componenti Aggiunti
                </span>
                <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800">
                  +{summary.added_count}
                </span>
              </div>
              <p className="text-3xl font-black text-slate-900 mt-2">+{summary.added_count}</p>
              <p className="text-[11px] text-slate-500 mt-1">Nuove librerie censite nel target</p>
            </div>

            {/* Removed Card */}
            <div className="bg-white p-5 rounded-xl border border-rose-200 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase tracking-wider text-rose-700">
                  Componenti Rimossi
                </span>
                <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800">
                  -{summary.removed_count}
                </span>
              </div>
              <p className="text-3xl font-black text-slate-900 mt-2">-{summary.removed_count}</p>
              <p className="text-[11px] text-slate-500 mt-1">Librerie eliminate rispetto alla base</p>
            </div>

            {/* Modified Card */}
            <div className="bg-white p-5 rounded-xl border border-amber-200 shadow-2xs">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase tracking-wider text-amber-700">
                  Componenti Modificati
                </span>
                <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-800">
                  Δ {summary.modified_count}
                </span>
              </div>
              <p className="text-3xl font-black text-slate-900 mt-2">{summary.modified_count}</p>
              <p className="text-[11px] text-slate-500 mt-1">
                {summary.version_drift_count} versioni, {summary.license_drift_count} licenze
              </p>
            </div>

            {/* Posture Verdict Card */}
            <div
              className={`p-5 rounded-xl border shadow-2xs ${
                summary.posture_verdict === 'IMPROVED'
                  ? 'bg-emerald-50/50 border-emerald-300 text-emerald-900'
                  : summary.posture_verdict === 'DEGRADED'
                  ? 'bg-rose-50/50 border-rose-300 text-rose-900'
                  : 'bg-slate-50 border-slate-200 text-slate-800'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase tracking-wider opacity-75">
                  Postura di Sicurezza
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-black uppercase ${
                    summary.posture_verdict === 'IMPROVED'
                      ? 'bg-emerald-200 text-emerald-900'
                      : summary.posture_verdict === 'DEGRADED'
                      ? 'bg-rose-200 text-rose-900'
                      : 'bg-slate-200 text-slate-700'
                  }`}
                >
                  {summary.posture_verdict}
                </span>
              </div>
              <p className="text-xs font-bold mt-2 leading-snug">{summary.posture_message}</p>
              {summary.hash_drop_count > 0 && (
                <div className="mt-2 text-[10px] font-bold bg-rose-200 text-rose-900 px-2 py-0.5 rounded inline-block">
                  ⚠️ {summary.hash_drop_count} Hash Crittografici Eliminati!
                </div>
              )}
            </div>
          </div>

          {/* Metadata Comparison Banner */}
          <div className="bg-slate-100 p-4 rounded-xl border border-slate-200 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-700 gap-3">
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-500 uppercase text-[10px]">Base (A):</span>
              <span className="font-bold font-mono text-slate-900">{diffResult?.base.label}</span>
              <span className="text-slate-400">({summary.base_total_components} comp.)</span>
            </div>
            <span className="text-slate-400 text-sm hidden sm:inline">&rarr;</span>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-500 uppercase text-[10px]">Target (B):</span>
              <span className="font-bold font-mono text-slate-900">{diffResult?.target.label}</span>
              <span className="text-slate-400">({summary.target_total_components} comp.)</span>
            </div>
            <div className="font-bold text-slate-700 ml-auto sm:ml-0">
              Delta Netto: {summary.net_component_delta >= 0 ? `+${summary.net_component_delta}` : summary.net_component_delta} componenti
            </div>
          </div>

          {/* Filter Bar & Search */}
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex flex-wrap gap-1.5 text-xs font-bold">
              <button
                type="button"
                onClick={() => setActiveFilter('all')}
                className={`px-3 py-1.5 rounded-lg border transition-all ${
                  activeFilter === 'all'
                    ? 'bg-slate-900 text-white border-slate-900'
                    : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                }`}
              >
                Tutte le Variazioni ({allItems.length})
              </button>
              <button
                type="button"
                onClick={() => setActiveFilter('added')}
                className={`px-3 py-1.5 rounded-lg border transition-all ${
                  activeFilter === 'added'
                    ? 'bg-emerald-600 text-white border-emerald-600'
                    : 'bg-white text-emerald-800 border-emerald-200 hover:bg-emerald-50'
                }`}
              >
                + Aggiunti ({summary.added_count})
              </button>
              <button
                type="button"
                onClick={() => setActiveFilter('removed')}
                className={`px-3 py-1.5 rounded-lg border transition-all ${
                  activeFilter === 'removed'
                    ? 'bg-rose-600 text-white border-rose-600'
                    : 'bg-white text-rose-800 border-rose-200 hover:bg-rose-50'
                }`}
              >
                - Rimossi ({summary.removed_count})
              </button>
              <button
                type="button"
                onClick={() => setActiveFilter('modified')}
                className={`px-3 py-1.5 rounded-lg border transition-all ${
                  activeFilter === 'modified'
                    ? 'bg-amber-600 text-white border-amber-600'
                    : 'bg-white text-amber-800 border-amber-200 hover:bg-amber-50'
                }`}
              >
                Δ Modificati ({summary.modified_count})
              </button>
              <button
                type="button"
                onClick={() => setActiveFilter('license_drift')}
                className={`px-3 py-1.5 rounded-lg border transition-all ${
                  activeFilter === 'license_drift'
                    ? 'bg-indigo-600 text-white border-indigo-600'
                    : 'bg-white text-indigo-800 border-indigo-200 hover:bg-indigo-50'
                }`}
              >
                ⚖️ Drift Licenze ({summary.license_drift_count})
              </button>
              {summary.hash_drop_count > 0 && (
                <button
                  type="button"
                  onClick={() => setActiveFilter('hash_drop')}
                  className={`px-3 py-1.5 rounded-lg border transition-all ${
                    activeFilter === 'hash_drop'
                      ? 'bg-rose-700 text-white border-rose-700'
                      : 'bg-white text-rose-700 border-rose-300 hover:bg-rose-50'
                  }`}
                >
                  ⚠️ Allerta Hash Drop ({summary.hash_drop_count})
                </button>
              )}
            </div>

            <div className="relative w-full md:w-72">
              <input
                type="text"
                placeholder="Filtra componente per nome o PURL..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-4 py-1.5 border border-slate-300 rounded-lg text-xs focus:ring-1 focus:ring-primary-500 focus:outline-none"
              />
              <span className="absolute left-2.5 top-2 text-slate-400 text-xs">🔍</span>
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-600 text-xs"
                >
                  ✕
                </button>
              )}
            </div>
          </div>

          {/* Differential Comparison Table */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-xs text-left">
                <thead className="bg-slate-50 text-slate-500 font-bold uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="px-4 py-3">Tipo Drift</th>
                    <th className="px-4 py-3">Libreria / Componente</th>
                    <th className="px-4 py-3">Versione (Base &rarr; Target)</th>
                    <th className="px-4 py-3">Licenza (Base &rarr; Target)</th>
                    <th className="px-4 py-3">Fornitore / Producer</th>
                    <th className="px-4 py-3 text-center">Integrità Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-sans">
                  {filteredItems.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="text-center py-10 text-slate-400">
                        Nessun componente corrisponde al filtro selezionato ({activeFilter}).
                      </td>
                    </tr>
                  ) : (
                    filteredItems.map(({ type, name, item }, idx) => {
                      if (type === 'ADDED') {
                        return (
                          <tr key={idx} className="bg-emerald-50/30 hover:bg-emerald-50/60 transition-colors">
                            <td className="px-4 py-3">
                              <span className="px-2 py-0.5 rounded text-[10px] font-black bg-emerald-100 text-emerald-800 border border-emerald-200">
                                + ADDED
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <span className="font-bold text-slate-900">{name}</span>
                              {item.purl && (
                                <span className="block font-mono text-[10px] text-slate-400 truncate max-w-xs">
                                  {item.purl}
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3 font-mono font-bold text-emerald-700">
                              v{item.version}
                            </td>
                            <td className="px-4 py-3">
                              <span className="px-1.5 py-0.5 bg-slate-100 rounded text-[11px] font-mono">
                                {item.license || 'N/D'}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-slate-600">{item.supplier || 'N/D'}</td>
                            <td className="px-4 py-3 text-center">
                              {item.has_strong_hash ? (
                                <span className="text-emerald-600 font-bold">✓ SHA-256</span>
                              ) : (
                                <span className="text-slate-400">✕ Assente</span>
                              )}
                            </td>
                          </tr>
                        );
                      }

                      if (type === 'REMOVED') {
                        return (
                          <tr key={idx} className="bg-rose-50/30 hover:bg-rose-50/60 transition-colors">
                            <td className="px-4 py-3">
                              <span className="px-2 py-0.5 rounded text-[10px] font-black bg-rose-100 text-rose-800 border border-rose-200">
                                - REMOVED
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <span className="font-bold text-slate-900 line-through opacity-75">{name}</span>
                              {item.purl && (
                                <span className="block font-mono text-[10px] text-slate-400 truncate max-w-xs">
                                  {item.purl}
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3 font-mono text-rose-700 line-through">
                              v{item.version}
                            </td>
                            <td className="px-4 py-3 text-slate-400 line-through">{item.license || 'N/D'}</td>
                            <td className="px-4 py-3 text-slate-400 line-through">{item.supplier || 'N/D'}</td>
                            <td className="px-4 py-3 text-center text-slate-400">—</td>
                          </tr>
                        );
                      }

                      // MODIFIED
                      const drift = item.drift;
                      return (
                        <tr key={idx} className="hover:bg-slate-50 transition-colors">
                          <td className="px-4 py-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-black bg-amber-100 text-amber-900 border border-amber-200">
                              Δ MODIFIED
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span className="font-bold text-slate-900">{name}</span>
                            {item.target.purl && (
                              <span className="block font-mono text-[10px] text-slate-400 truncate max-w-xs">
                                {item.target.purl}
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3 font-mono">
                            {drift.version_changed ? (
                              <div className="flex items-center gap-1.5">
                                <span className="text-slate-400 line-through">{item.base.version}</span>
                                <span>&rarr;</span>
                                <span className="font-bold text-primary-700 bg-primary-50 px-1.5 py-0.5 rounded">
                                  {item.target.version}
                                </span>
                              </div>
                            ) : (
                              <span className="text-slate-700 font-bold">{item.target.version}</span>
                            )}
                          </td>
                          <td className="px-4 py-3 font-mono">
                            {drift.license_changed ? (
                              <div className="flex items-center gap-1.5">
                                <span className="text-slate-400 line-through">{item.base.license || 'N/D'}</span>
                                <span>&rarr;</span>
                                <span className="font-bold text-indigo-700 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-200">
                                  {item.target.license || 'N/D'}
                                </span>
                              </div>
                            ) : (
                              <span className="text-slate-600">{item.target.license || 'N/D'}</span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-slate-600">
                            {drift.supplier_changed ? (
                              <div className="flex items-center gap-1">
                                <span className="text-slate-400 line-through">{item.base.supplier}</span>
                                <span>&rarr;</span>
                                <span className="font-bold text-slate-800">{item.target.supplier}</span>
                              </div>
                            ) : (
                              item.target.supplier || 'N/D'
                            )}
                          </td>
                          <td className="px-4 py-3 text-center">
                            {drift.hash_dropped ? (
                              <span className="px-2 py-0.5 bg-rose-100 text-rose-800 font-black rounded text-[10px] border border-rose-300 animate-pulse">
                                ⚠️ HASH DROPPED!
                              </span>
                            ) : drift.hash_added ? (
                              <span className="px-2 py-0.5 bg-emerald-100 text-emerald-800 font-bold rounded text-[10px]">
                                + Hash Added
                              </span>
                            ) : item.target.has_strong_hash ? (
                              <span className="text-emerald-600 font-bold">✓ Preservato</span>
                            ) : (
                              <span className="text-slate-300">✕ Assente</span>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Dependency Graph Delta Section */}
          <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
            <h3 className="text-sm font-black text-slate-900 tracking-tight flex items-center justify-between">
              <span>🕸️ Variazioni nel Grafo delle Dipendenze (Dependency Graph Delta)</span>
              <span className="text-xs font-normal text-slate-500">
                Archi Base: {diffResult?.dependency_graph_delta.total_base_edges} &rarr; Archi Target: {diffResult?.dependency_graph_delta.total_target_edges}
              </span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
              {/* Added Edges */}
              <div className="p-4 bg-emerald-50/50 rounded-xl border border-emerald-200">
                <span className="text-xs font-bold text-emerald-900 block mb-2">
                  + Nuove Relazioni / Dipendenze Introdotte ({diffResult?.dependency_graph_delta.added_edges.length})
                </span>
                {diffResult?.dependency_graph_delta.added_edges.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">Nessun nuovo arco aggiunto.</p>
                ) : (
                  <div className="max-h-48 overflow-y-auto space-y-1 font-mono text-[11px]">
                    {diffResult?.dependency_graph_delta.added_edges.map((e, idx) => (
                      <div key={idx} className="bg-white p-2 rounded border border-emerald-100 truncate" title={`${e.source} -> ${e.target}`}>
                        <span className="text-slate-700 font-semibold">{e.source}</span>
                        <span className="text-emerald-600 font-bold mx-1.5">&rarr;</span>
                        <span className="text-emerald-800 font-bold">{e.target}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Removed Edges */}
              <div className="p-4 bg-rose-50/50 rounded-xl border border-rose-200">
                <span className="text-xs font-bold text-rose-900 block mb-2">
                  - Relazioni / Dipendenze Rimosse ({diffResult?.dependency_graph_delta.removed_edges.length})
                </span>
                {diffResult?.dependency_graph_delta.removed_edges.length === 0 ? (
                  <p className="text-xs text-slate-400 italic">Nessun arco rimosso.</p>
                ) : (
                  <div className="max-h-48 overflow-y-auto space-y-1 font-mono text-[11px]">
                    {diffResult?.dependency_graph_delta.removed_edges.map((e, idx) => (
                      <div key={idx} className="bg-white p-2 rounded border border-rose-100 truncate" title={`${e.source} -> ${e.target}`}>
                        <span className="text-slate-500 line-through">{e.source}</span>
                        <span className="text-rose-500 font-bold mx-1.5">&rarr;</span>
                        <span className="text-rose-700 line-through">{e.target}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SbomDiffPage;
