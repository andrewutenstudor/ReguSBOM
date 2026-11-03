import React, { useState, useEffect, useMemo } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import { SbomViewerData, ComponentViewerItem } from '../types';

export const SbomViewerPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [data, setData] = useState<SbomViewerData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [activeFilter, setActiveFilter] = useState<'all' | 'core' | 'third_party' | 'issues' | 'no_hash' | 'no_supplier' | 'no_version' | 'non_spdx' | 'complete'>('all');
  const [specificFieldFilter, setSpecificFieldFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'name_asc' | 'name_desc' | 'score_asc' | 'score_desc' | 'version'>('score_asc');
  
  // Pagination states
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(50);

  // Selected component for inspection drawer / modal
  const [selectedComponent, setSelectedComponent] = useState<ComponentViewerItem | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const fetchViewerData = async () => {
      setLoading(true);
      setError(null);
      try {
        const numericId = parseInt(id, 10);
        // Try sbom viewer endpoint first; fallback to report viewer if needed
        try {
          const res = await apiService.getSbomViewerData(numericId);
          setData(res);
        } catch {
          const res = await apiService.getReportViewerData(numericId);
          setData(res);
        }
      } catch (err: any) {
        console.error('Failed to load SBOM viewer data:', err);
        setError(err.response?.data?.detail || err.message || 'Errore durante il caricamento dei dati SBOM.');
      } finally {
        setLoading(false);
      }
    };

    fetchViewerData();
  }, [id]);

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, activeFilter, specificFieldFilter, sortBy, pageSize]);

  const copyToClipboard = (text: string, label: string) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopiedText(label);
      setTimeout(() => setCopiedText(null), 2000);
    }
  };

  // Filter counts
  const rawComponents = data?.components || [];
  const countAll = rawComponents.length;
  const countCore = rawComponents.filter((c) => c.is_core).length;
  const countThirdParty = rawComponents.filter((c) => !c.is_core).length;
  const countIssues = rawComponents.filter(
    (c) =>
      c.has_version === false || c.has_version_symbol === '✕' || c.has_version_symbol === 'X' || !c.version || c.version === 'vN/D' || c.version === '—' ||
      c.has_id === '✕' || c.has_id === 'X' || c.has_id_symbol === '✕' || c.has_id_symbol === 'X' || !c.has_id ||
      c.has_supplier === '✕' || c.has_supplier === 'X' || c.has_supplier_symbol === '✕' || c.has_supplier_symbol === 'X' ||
      c.has_hash === '✕' || c.has_hash === 'X' || c.has_hash_symbol === '✕' || c.has_hash_symbol === 'X' ||
      c.has_dependencies === '✕' || c.has_dependencies === 'X' || c.has_dependencies_symbol === '✕' ||
      (c.has_license !== '✓' && c.has_license_symbol !== '✓')
  ).length;
  const countNoHash = rawComponents.filter(
    (c) => c.has_hash === '✕' || c.has_hash === 'X' || c.has_hash_symbol === '✕' || c.has_hash_symbol === 'X' || !c.has_hashes
  ).length;
  const countNoSupplier = rawComponents.filter(
    (c) => c.has_supplier === '✕' || c.has_supplier === 'X' || c.has_supplier_symbol === '✕' || c.has_supplier_symbol === 'X'
  ).length;
  const countNoVersion = rawComponents.filter(
    (c) => c.has_version === false || c.has_version_symbol === '✕' || c.has_version_symbol === 'X' || !c.version || c.version === 'vN/D' || c.version === '—'
  ).length;
  const countNonSpdx = rawComponents.filter((c) => c.has_license === '!' || c.has_license_symbol === '!').length;

  // Filtered and sorted components
  const filteredComponents = useMemo(() => {
    if (!data?.components) return [];

    let list = data.components;

    // 1. Status Filter
    if (activeFilter === 'core') {
      list = list.filter((c) => c.is_core);
    } else if (activeFilter === 'third_party') {
      list = list.filter((c) => !c.is_core);
    } else if (activeFilter === 'issues') {
      list = list.filter(
        (c) =>
          c.has_version === false || c.has_version_symbol === '✕' || c.has_version_symbol === 'X' || !c.version || c.version === 'vN/D' || c.version === '—' ||
          c.has_id === '✕' || c.has_id === 'X' || c.has_id_symbol === '✕' || c.has_id_symbol === 'X' || !c.has_id ||
          c.has_supplier === '✕' || c.has_supplier === 'X' || c.has_supplier_symbol === '✕' || c.has_supplier_symbol === 'X' ||
          c.has_hash === '✕' || c.has_hash === 'X' || c.has_hash_symbol === '✕' || c.has_hash_symbol === 'X' ||
          c.has_dependencies === '✕' || c.has_dependencies === 'X' || c.has_dependencies_symbol === '✕' ||
          (c.has_license !== '✓' && c.has_license_symbol !== '✓')
      );
    } else if (activeFilter === 'no_hash') {
      list = list.filter(
        (c) => c.has_hash === '✕' || c.has_hash === 'X' || c.has_hash_symbol === '✕' || c.has_hash_symbol === 'X' || !c.has_hashes
      );
    } else if (activeFilter === 'no_supplier') {
      list = list.filter(
        (c) => c.has_supplier === '✕' || c.has_supplier === 'X' || c.has_supplier_symbol === '✕' || c.has_supplier_symbol === 'X'
      );
    } else if (activeFilter === 'no_version') {
      list = list.filter(
        (c) => c.has_version === false || c.has_version_symbol === '✕' || c.has_version_symbol === 'X' || !c.version || c.version === 'vN/D' || c.version === '—'
      );
    } else if (activeFilter === 'non_spdx') {
      list = list.filter((c) => c.has_license === '!' || c.has_license_symbol === '!');
    } else if (activeFilter === 'complete') {
      list = list.filter(
        (c) =>
          (c.has_id === '✓' || c.has_id_symbol === '✓') &&
          (c.has_supplier === '✓' || c.has_supplier_symbol === '✓') &&
          (c.has_hash === '✓' || c.has_hash_symbol === '✓') &&
          (c.has_license === '✓' || c.has_license_symbol === '✓')
      );
    }

    // 2. Specific Field Filter
    if (specificFieldFilter !== 'all') {
      if (specificFieldFilter === 'supplier') {
        list = list.filter((c) => c.has_supplier === '✕' || c.has_supplier === 'X' || c.has_supplier_symbol === '✕' || c.missing_desirable.includes('supplier'));
      } else if (specificFieldFilter === 'hashes') {
        list = list.filter((c) => c.has_hash === '✕' || c.has_hash === 'X' || c.has_hash_symbol === '✕' || c.missing_desirable.includes('hashes'));
      } else if (specificFieldFilter === 'licenses') {
        list = list.filter((c) => (c.has_license !== '✓' && c.has_license_symbol !== '✓') || c.missing_desirable.includes('licenses'));
      } else if (specificFieldFilter === 'purl' || specificFieldFilter === 'cpe') {
        list = list.filter((c) => c.has_id === '✕' || c.has_id === 'X' || c.has_id_symbol === '✕' || c.missing_desirable.includes(specificFieldFilter));
      } else {
        list = list.filter((c) => c.missing_desirable.includes(specificFieldFilter));
      }
    }

    // 3. Search Query
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      list = list.filter((c) => {
        return (
          c.name.toLowerCase().includes(q) ||
          c.version.toLowerCase().includes(q) ||
          (c.supplier && c.supplier.toLowerCase().includes(q)) ||
          (c.purl && c.purl.toLowerCase().includes(q)) ||
          (c.bom_ref && c.bom_ref.toLowerCase().includes(q)) ||
          (c.licenses && c.licenses.some((lic) => lic.toLowerCase().includes(q)))
        );
      });
    }

    // 4. Sorting
    const sorted = [...list];
    sorted.sort((a, b) => {
      if (sortBy === 'name_asc') {
        return a.name.localeCompare(b.name);
      }
      if (sortBy === 'name_desc') {
        return b.name.localeCompare(a.name);
      }
      if (sortBy === 'score_asc') {
        return a.completeness_score - b.completeness_score;
      }
      if (sortBy === 'score_desc') {
        return b.completeness_score - a.completeness_score;
      }
      if (sortBy === 'version') {
        return a.version.localeCompare(b.version);
      }
      return 0;
    });

    return sorted;
  }, [data, activeFilter, specificFieldFilter, searchQuery, sortBy]);

  // Pagination calculation
  const totalItems = filteredComponents.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const safeCurrentPage = Math.min(currentPage, totalPages);

  const paginatedComponents = useMemo(() => {
    const startIndex = (safeCurrentPage - 1) * pageSize;
    return filteredComponents.slice(startIndex, startIndex + pageSize);
  }, [filteredComponents, safeCurrentPage, pageSize]);

  // Export filtered data as JSON
  const handleExportJson = () => {
    if (!filteredComponents.length) return;
    const jsonStr = JSON.stringify(filteredComponents, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sbom_${id}_components_gap_analysis.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Export filtered data as CSV
  const handleExportCsv = () => {
    if (!filteredComponents.length) return;
    const headers = ['Name', 'Version', 'Type', 'Scope', 'Supplier', 'Licenses', 'Hashes Count', 'PURL', 'CPE', 'Completeness Score (%)', 'Missing Desirable Fields'];
    const rows = filteredComponents.map((c) => [
      `"${c.name.replace(/"/g, '""')}"`,
      `"${c.version.replace(/"/g, '""')}"`,
      `"${c.type}"`,
      c.is_core ? 'Core' : 'Third-Party',
      `"${(c.supplier || '').replace(/"/g, '""')}"`,
      `"${(c.licenses || []).join(', ').replace(/"/g, '""')}"`,
      c.hashes_count,
      `"${(c.purl || '').replace(/"/g, '""')}"`,
      `"${(c.cpe || '').replace(/"/g, '""')}"`,
      c.completeness_score,
      `"${c.missing_desirable.join(', ')}"`,
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sbom_${id}_components_gap_analysis.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="min-h-[60vh] flex flex-col items-center justify-center p-8">
        <div className="w-16 h-16 border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin"></div>
        <h3 className="mt-6 text-xl font-semibold text-gray-800">Analisi Componenti &amp; Metadati in corso...</h3>
        <p className="mt-2 text-sm text-gray-500 max-w-md text-center">
          Analisi ad alte prestazioni della distinta base software (SBOM), scansione dei gap per fornitori, licenze, hash e PURL.
        </p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="max-w-3xl mx-auto my-12 p-8 bg-red-50 border border-red-200 rounded-2xl shadow-sm">
        <div className="flex items-center gap-3 text-red-700 mb-4">
          <span className="text-3xl">⚠️</span>
          <h2 className="text-xl font-bold">Impossibile aprire SBOM Viewer</h2>
        </div>
        <p className="text-gray-700 mb-6">{error || 'Dati SBOM non trovati o formato non valido.'}</p>
        <div className="flex gap-4">
          <button onClick={() => navigate(-1)} className="btn-secondary">
            Torna Indietro
          </button>
          <Link to="/reports" className="btn-primary">
            Elenco Report
          </Link>
        </div>
      </div>
    );
  }

  const { root_metadata, statistics } = data;
  const isHealthyCompleteness = statistics.completeness_percentage >= 80;
  const isModerateCompleteness = statistics.completeness_percentage >= 50 && statistics.completeness_percentage < 80;

  return (
    <div className="space-y-8 pb-20">
      {/* Top Header & Breadcrumbs */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-gray-200 pb-5">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate(-1)}
            className="inline-flex items-center text-sm font-semibold text-gray-600 hover:text-indigo-600 transition-colors"
          >
            <span className="mr-1.5 text-lg">←</span> Indietro
          </button>
          <span className="text-gray-300">|</span>
          <div className="flex items-center gap-2">
            <span className="text-2xl">🔍</span>
            <div>
              <h1 className="text-2xl font-extrabold text-gray-900 tracking-tight">
                Interactive SBOM Viewer &amp; Gap Analyzer
              </h1>
              <p className="text-xs text-gray-500 font-medium">
                {data.filename} • ID #{data.sbom_id} • Formato: {root_metadata.bom_format} {root_metadata.spec_version}
              </p>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={handleExportJson}
            className="inline-flex items-center gap-1.5 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 font-semibold py-2 px-3.5 rounded-lg text-xs shadow-sm transition-colors"
            title="Esporta i componenti filtrati in formato JSON"
          >
            <span>📥</span> Esporta JSON ({filteredComponents.length})
          </button>
          <button
            onClick={handleExportCsv}
            className="inline-flex items-center gap-1.5 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 font-semibold py-2 px-3.5 rounded-lg text-xs shadow-sm transition-colors"
            title="Esporta i componenti filtrati in formato CSV"
          >
            <span>📊</span> Esporta CSV
          </button>
          <Link
            to={`/reports/${id}`}
            className="inline-flex items-center gap-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 font-semibold py-2 px-3.5 rounded-lg text-xs shadow-sm transition-colors"
          >
            <span>📋</span> Report di Validazione
          </Link>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 1. ROOT SBOM METADATA CARDS                                               */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Product Card */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded">
              Prodotto Principale (Root)
            </span>
            <span className="text-xs text-gray-400 font-mono">
              {root_metadata.root_product.type || 'application'}
            </span>
          </div>
          <div>
            <h3 className="text-lg font-bold text-gray-900 truncate" title={root_metadata.root_product.name}>
              {root_metadata.root_product.name || 'Nome non specificato'}
            </h3>
            <p className="text-sm text-gray-600 font-medium">
              Versione: <span className="font-semibold text-gray-900">{root_metadata.root_product.version || '—'}</span>
            </p>
          </div>
          <div className="text-xs text-gray-500 space-y-1 pt-2 border-t border-gray-100">
            <div>
              <span className="text-gray-400">Fornitore / Produttore:</span>{' '}
              <span className="font-medium text-gray-700">{root_metadata.root_product.supplier || '—'}</span>
            </div>
            {root_metadata.root_product.purl && (
              <div className="truncate" title={root_metadata.root_product.purl}>
                <span className="text-gray-400">PURL:</span>{' '}
                <span className="font-mono text-gray-700">{root_metadata.root_product.purl}</span>
              </div>
            )}
          </div>
        </div>

        {/* SBOM Spec Card */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded">
              Specifiche Distinta Base
            </span>
            <span className="text-xs text-gray-400">v{root_metadata.document_version || 1}</span>
          </div>
          <div className="space-y-1.5 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-500">Formato / Spec:</span>
              <span className="font-semibold text-gray-900">
                {root_metadata.bom_format} {root_metadata.spec_version}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Data Generazione:</span>
              <span className="font-medium text-gray-800">
                {root_metadata.timestamp ? new Date(root_metadata.timestamp).toLocaleString('it-IT') : '—'}
              </span>
            </div>
            <div className="flex justify-between items-center text-xs pt-1">
              <span className="text-gray-500">Numero di Serie:</span>
              <span className="font-mono text-gray-600 truncate max-w-[180px]" title={root_metadata.serial_number}>
                {root_metadata.serial_number || '—'}
              </span>
            </div>
          </div>
        </div>

        {/* Tools & Authors Card */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-amber-600 bg-amber-50 px-2 py-0.5 rounded">
              Strumenti &amp; Autori
            </span>
            <span className="text-xs text-gray-400">Generazione</span>
          </div>
          <div className="space-y-2 text-xs">
            <div>
              <span className="text-gray-500 block mb-1">Strumenti SBOM (Tools):</span>
              {root_metadata.tools && root_metadata.tools.length > 0 ? (
                <div className="flex flex-wrap gap-1">
                  {root_metadata.tools.map((t: string, idx: number) => (
                    <span key={idx} className="bg-gray-100 text-gray-700 px-2 py-0.5 rounded font-mono">
                      {t}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="text-gray-400 italic">Nessun tool registrato</span>
              )}
            </div>
            <div className="pt-1">
              <span className="text-gray-500 block mb-1">Autori / Contatti:</span>
              {root_metadata.authors && root_metadata.authors.length > 0 ? (
                <div className="flex flex-wrap gap-1">
                  {root_metadata.authors.map((a: string, idx: number) => (
                    <span key={idx} className="bg-gray-100 text-gray-700 px-2 py-0.5 rounded font-mono">
                      {a}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="text-gray-400 italic">Nessun autore specificato</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 2. GAP ANALYSIS & DESIRABLE METADATA DASHBOARD                            */}
      {/* ========================================================================= */}
      <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6 space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-100 pb-5">
          <div>
            <h2 className="text-lg font-bold text-gray-900 flex items-center gap-2">
              <span>📊</span> Analisi Completezza &amp; Gap Metadati Desiderabili
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">
              Conformità con le raccomandazioni CRA e NIS2: presenza di fornitore, licenze SPDX, hash crittografici, identificativi PURL/CPE.
            </p>
          </div>
          
          {/* Completeness Badge */}
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="text-2xl font-black text-gray-900">
                {statistics.completeness_percentage}%
              </div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                Completezza Globale
              </div>
            </div>
            <div className="w-24 bg-gray-200 rounded-full h-3 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  isHealthyCompleteness
                    ? 'bg-emerald-500'
                    : isModerateCompleteness
                    ? 'bg-amber-500'
                    : 'bg-rose-500'
                }`}
                style={{ width: `${statistics.completeness_percentage}%` }}
              />
            </div>
          </div>
        </div>

        {/* Top Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-gray-50 rounded-xl p-4 border border-gray-100">
            <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Componenti Totali</div>
            <div className="text-2xl font-black text-gray-900 mt-1">{statistics.total_components.toLocaleString()}</div>
            <div className="text-[11px] text-gray-400 mt-1">
              {statistics.core_components_count} Core • {statistics.third_party_components_count} Terze Parti
            </div>
          </div>

          <div
            onClick={() => {
              setActiveFilter('complete');
              setSpecificFieldFilter('all');
            }}
            className="bg-emerald-50/70 hover:bg-emerald-100/70 cursor-pointer rounded-xl p-4 border border-emerald-200 transition-colors"
          >
            <div className="text-xs font-semibold text-emerald-800 uppercase tracking-wide flex items-center justify-between">
              <span>✅ Completi</span>
              <span className="text-[10px] bg-emerald-200 text-emerald-800 px-1.5 py-0.5 rounded font-bold">100% OK</span>
            </div>
            <div className="text-2xl font-black text-emerald-900 mt-1">
              {statistics.complete_components.toLocaleString()}
            </div>
            <div className="text-[11px] text-emerald-700 mt-1">
              {((statistics.complete_components / Math.max(1, statistics.total_components)) * 100).toFixed(1)}% con tutti i metadati
            </div>
          </div>

          <div
            onClick={() => {
              setActiveFilter('issues');
              setSpecificFieldFilter('all');
            }}
            className="bg-amber-50/70 hover:bg-amber-100/70 cursor-pointer rounded-xl p-4 border border-amber-200 transition-colors"
          >
            <div className="text-xs font-semibold text-amber-800 uppercase tracking-wide flex items-center justify-between">
              <span>⚠️ Con Lacune (Gaps)</span>
              <span className="text-[10px] bg-amber-200 text-amber-800 px-1.5 py-0.5 rounded font-bold">Incompleti</span>
            </div>
            <div className="text-2xl font-black text-amber-900 mt-1">
              {statistics.incomplete_components.toLocaleString()}
            </div>
            <div className="text-[11px] text-amber-700 mt-1">
              Mancano uno o più metadati
            </div>
          </div>

          <div
            onClick={() => {
              setActiveFilter('core');
              setSpecificFieldFilter('all');
            }}
            className="bg-indigo-50/70 hover:bg-indigo-100/70 cursor-pointer rounded-xl p-4 border border-indigo-200 transition-colors"
          >
            <div className="text-xs font-semibold text-indigo-800 uppercase tracking-wide flex items-center justify-between">
              <span>🏢 Componenti Core</span>
              <span className="text-[10px] bg-indigo-200 text-indigo-800 px-1.5 py-0.5 rounded font-bold">Proprietari</span>
            </div>
            <div className="text-2xl font-black text-indigo-900 mt-1">
              {statistics.core_components_count.toLocaleString()}
            </div>
            <div className="text-[11px] text-indigo-700 mt-1">
              Sottoposti a policy stretta
            </div>
          </div>
        </div>

        {/* Desirable Fields Gap Breakdown Cards (Clickable) */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-bold uppercase tracking-wider text-gray-500">
              Dettaglio Campi Desiderabili (Clicca per filtrare i componenti mancanti):
            </span>
            {specificFieldFilter !== 'all' && (
              <button
                onClick={() => setSpecificFieldFilter('all')}
                className="text-xs text-indigo-600 hover:text-indigo-800 font-semibold"
              >
                Rimuovi filtro ({specificFieldFilter}) ✕
              </button>
            )}
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
            {statistics.desirable_fields.map((field: string) => {
              const gapCount = statistics.field_gap_counts[field] || 0;
              const coveragePct = statistics.field_coverage_percentages[field] || 0;
              const label = statistics.field_labels[field] || field;
              const isSelected = specificFieldFilter === field;

              return (
                <button
                  key={field}
                  type="button"
                  onClick={() => {
                    if (isSelected) {
                      setSpecificFieldFilter('all');
                    } else {
                      setSpecificFieldFilter(field);
                      setActiveFilter('all');
                    }
                  }}
                  className={`text-left p-3 rounded-xl border transition-all ${
                    isSelected
                      ? 'border-indigo-600 bg-indigo-50/80 ring-2 ring-indigo-500 shadow-sm'
                      : gapCount > 0
                      ? 'border-gray-200 bg-white hover:border-amber-300 hover:bg-amber-50/40'
                      : 'border-gray-200 bg-white hover:border-emerald-300 hover:bg-emerald-50/30'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-gray-800 capitalize truncate" title={label}>
                      {label}
                    </span>
                    {gapCount === 0 ? (
                      <span className="text-[10px] text-emerald-600 font-bold">100%</span>
                    ) : (
                      <span className="text-[10px] text-amber-600 font-bold">{coveragePct}%</span>
                    )}
                  </div>
                  <div className="mt-2 flex items-baseline justify-between">
                    <span className={`text-lg font-black ${gapCount > 0 ? 'text-amber-700' : 'text-emerald-700'}`}>
                      {gapCount.toLocaleString()}
                    </span>
                    <span className="text-[10px] text-gray-400">mancanti</span>
                  </div>
                  {/* Mini progress bar */}
                  <div className="w-full bg-gray-100 rounded-full h-1.5 mt-2 overflow-hidden">
                    <div
                      className={`h-full ${gapCount === 0 ? 'bg-emerald-500' : coveragePct >= 80 ? 'bg-amber-500' : 'bg-rose-500'}`}
                      style={{ width: `${coveragePct}%` }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 2b. CHECKLIST SECTION ("COSA MANCA PER LA CONFORMITÀ AL CRA")             */}
      {/* ========================================================================= */}
      {data.cra_checklist && data.cra_checklist.length > 0 && (
        <section className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-100 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl">📋</span>
                <h3 className="text-lg font-bold text-gray-900 tracking-tight">
                  COSA MANCA PER LA CONFORMITÀ AL CRA
                </h3>
              </div>
              <p className="text-xs text-gray-500 mt-0.5">
                Verifica dei requisiti essenziali definiti nella Tabella 4.1.1 delle Linee Guida SBOM e Regolamento UE Cyber Resilience Act.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {data.cra_checklist.map((item, idx) => {
              const isWarning = item.status === 'WARNING';
              const isPass = item.passed && !isWarning;
              return (
                <div
                  key={item.id || idx}
                  className={`rounded-xl p-3.5 border transition-colors flex items-start gap-3 ${
                    isPass
                      ? 'bg-emerald-50/40 border-emerald-200 text-gray-900'
                      : isWarning
                      ? 'bg-amber-50/40 border-amber-200 text-gray-900'
                      : 'bg-rose-50/40 border-rose-200 text-gray-900'
                  }`}
                >
                  <div className="mt-0.5 flex-shrink-0">
                    {isPass ? (
                      <span className="w-5 h-5 rounded-full bg-emerald-600 text-white flex items-center justify-center text-xs font-bold shadow-xs">
                        ✓
                      </span>
                    ) : isWarning ? (
                      <span className="w-5 h-5 rounded-full bg-amber-500 text-white flex items-center justify-center text-xs font-bold shadow-xs">
                        !
                      </span>
                    ) : (
                      <span className="w-5 h-5 rounded-full bg-rose-600 text-white flex items-center justify-center text-xs font-bold shadow-xs">
                        ✕
                      </span>
                    )}
                  </div>

                  <div className="space-y-0.5 flex-1 min-w-0">
                    <div className="flex items-baseline justify-between gap-2">
                      <h4 className="text-xs font-bold text-gray-900 leading-snug">
                        {item.title || item.name}
                      </h4>
                      <span
                        className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded-full flex-shrink-0 ${
                          isPass
                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                            : isWarning
                            ? 'bg-amber-100 text-amber-800 border border-amber-200'
                            : 'bg-rose-100 text-rose-800 border border-rose-200'
                        }`}
                      >
                        {isPass ? '✓ Conforme' : isWarning ? '! Avviso' : '✕ Non Conforme'}
                      </span>
                    </div>

                    <p
                      className={`text-[11px] font-medium leading-relaxed ${
                        isPass ? 'text-emerald-800' : isWarning ? 'text-amber-800' : 'text-rose-700'
                      }`}
                    >
                      {item.missing_count > 0 && item.total_count > 0
                        ? `manca in ${item.missing_count.toLocaleString()} componenti su ${item.total_count.toLocaleString()}`
                        : item.detail || item.details}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* ========================================================================= */}
      {/* 3. INTERACTIVE SEARCH & FILTER CONTROLS                                    */}
      {/* ========================================================================= */}
      <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-5 space-y-4">
        {/* Quick Filter Tabs & Search Bar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Quick Filters */}
          <div className="flex flex-wrap items-center gap-2">
            {[
              { id: 'all', label: `Tutti (${countAll})` },
              { id: 'core', label: `Solo Core (${countCore})` },
              { id: 'third_party', label: `Terze Parti (${countThirdParty})` },
              { id: 'issues', label: `Con mancanze (${countIssues})` },
              { id: 'no_hash', label: `Senza Hash (${countNoHash})` },
              { id: 'no_supplier', label: `Senza Fornitore (${countNoSupplier})` },
              { id: 'non_spdx', label: `Licenze non-SPDX (${countNonSpdx})` },
            ].map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => {
                  setActiveFilter(f.id as any);
                  setSpecificFieldFilter('all');
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  activeFilter === f.id && specificFieldFilter === 'all'
                    ? 'bg-gray-900 text-white shadow-sm'
                    : 'bg-white text-gray-700 hover:bg-gray-100 border border-gray-300'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Search Box */}
          <div className="relative min-w-[280px]">
            <input
              type="text"
              placeholder="Cerca nome, versione, fornitore, PURL..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full text-xs bg-gray-50 border border-gray-300 rounded-lg pl-9 pr-8 py-2 focus:ring-2 focus:ring-indigo-500 focus:bg-white focus:outline-none transition-all"
            />
            <span className="absolute left-3 top-2.5 text-gray-400 text-xs">🔍</span>
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-2 text-gray-400 hover:text-gray-600 text-xs"
              >
                ✕
              </button>
            )}
          </div>
        </div>

        {/* Secondary controls: Sort, Page Size, Status Summary */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-gray-100 text-xs text-gray-500">
          <div className="flex items-center gap-2">
            <span>Mostrati <strong>{totalItems.toLocaleString()}</strong> su {statistics.total_components.toLocaleString()} componenti</span>
            {specificFieldFilter !== 'all' && (
              <span className="bg-amber-100 text-amber-800 px-2 py-0.5 rounded font-medium">
                Filtro campo attivo: <strong>{statistics.field_labels[specificFieldFilter] || specificFieldFilter} mancante</strong>
              </span>
            )}
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <label htmlFor="sortBySelect" className="text-gray-600">Ordina:</label>
              <select
                id="sortBySelect"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="bg-white border border-gray-300 rounded-md px-2 py-1 text-xs focus:ring-1 focus:ring-indigo-500"
              >
                <option value="score_asc">Completezza: Più incompleti prima</option>
                <option value="score_desc">Completezza: Più completi prima</option>
                <option value="name_asc">Nome (A - Z)</option>
                <option value="name_desc">Nome (Z - A)</option>
                <option value="version">Versione</option>
              </select>
            </div>

            <div className="flex items-center gap-1.5">
              <label htmlFor="pageSizeSelect" className="text-gray-600">Per pagina:</label>
              <select
                id="pageSizeSelect"
                value={pageSize}
                onChange={(e) => setPageSize(parseInt(e.target.value, 10))}
                className="bg-white border border-gray-300 rounded-md px-2 py-1 text-xs focus:ring-1 focus:ring-indigo-500"
              >
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
                <option value="250">250</option>
                <option value="1000">1000</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 4. MATRIX SECTION ("MATRICE DI COMPLETEZZA PER COMPONENTE")               */}
      {/* ========================================================================= */}
      <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="p-4 border-b border-gray-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xl">🧱</span>
            <h3 className="text-base font-bold text-gray-900 tracking-tight">
              MATRICE DI COMPLETEZZA PER COMPONENTE
            </h3>
          </div>
          <div className="flex items-center gap-2 text-xs font-medium">
            <span className="inline-flex items-center gap-1 text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded-md border border-emerald-200">
              <strong className="text-sm">✓</strong> Conforme
            </span>
            <span className="inline-flex items-center gap-1 text-amber-700 bg-amber-50 px-2.5 py-1 rounded-md border border-amber-200">
              <strong className="text-sm">!</strong> Non-SPDX
            </span>
            <span className="inline-flex items-center gap-1 text-rose-700 bg-rose-50 px-2.5 py-1 rounded-md border border-rose-200">
              <strong className="text-sm">✕</strong> Assente
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-gray-700">
            <thead className="bg-gray-100 text-gray-700 border-b border-gray-200 font-semibold uppercase tracking-wider text-[11px]">
              <tr>
                <th scope="col" className="px-4 py-3.5">Componente</th>
                <th scope="col" className="px-4 py-3.5 w-32">Versione</th>
                <th scope="col" className="px-4 py-3.5 text-center w-24">Core</th>
                <th scope="col" className="px-4 py-3.5 text-center w-28">Identificativo</th>
                <th scope="col" className="px-4 py-3.5 text-center w-28">Fornitore</th>
                <th scope="col" className="px-4 py-3.5 text-center w-24">Hash</th>
                <th scope="col" className="px-4 py-3.5 text-center w-32">Licenza</th>
                <th scope="col" className="px-4 py-3.5 text-center w-28" title="Verifica se il componente è mappato nel grafo delle dipendenze o se risulta orfano">
                  Relazioni
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {paginatedComponents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-16 text-center text-gray-500">
                    <span className="text-4xl block mb-2">{activeFilter === 'core' && countCore === 0 ? '🧱' : '🔍'}</span>
                    <p className="font-semibold text-gray-700">
                      {activeFilter === 'core' && countCore === 0
                        ? 'Nessun elemento classificato come core: tutti i componenti sono gestiti come terze parti.'
                        : 'Nessun componente corrisponde ai criteri di filtro.'}
                    </p>
                    <p className="text-xs text-gray-400 mt-1">
                      {activeFilter === 'core' && countCore === 0
                        ? 'Tutti gli elementi rilevati nell\'SBOM sono classificati come dipendenze o librerie esterne.'
                        : 'Prova a reimpostare i filtri di ricerca o selezionare "Tutti i Componenti".'}
                    </p>
                    <button
                      onClick={() => {
                        setSearchQuery('');
                        setActiveFilter('all');
                        setSpecificFieldFilter('all');
                      }}
                      className="mt-4 px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 rounded-lg font-semibold text-xs transition-colors"
                    >
                      Reimposta Filtri
                    </button>
                  </td>
                </tr>
              ) : (
                paginatedComponents.map((c, idx) => (
                  <tr
                    key={c.bom_ref || c.index || idx}
                    onClick={() => setSelectedComponent(c)}
                    className={`hover:bg-indigo-50/40 transition-colors cursor-pointer ${
                      c.is_core ? 'bg-indigo-50/15' : idx % 2 === 1 ? 'bg-gray-50/50' : 'bg-white'
                    }`}
                  >
                    {/* Componente */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-gray-900 text-sm truncate max-w-[280px]" title={c.name}>
                          {c.name}
                        </span>
                        {c.is_core && (
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-extrabold bg-blue-100 text-blue-800 border border-blue-200">
                            CORE
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 text-[11px] text-gray-400 mt-0.5">
                        <span className="bg-gray-100 px-1.5 py-0.2 rounded text-gray-600 font-mono text-[10px]">
                          {c.type || 'library'}
                        </span>
                        {c.bom_ref && (
                          <span className="truncate max-w-[160px] font-mono" title={c.bom_ref}>
                            ref: {c.bom_ref}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Versione */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[11px] font-mono text-gray-700 bg-gray-100 px-1.5 py-0.5 rounded">
                          {c.version && !c.version.startsWith('v') ? `v${c.version}` : c.version || 'vN/D'}
                        </span>
                        {(c.has_version_symbol === '✓' || (c.has_version && c.version && c.version !== 'vN/D' && c.version !== '—')) ? (
                          <span className="text-emerald-600 font-bold text-xs" title="Versione Presente">✓</span>
                        ) : (
                          <span className="text-rose-600 font-bold text-xs" title="Versione Assente o N/D">✕</span>
                        )}
                      </div>
                    </td>

                    {/* Core */}
                    <td className="px-4 py-3 text-center">
                      {c.is_core ? (
                        <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-100 text-blue-800 border border-blue-200">
                          Core
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-gray-100 text-gray-600">
                          Terze Parti
                        </span>
                      )}
                    </td>

                    {/* Identificativo */}
                    <td className="px-4 py-3 text-center">
                      {(c.has_id === '✓' || c.has_id_symbol === '✓') ? (
                        <span className="text-emerald-600 font-bold text-base" title="Identificativo PURL/CPE Presente">
                          ✓
                        </span>
                      ) : (
                        <span className="text-rose-600 font-bold text-base" title="Identificativo PURL/CPE Assente">
                          ✕
                        </span>
                      )}
                    </td>

                    {/* Fornitore */}
                    <td className="px-4 py-3 text-center">
                      {(c.has_supplier === '✓' || c.has_supplier_symbol === '✓') ? (
                        <span className="text-emerald-600 font-bold text-base" title={`Fornitore Presente: ${c.supplier || 'OK'}`}>
                          ✓
                        </span>
                      ) : (
                        <span className="text-rose-600 font-bold text-base" title="Fornitore Assente">
                          ✕
                        </span>
                      )}
                    </td>

                    {/* Hash */}
                    <td className="px-4 py-3 text-center">
                      {(c.has_hash === '✓' || c.has_hash_symbol === '✓') ? (
                        <span className="text-emerald-600 font-bold text-base" title={`Hash SHA-256/512 Presente (${c.hashes_count || 1} validi)`}>
                          ✓
                        </span>
                      ) : (
                        <span className="text-rose-600 font-bold text-base" title="Hash SHA-256/512 Assente">
                          ✕
                        </span>
                      )}
                    </td>

                    {/* Licenza */}
                    <td className="px-4 py-3 text-center">
                      {(c.has_license === '✓' || c.has_license_symbol === '✓') ? (
                        <span className="text-emerald-600 font-bold text-base" title={`Licenza SPDX Valida: ${c.licenses?.join(', ') || 'OK'}`}>
                          ✓
                        </span>
                      ) : (c.has_license === '!' || c.has_license_symbol === '!') ? (
                        <span
                          className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-600 border border-amber-300"
                          title={`Licenza presente ma non-SPDX standard: ${c.licenses?.join(', ') || ''}`}
                        >
                          ! Non-SPDX
                        </span>
                      ) : (
                        <span className="text-rose-600 font-bold text-base" title="Licenza Assente">
                          ✕
                        </span>
                      )}
                    </td>

                    {/* Relazioni tra i componenti */}
                    <td className="px-4 py-3 text-center">
                      {(c.has_dependencies === '✓' || c.has_dependencies_symbol === '✓') ? (
                        <span
                          className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200 whitespace-nowrap"
                          title="Tracciata nel grafo delle dipendenze"
                        >
                          ✓ Tracciata
                        </span>
                      ) : (
                        <span
                          className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-100 text-rose-800 border border-rose-200 whitespace-nowrap"
                          title="Orfano (non presente nel grafo dipendenze)"
                        >
                          ✕ Orfano
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="px-6 py-4 bg-gray-50 border-t border-gray-200 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-gray-600">
          <div>
            Mostrati da <strong>{totalItems === 0 ? 0 : (safeCurrentPage - 1) * pageSize + 1}</strong> a{' '}
            <strong>{Math.min(safeCurrentPage * pageSize, totalItems)}</strong> di{' '}
            <strong>{totalItems.toLocaleString()}</strong> componenti
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={() => setCurrentPage(1)}
              disabled={safeCurrentPage <= 1}
              className="px-2.5 py-1 rounded border border-gray-300 bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed font-medium"
            >
              « Prima
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={safeCurrentPage <= 1}
              className="px-2.5 py-1 rounded border border-gray-300 bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed font-medium"
            >
              ‹ Prec
            </button>

            <span className="px-3 py-1 font-semibold text-gray-800">
              Pagina {safeCurrentPage} di {totalPages}
            </span>

            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={safeCurrentPage >= totalPages}
              className="px-2.5 py-1 rounded border border-gray-300 bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed font-medium"
            >
              Succ ›
            </button>
            <button
              onClick={() => setCurrentPage(totalPages)}
              disabled={safeCurrentPage >= totalPages}
              className="px-2.5 py-1 rounded border border-gray-300 bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed font-medium"
            >
              Ultima »
            </button>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 5. COMPONENT INSPECTION MODAL / DRAWER                                    */}
      {/* ========================================================================= */}
      {selectedComponent && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/50 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-2xl w-full border border-gray-200 overflow-hidden transform transition-all animate-fadeIn">
            {/* Modal Header */}
            <div className="bg-gradient-to-r from-gray-900 to-indigo-950 text-white p-6 flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono uppercase bg-indigo-500/30 text-indigo-200 px-2 py-0.5 rounded">
                    {selectedComponent.type || 'library'}
                  </span>
                  {selectedComponent.is_core ? (
                    <span className="text-xs font-bold bg-amber-400 text-gray-950 px-2 py-0.5 rounded">
                      CORE COMPONENT
                    </span>
                  ) : (
                    <span className="text-xs font-mono text-gray-300">Third-Party Component</span>
                  )}
                </div>
                <h3 className="text-xl font-bold truncate max-w-lg">{selectedComponent.name}</h3>
                <p className="text-sm text-gray-300 font-mono mt-0.5">Versione: {selectedComponent.version || '—'}</p>
              </div>
              <button
                onClick={() => setSelectedComponent(null)}
                className="text-gray-400 hover:text-white text-2xl font-bold leading-none p-1"
              >
                ✕
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto text-xs text-gray-700">
              {/* Completeness Summary Banner */}
              <div
                className={`p-4 rounded-xl border flex items-center justify-between ${
                  selectedComponent.missing_desirable.length === 0
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                    : 'bg-amber-50 border-amber-200 text-amber-900'
                }`}
              >
                <div>
                  <div className="font-bold text-sm">
                    {selectedComponent.missing_desirable.length === 0
                      ? '✅ Metadati Desiderabili Completi (100%)'
                      : `⚠️ Rilevati ${selectedComponent.missing_desirable.length} Campi Mancanti`}
                  </div>
                  <div className="text-xs mt-0.5 opacity-90">
                    Punteggio: {selectedComponent.completeness_score}% conformità ai metadati desiderabili.
                  </div>
                </div>
                <div className="flex flex-wrap gap-1 max-w-[220px] justify-end">
                  {selectedComponent.missing_desirable.map((gap: string) => (
                    <span key={gap} className="bg-amber-200 text-amber-900 font-bold px-2 py-0.5 rounded text-[10px]">
                      {gap}
                    </span>
                  ))}
                </div>
              </div>

              {/* Grid of properties */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1 bg-gray-50 p-3 rounded-lg border border-gray-100">
                  <span className="font-bold text-gray-500 uppercase tracking-wider text-[10px]">Fornitore (Supplier)</span>
                  <p className="font-medium text-gray-900">{selectedComponent.supplier || 'Non specificato'}</p>
                </div>

                <div className="space-y-1 bg-gray-50 p-3 rounded-lg border border-gray-100">
                  <span className="font-bold text-gray-500 uppercase tracking-wider text-[10px]">BOM Reference</span>
                  <p className="font-mono text-gray-900 truncate" title={selectedComponent.bom_ref}>
                    {selectedComponent.bom_ref || 'Non presente'}
                  </p>
                </div>

                <div className="space-y-1 bg-gray-50 p-3 rounded-lg border border-gray-100 sm:col-span-2">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-gray-500 uppercase tracking-wider text-[10px]">Package URL (PURL)</span>
                    {selectedComponent.purl && (
                      <button
                        onClick={() => copyToClipboard(selectedComponent.purl!, 'PURL')}
                        className="text-indigo-600 hover:text-indigo-800 text-[10px] font-semibold"
                      >
                        {copiedText === 'PURL' ? 'Copiato! ✓' : 'Copia PURL'}
                      </button>
                    )}
                  </div>
                  <p className="font-mono text-gray-900 break-all">{selectedComponent.purl || 'Non specificato'}</p>
                </div>

                {selectedComponent.cpe && (
                  <div className="space-y-1 bg-gray-50 p-3 rounded-lg border border-gray-100 sm:col-span-2">
                    <span className="font-bold text-gray-500 uppercase tracking-wider text-[10px]">CPE Identifier</span>
                    <p className="font-mono text-gray-900 break-all">{selectedComponent.cpe}</p>
                  </div>
                )}

                <div className="space-y-1 bg-gray-50 p-3 rounded-lg border border-gray-100 sm:col-span-2">
                  <span className="font-bold text-gray-500 uppercase tracking-wider text-[10px]">Licenze Identificate</span>
                  {selectedComponent.licenses && selectedComponent.licenses.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {selectedComponent.licenses.map((lic, idx) => (
                        <span key={idx} className="bg-blue-100 text-blue-800 font-mono px-2 py-0.5 rounded font-semibold text-xs">
                          {lic}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-amber-700 italic">Nessuna licenza dichiarata.</p>
                  )}
                </div>

                <div className="space-y-1 bg-gray-50 p-3 rounded-lg border border-gray-100 sm:col-span-2">
                  <span className="font-bold text-gray-500 uppercase tracking-wider text-[10px]">Hash Crittografici</span>
                  <p className="text-gray-800">
                    {selectedComponent.hashes_count > 0 ? (
                      <span className="text-emerald-700 font-semibold">{selectedComponent.hashes_count} hash crittografici associati</span>
                    ) : (
                      <span className="text-amber-700 italic">Nessun hash presente per questo componente</span>
                    )}
                  </p>
                </div>

                {selectedComponent.description && (
                  <div className="space-y-1 bg-gray-50 p-3 rounded-lg border border-gray-100 sm:col-span-2">
                    <span className="font-bold text-gray-500 uppercase tracking-wider text-[10px]">Descrizione</span>
                    <p className="text-gray-700 text-xs">{selectedComponent.description}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="bg-gray-50 p-4 border-t border-gray-200 flex justify-end">
              <button
                onClick={() => setSelectedComponent(null)}
                className="btn-primary text-xs py-2 px-5"
              >
                Chiudi
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SbomViewerPage;
