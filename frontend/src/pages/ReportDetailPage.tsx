import React, { useState, useEffect, useMemo } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import apiService from '../services/api';
import { useAuth } from '../context/AuthContext';
import {
  ReportDetail,
  CraChecklistItem,
  ComponentMatrixItem,
  FileImprint,
  RootProduct,
} from '../types';

type MatrixFilterType =
  | 'all'
  | 'proprietary'
  | 'third_party'
  | 'incomplete'
  | 'non_spdx'
  | 'missing_hashes'
  | 'orphaned';

export const ReportDetailPage: React.FC = () => {
  const { reportId } = useParams<{ reportId: string }>();
  const navigate = useNavigate();
  const { canMutate } = useAuth();
  const [report, setReport] = useState<ReportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Matrix search, filter, and pagination
  const [matrixSearch, setMatrixSearch] = useState('');
  const [matrixFilter, setMatrixFilter] = useState<MatrixFilterType>('all');
  const [matrixPage, setMatrixPage] = useState(1);
  const [matrixPageSize, setMatrixPageSize] = useState(50);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    if (reportId) {
      loadReport();
    }
  }, [reportId]);

  const loadReport = async () => {
    try {
      setLoading(true);
      const data = await apiService.getReport(parseInt(reportId!, 10));
      setReport(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to load regulatory compliance dossier');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = (format: 'json' | 'html' | 'pdf' | 'certificate') => {
    const url = apiService.downloadReport(parseInt(reportId!, 10), format);
    window.open(url, '_blank');
  };

  const handlePrint = () => {
    window.print();
  };

  const handleDelete = async () => {
    if (!window.confirm('Are you sure you want to delete this regulatory compliance dossier?')) {
      return;
    }
    try {
      await apiService.deleteReport(parseInt(reportId!, 10));
      navigate('/reports');
    } catch (err: any) {
      setError(err.message || 'Failed to delete report');
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopiedHash(label);
      setTimeout(() => setCopiedHash(null), 2000);
    }
  };

  // -------------------------------------------------------------------------
  // Filtering & Search for Component Completeness Matrix
  // -------------------------------------------------------------------------
  const rawMatrix: ComponentMatrixItem[] = report?.report_data?.component_matrix || [];

  const counts = useMemo(() => {
    let prop = 0;
    let tp = 0;
    let incomplete = 0;
    let nonSpdx = 0;
    let missingHash = 0;
    let orphan = 0;

    rawMatrix.forEach((m) => {
      const isProp = m.is_core || m.is_proprietary;
      if (isProp) prop++;
      else tp++;

      const isInc =
        m.has_version === '✕' ||
        m.has_id === '✕' ||
        m.has_supplier === '✕' ||
        m.has_hash === '✕' ||
        m.has_license !== '✓' ||
        m.has_dependencies === '✕';

      if (isInc) incomplete++;
      if (m.has_license === '!') nonSpdx++;
      if (m.has_hash === '✕') missingHash++;
      if (m.has_dependencies === '✕') orphan++;
    });

    return {
      all: rawMatrix.length,
      proprietary: prop,
      third_party: tp,
      incomplete,
      non_spdx: nonSpdx,
      missing_hashes: missingHash,
      orphaned: orphan,
    };
  }, [rawMatrix]);

  const filteredMatrix = useMemo(() => {
    return rawMatrix.filter((item) => {
      // Search
      if (matrixSearch.trim()) {
        const q = matrixSearch.trim().toLowerCase();
        const matchesName = item.name.toLowerCase().includes(q);
        const matchesVer = item.version.toLowerCase().includes(q);
        const matchesLic = (item.license || '').toLowerCase().includes(q);
        const matchesSupp = (item.supplier || '').toLowerCase().includes(q);
        const matchesPurl = (item.purl || '').toLowerCase().includes(q);
        if (!matchesName && !matchesVer && !matchesLic && !matchesSupp && !matchesPurl) {
          return false;
        }
      }

      // Filter
      const isProp = item.is_core || item.is_proprietary;
      if (matrixFilter === 'proprietary') return isProp;
      if (matrixFilter === 'third_party') return !isProp;
      if (matrixFilter === 'incomplete') {
        return (
          item.has_version === '✕' ||
          item.has_id === '✕' ||
          item.has_supplier === '✕' ||
          item.has_hash === '✕' ||
          item.has_license !== '✓' ||
          item.has_dependencies === '✕'
        );
      }
      if (matrixFilter === 'non_spdx') return item.has_license === '!';
      if (matrixFilter === 'missing_hashes') return item.has_hash === '✕';
      if (matrixFilter === 'orphaned') return item.has_dependencies === '✕';

      return true;
    });
  }, [rawMatrix, matrixSearch, matrixFilter]);

  const totalMatrixItems = filteredMatrix.length;
  const totalMatrixPages = Math.max(1, Math.ceil(totalMatrixItems / matrixPageSize));
  const currentSafePage = Math.min(matrixPage, totalMatrixPages);

  const paginatedMatrix = useMemo(() => {
    const start = (currentSafePage - 1) * matrixPageSize;
    return filteredMatrix.slice(start, start + matrixPageSize);
  }, [filteredMatrix, currentSafePage, matrixPageSize]);

  if (loading) {
    return (
      <div className="text-center py-24">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto"></div>
        <p className="mt-4 text-gray-700 font-medium text-base">Loading Regulatory Compliance Dossier...</p>
        <p className="text-sm text-gray-500">Auditing ENISA Advisory 2026, BSI TR-03183-2 &amp; CRA Article 13</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-6 max-w-2xl mx-auto my-12">
        <h2 className="text-lg font-bold text-red-900 flex items-center gap-2">
          <span>❌</span> Regulatory Dossier Error
        </h2>
        <p className="text-red-800 mt-2">{error}</p>
        <button onClick={() => navigate('/reports')} className="mt-4 px-4 py-2 bg-primary-600 text-white rounded-lg text-sm font-medium hover:bg-primary-700">
          Return to Reports Registry
        </button>
      </div>
    );
  }

  if (!report) return null;

  const reportData = report.report_data;
  const statistics = reportData.statistics || ({} as any);

  // File Imprint
  const fileImprint: FileImprint = reportData.file_imprint || {
    sha256: 'N/D',
    sha512: 'N/D',
    file_size_mb: 0,
    file_size_bytes: 0,
  };

  // Document metadata & Root product
  const docMeta = reportData.document_metadata || ({} as any);
  const rootProduct: RootProduct = reportData.root_product || {
    name: reportData.root_product_name || 'N/D',
    version: reportData.root_product_version || 'N/D',
    type: 'application',
    supplier: 'N/D',
  };

  // 12-Point ENISA / BSI Checklist
  const craChecklist: CraChecklistItem[] = reportData.cra_checklist || [];
  const passedCraCount = craChecklist.filter((c) => c.status === 'PASS').length;
  const warningCraCount = craChecklist.filter((c) => c.status === 'WARNING').length;
  const failedCraCount = craChecklist.filter((c) => c.status === 'FAIL').length;
  const totalCraCount = craChecklist.length || 12;

  const statusLabel =
    report.overall_status === 'PASS'
      ? 'CONFORME (PASS)'
      : report.overall_status === 'WARNING'
      ? 'CONFORME CON AVVISI NON BLOCCANTI (WARNING)'
      : 'NON CONFORME (FAIL)';

  return (
    <div className="space-y-8 pb-16">
      {/* ------------------------------------------------------------------- */}
      {/* Top Action & Navigation Bar                                         */}
      {/* ------------------------------------------------------------------- */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-gray-200 pb-4 no-print">
        <Link
          to="/reports"
          className="inline-flex items-center text-sm font-medium text-gray-600 hover:text-primary-700 transition-colors"
        >
          <span className="mr-1.5 text-base">←</span> Return to Compliance Dossiers
        </Link>

        {/* Audit Export Suite */}
        <div className="flex flex-wrap items-center gap-2">
          <Link
            to={`/sboms/${report.sbom_id || report.report_id}/view`}
            className="inline-flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-3.5 rounded-lg text-sm shadow-sm transition-colors"
            title="Interactive Component Explorer"
          >
            <span>🔍</span> SBOM Explorer
          </Link>

          <button
            onClick={() => handleDownload('certificate')}
            className="inline-flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-700 text-white font-medium py-2 px-3.5 rounded-lg text-sm shadow-sm transition-colors"
            title="Download JSON Compliance Certificate conforming to CRA Art. 13"
          >
            <span>📜</span> JSON Certificate
          </button>

          <button
            onClick={handlePrint}
            className="inline-flex items-center gap-1.5 bg-primary-600 hover:bg-primary-700 text-white font-medium py-2 px-3.5 rounded-lg text-sm shadow-sm transition-colors"
            title="Print or export print-ready PDF"
          >
            <span>🖨️</span> Print / PDF
          </button>

          <button
            onClick={() => handleDownload('html')}
            className="inline-flex items-center gap-1.5 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 font-medium py-2 px-3 rounded-lg text-sm shadow-sm transition-colors"
            title="Download Standalone HTML Technical File"
          >
            <span>🌐</span> HTML Dossier
          </button>

          <button
            onClick={() => handleDownload('json')}
            className="inline-flex items-center gap-1.5 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 font-medium py-2 px-3 rounded-lg text-sm shadow-sm transition-colors"
            title="Download Raw JSON Audit"
          >
            <span>📥</span> JSON Full
          </button>

          {canMutate && (
            <button
              onClick={handleDelete}
              className="text-red-600 hover:text-red-700 border border-red-200 hover:bg-red-50 font-medium py-2 px-3 rounded-lg text-sm transition-colors ml-2"
            >
              Delete
            </button>
          )}
        </div>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* Executive Compliance Headline & Status Banner                       */}
      {/* ------------------------------------------------------------------- */}
      <div className="bg-white rounded-2xl shadow-sm border border-gray-200 p-6 sm:p-8">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 bg-primary-50 border border-primary-200 rounded-full text-xs font-semibold text-primary-800 uppercase tracking-wider mb-2">
              <span>🛡️</span> ReguBOM Regulatory Gateway
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-gray-900 tracking-tight">
              Technical Documentation Compliance Dossier (EU CRA Art. 13 &amp; ENISA Advisory 2026)
            </h1>
            <p className="text-sm text-gray-600 mt-1 max-w-3xl">
              Formal audit against the <strong>ENISA Technical Advisory on SBOM (October 2026)</strong>,{' '}
              <strong>BSI TR-03183-2 v2.1.0</strong>, and <strong>CISA 2026 Minimum Elements</strong> for Products with Digital Elements.
            </p>
          </div>

          <div className="text-right">
            <span className="text-xs font-semibold text-gray-400 block uppercase tracking-wider">Audit Date</span>
            <span className="text-sm font-semibold text-gray-700">
              {report.validation_timestamp ? new Date(report.validation_timestamp).toLocaleString() : 'N/D'}
            </span>
            <span className="text-xs text-gray-500 block mt-0.5">
              Processing: {Number(report.processing_time || 0).toFixed(3)}s
            </span>
          </div>
        </div>

        {/* Verdict Banner */}
        <div
          className={`mt-6 p-4 rounded-xl border flex flex-wrap items-center justify-between gap-4 ${
            report.overall_status === 'PASS'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : report.overall_status === 'WARNING'
              ? 'bg-amber-50 border-amber-200 text-amber-900'
              : 'bg-red-50 border-red-200 text-red-900'
          }`}
        >
          <div className="flex items-center gap-3">
            <span className="text-3xl">
              {report.overall_status === 'PASS' ? '✅' : report.overall_status === 'WARNING' ? '⚠️' : '❌'}
            </span>
            <div>
              <div className="text-base font-extrabold tracking-wide">{statusLabel}</div>
              <div className="text-xs opacity-90 font-medium">
                {report.overall_status === 'PASS' &&
                  'All mandatory regulatory criteria for proprietary software and open-source dependencies are fully satisfied.'}
                {report.overall_status === 'WARNING' &&
                  'Proprietary components are compliant. Upstream third-party OSS dependencies exhibit non-blocking metadata omissions.'}
                {report.overall_status === 'FAIL' &&
                  'Critical regulatory omissions detected in proprietary code or baseline document specifications.'}
              </div>
            </div>
          </div>

          <div className="text-right">
            <span className="text-xs font-bold block uppercase tracking-wider opacity-75">Checklist Score</span>
            <span className="text-xl font-extrabold">
              {passedCraCount}/{totalCraCount} Passed
              {warningCraCount > 0 && <span className="text-sm font-semibold ml-1.5 text-amber-700">({warningCraCount} Warn)</span>}
              {failedCraCount > 0 && <span className="text-sm font-semibold ml-1.5 text-red-700">({failedCraCount} Fail)</span>}
            </span>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* 4 Visual Cards: File Imprint, SBOM Type, Format, Components         */}
      {/* ------------------------------------------------------------------- */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: File Imprint */}
        <div className="bg-slate-900 text-white rounded-xl p-5 shadow-sm border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-xs font-semibold text-slate-400 uppercase tracking-wider">
              <span>🔒 Cryptographic Imprint</span>
              <span>{fileImprint.file_size_mb} MB</span>
            </div>
            <div className="mt-3 font-mono text-xs">
              <div className="text-slate-400 text-[10px]">SHA-256 Digest</div>
              <div className="text-emerald-400 font-bold truncate mt-0.5" title={fileImprint.sha256}>
                {fileImprint.sha256}
              </div>
            </div>
            <div className="mt-2 font-mono text-xs">
              <div className="text-slate-400 text-[10px]">SHA-512 Digest</div>
              <div className="text-slate-300 truncate mt-0.5" title={fileImprint.sha512}>
                {fileImprint.sha512}
              </div>
            </div>
          </div>
          <button
            onClick={() => copyToClipboard(fileImprint.sha256, 'sha256')}
            className="mt-3 text-xs text-primary-400 hover:text-primary-300 font-medium text-left flex items-center gap-1.5 transition-colors"
          >
            <span>📋</span> {copiedHash === 'sha256' ? 'SHA-256 Copied!' : 'Copy SHA-256 Imprint'}
          </button>
        </div>

        {/* Card 2: SBOM Type / Lifecycle Phase */}
        <div className="bg-white rounded-xl p-5 shadow-sm border border-gray-200 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-semibold text-gray-500 uppercase tracking-wider">
            <span>🔄 Lifecycle Phase</span>
            <span className="text-primary-600 font-bold">Table 1</span>
          </div>
          <div className="my-3">
            <div className="text-2xl font-extrabold text-gray-900">
              {docMeta.lifecycle_phase || 'Build (Inferred)'}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              Generation Context: {docMeta.has_lifecycle ? 'Explicitly Declared' : 'Standard Pipeline Phase'}
            </div>
          </div>
          <div className="text-xs text-gray-600 font-medium flex items-center gap-1">
            <span>⚙️ Tool:</span>
            <span className="font-semibold truncate" title={docMeta.tools?.[0] || 'Registered Generator'}>
              {docMeta.tools?.[0] || 'Registered Engine'}
            </span>
          </div>
        </div>

        {/* Card 3: Standard & Format */}
        <div className="bg-white rounded-xl p-5 shadow-sm border border-gray-200 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-semibold text-gray-500 uppercase tracking-wider">
            <span>📑 Standard &amp; Spec</span>
            <span className="px-2 py-0.5 bg-blue-50 text-blue-700 rounded text-[10px] font-bold">
              {reportData.format_info?.regulatory_verdict || 'CONFORME'}
            </span>
          </div>
          <div className="my-3">
            <div className="text-2xl font-extrabold text-gray-900">
              {report.format?.toUpperCase()} {report.schema_version}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              Normative Standard: {reportData.format_info?.standard || 'ECMA-424'}
            </div>
          </div>
          <div className="text-xs text-gray-600 font-medium">
            Attestation:{' '}
            <span className={docMeta.has_signature ? 'text-emerald-700 font-bold' : 'text-gray-500'}>
              {docMeta.has_signature ? 'Signed / In-Toto Verified' : 'None Detected (Advisory)'}
            </span>
          </div>
        </div>

        {/* Card 4: Total Components & Bifurcated Breakdown */}
        <div className="bg-white rounded-xl p-5 shadow-sm border border-gray-200 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-semibold text-gray-500 uppercase tracking-wider">
            <span>📦 Component Inventory</span>
            <span className="text-xs font-bold text-gray-700">{counts.all} Total</span>
          </div>
          <div className="my-2 grid grid-cols-2 gap-2 text-center">
            <div className="bg-blue-50 border border-blue-100 rounded-lg p-2">
              <div className="text-lg font-extrabold text-blue-900">{counts.proprietary}</div>
              <div className="text-[10px] uppercase font-bold text-blue-700 tracking-wider">Proprietary</div>
            </div>
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-2">
              <div className="text-lg font-extrabold text-slate-800">{counts.third_party}</div>
              <div className="text-[10px] uppercase font-bold text-slate-600 tracking-wider">Third-Party OSS</div>
            </div>
          </div>
          <div className="text-xs text-gray-500 font-medium flex justify-between">
            <span>Gaps: {counts.incomplete}</span>
            <span>Compliance: {statistics.compliance_rate || 0}%</span>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* 12-Point Regulatory Checklist (ENISA October 2026 / BSI TR-03183-2) */}
      {/* ------------------------------------------------------------------- */}
      <div className="bg-white rounded-2xl shadow-sm border border-gray-200 p-6 sm:p-8">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-lg font-bold text-gray-900 flex items-center gap-2">
              <span>📋</span> 12-Point Regulatory Checklist (ENISA October 2026 &amp; BSI TR-03183-2)
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">
              Complete baseline verification against official EU CRA Article 13 &amp; Annex II technical requirements.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 bg-emerald-100 text-emerald-800 rounded-full text-xs font-bold">
              {passedCraCount} Conforme
            </span>
            {warningCraCount > 0 && (
              <span className="px-2.5 py-1 bg-amber-100 text-amber-800 rounded-full text-xs font-bold">
                {warningCraCount} Avviso
              </span>
            )}
            {failedCraCount > 0 && (
              <span className="px-2.5 py-1 bg-red-100 text-red-800 rounded-full text-xs font-bold">
                {failedCraCount} Non Conforme
              </span>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {craChecklist.map((item) => {
            const isPass = item.status === 'PASS';
            const isWarn = item.status === 'WARNING';
            return (
              <div
                key={item.id}
                className={`p-3.5 rounded-xl border flex items-start gap-3 transition-colors ${
                  isPass
                    ? 'bg-emerald-50/50 border-emerald-200 hover:bg-emerald-50'
                    : isWarn
                    ? 'bg-amber-50/50 border-amber-200 hover:bg-amber-50'
                    : 'bg-red-50/50 border-red-200 hover:bg-red-50'
                }`}
              >
                <div
                  className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-extrabold flex-shrink-0 text-white mt-0.5 ${
                    isPass ? 'bg-emerald-600' : isWarn ? 'bg-amber-600' : 'bg-red-600'
                  }`}
                >
                  {isPass ? '✓' : isWarn ? '!' : '✕'}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-xs font-bold text-gray-900 truncate">{item.title}</div>
                    <span
                      className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded ${
                        isPass
                          ? 'bg-emerald-100 text-emerald-800'
                          : isWarn
                          ? 'bg-amber-100 text-amber-800'
                          : 'bg-red-100 text-red-800'
                      }`}
                    >
                      {isPass ? 'Conforme' : isWarn ? 'Avviso' : 'Non Conforme'}
                    </span>
                  </div>
                  <div className={`text-xs mt-1 leading-snug ${isPass ? 'text-emerald-900' : isWarn ? 'text-amber-900' : 'text-red-900'}`}>
                    {item.detail}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ------------------------------------------------------------------- */}
      {/* Component Completeness Matrix Table (8 Columns & Interactive Filters)*/}
      {/* ------------------------------------------------------------------- */}
      <div className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
        {/* Table Header & Controls */}
        <div className="p-6 sm:p-8 border-b border-gray-200">
          <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
            <div>
              <h2 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                <span>🧩</span> Matrice di Completezza per Componente (Regulatory Inventory Matrix)
              </h2>
              <p className="text-xs text-gray-500 mt-0.5">
                BSI TR-03183-2 v2.1.0 &amp; CISA 2026 item-by-item verification with bifurcated First-Party vs. Third-Party logic.
              </p>
            </div>

            {/* Search Input */}
            <div className="w-full sm:w-72">
              <input
                type="text"
                placeholder="Search component, version, license, PURL..."
                value={matrixSearch}
                onChange={(e) => {
                  setMatrixSearch(e.target.value);
                  setMatrixPage(1);
                }}
                className="w-full px-3.5 py-2 border border-gray-300 rounded-lg text-xs focus:ring-2 focus:ring-primary-500 focus:border-primary-500 shadow-sm"
              />
            </div>
          </div>

          {/* 7 Interactive Filter Tabs */}
          <div className="flex flex-wrap gap-2 text-xs font-semibold">
            {[
              { id: 'all', label: 'All Components', count: counts.all },
              { id: 'proprietary', label: 'Proprietary Only', count: counts.proprietary, color: 'text-blue-700' },
              { id: 'third_party', label: 'Third-Party OSS', count: counts.third_party },
              { id: 'incomplete', label: 'Incomplete / With Gaps', count: counts.incomplete, color: 'text-red-700' },
              { id: 'non_spdx', label: 'Non-SPDX Licenses', count: counts.non_spdx, color: 'text-amber-700' },
              { id: 'missing_hashes', label: 'Missing Hashes', count: counts.missing_hashes, color: 'text-red-700' },
              { id: 'orphaned', label: 'Orphaned (No Relations)', count: counts.orphaned, color: 'text-amber-700' },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => {
                  setMatrixFilter(f.id as MatrixFilterType);
                  setMatrixPage(1);
                }}
                className={`px-3 py-1.5 rounded-lg border transition-all flex items-center gap-1.5 ${
                  matrixFilter === f.id
                    ? 'bg-primary-900 text-white border-primary-900 shadow-sm'
                    : 'bg-gray-50 text-gray-700 border-gray-200 hover:bg-gray-100'
                }`}
              >
                <span>{f.label}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded-full font-bold ${
                    matrixFilter === f.id ? 'bg-white/20 text-white' : 'bg-gray-200 text-gray-800'
                  }`}
                >
                  {f.count}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Matrix Table */}
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 text-left text-xs">
            <thead className="bg-gray-50 text-gray-700 font-bold uppercase tracking-wider text-[10px]">
              <tr>
                <th className="py-3 px-4">Component</th>
                <th className="py-3 px-3">Version</th>
                <th className="py-3 px-3">Type</th>
                <th className="py-3 px-3 text-center">Identifiers (PURL/CPE)</th>
                <th className="py-3 px-3 text-center">Supplier</th>
                <th className="py-3 px-3 text-center">Hash</th>
                <th className="py-3 px-3 text-center">License</th>
                <th className="py-3 px-3 text-center">Relations</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 bg-white">
              {paginatedMatrix.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-gray-500 font-medium">
                    No components found matching current filters and search query.
                  </td>
                </tr>
              ) : (
                paginatedMatrix.map((item, idx) => {
                  const isProp = item.is_core || item.is_proprietary;
                  return (
                    <tr key={`${item.name}-${idx}`} className="hover:bg-gray-50/80 transition-colors">
                      {/* 1. Component Name */}
                      <td className="py-3 px-4 font-semibold text-gray-900">
                        <div className="flex items-center gap-2">
                          <span className="text-gray-400">📦</span>
                          <span className="truncate max-w-xs" title={item.name}>
                            {item.name}
                          </span>
                        </div>
                      </td>

                      {/* 2. Version */}
                      <td className="py-3 px-3">
                        {item.has_version === '✓' ? (
                          <span className="px-2 py-0.5 bg-gray-100 border border-gray-200 rounded text-gray-800 font-mono text-[11px]">
                            {item.version}
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 bg-red-100 border border-red-200 rounded text-red-800 font-bold text-[11px]">
                            ✕ vN/D
                          </span>
                        )}
                      </td>

                      {/* 3. Type (Proprietary / OSS) */}
                      <td className="py-3 px-3">
                        {isProp ? (
                          <span className="px-2 py-0.5 bg-blue-100 border border-blue-200 text-blue-800 font-extrabold rounded text-[10px] tracking-wide">
                            Proprietary
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 bg-slate-100 border border-slate-200 text-slate-700 rounded text-[10px] font-medium">
                            Third-Party OSS
                          </span>
                        )}
                      </td>

                      {/* 4. Identifiers (PURL / CPE) */}
                      <td className="py-3 px-3 text-center">
                        {item.has_id === '✓' ? (
                          <span
                            className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-emerald-100 text-emerald-800 font-extrabold cursor-help"
                            title={item.purl || item.cpe || 'PURL/CPE present'}
                          >
                            ✓
                          </span>
                        ) : (
                          <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-red-100 text-red-800 font-extrabold">
                            ✕
                          </span>
                        )}
                      </td>

                      {/* 5. Supplier */}
                      <td className="py-3 px-3 text-center">
                        {item.has_supplier === '✓' ? (
                          <span
                            className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-emerald-100 text-emerald-800 font-extrabold cursor-help"
                            title={item.supplier || 'Supplier verified'}
                          >
                            ✓
                          </span>
                        ) : (
                          <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-red-100 text-red-800 font-extrabold">
                            ✕
                          </span>
                        )}
                      </td>

                      {/* 6. Hash */}
                      <td className="py-3 px-3 text-center">
                        {item.has_hash === '✓' ? (
                          <span
                            className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-emerald-100 text-emerald-800 font-extrabold cursor-help"
                            title={item.hashes?.join(', ') || 'SHA-256 / SHA-512 digest present'}
                          >
                            ✓
                          </span>
                        ) : (
                          <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-red-100 text-red-800 font-extrabold">
                            ✕
                          </span>
                        )}
                      </td>

                      {/* 7. License */}
                      <td className="py-3 px-3 text-center">
                        {item.has_license === '✓' ? (
                          <span
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 font-semibold text-[10px] cursor-help"
                            title={item.license}
                          >
                            ✓ <span className="max-w-[100px] truncate">{item.license}</span>
                          </span>
                        ) : item.has_license === '!' ? (
                          <span
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-100 text-amber-900 border border-amber-200 font-bold text-[10px] cursor-help"
                            title={`Non-standard license text: ${item.license}`}
                          >
                            ! Non-SPDX
                          </span>
                        ) : (
                          <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-red-100 text-red-800 font-extrabold">
                            ✕
                          </span>
                        )}
                      </td>

                      {/* 8. Relations */}
                      <td className="py-3 px-3 text-center">
                        {item.has_dependencies === '✓' ? (
                          <span
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 text-[10px] font-semibold"
                            title="Mapped in dependency graph"
                          >
                            ✓ Tracciata
                          </span>
                        ) : (
                          <span
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-100 text-amber-800 text-[10px] font-semibold"
                            title="Orphaned component (not referenced in dependency graph)"
                          >
                            ✕ Orfano
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination & Footer Stats */}
        <div className="p-4 bg-gray-50 border-t border-gray-200 flex flex-wrap items-center justify-between gap-4 text-xs text-gray-600">
          <div>
            Showing <span className="font-bold">{totalMatrixItems > 0 ? (currentSafePage - 1) * matrixPageSize + 1 : 0}</span> to{' '}
            <span className="font-bold">{Math.min(currentSafePage * matrixPageSize, totalMatrixItems)}</span> of{' '}
            <span className="font-bold">{totalMatrixItems}</span> components ({counts.all} total in SBOM)
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span>Per page:</span>
              <select
                value={matrixPageSize}
                onChange={(e) => {
                  setMatrixPageSize(parseInt(e.target.value, 10));
                  setMatrixPage(1);
                }}
                className="border border-gray-300 rounded px-2 py-1 text-xs bg-white"
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={250}>250</option>
              </select>
            </div>

            <div className="flex items-center gap-1">
              <button
                disabled={currentSafePage <= 1}
                onClick={() => setMatrixPage((p) => Math.max(1, p - 1))}
                className="px-2.5 py-1 border border-gray-300 rounded bg-white hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed font-medium"
              >
                Prev
              </button>
              <span className="px-2 font-semibold">
                Page {currentSafePage} of {totalMatrixPages}
              </span>
              <button
                disabled={currentSafePage >= totalMatrixPages}
                onClick={() => setMatrixPage((p) => Math.min(totalMatrixPages, p + 1))}
                className="px-2.5 py-1 border border-gray-300 rounded bg-white hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed font-medium"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportDetailPage;
