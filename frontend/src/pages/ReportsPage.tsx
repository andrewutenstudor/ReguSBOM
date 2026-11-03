import React, { useEffect, useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import apiService from '../services/api';
import { useAuth } from '../context/AuthContext';
import type { ReportListItem, OverallStatus } from '../types';

const STATUS_INFO: Record<OverallStatus, { label: string; className: string; icon: string }> = {
  PASS: { label: 'PASS', className: 'bg-emerald-100 text-emerald-800 border-emerald-200', icon: '✅' },
  FAIL: { label: 'FAIL', className: 'bg-red-100 text-red-800 border-red-200', icon: '❌' },
  WARNING: { label: 'WARNING', className: 'bg-amber-100 text-amber-800 border-amber-200', icon: '⚠️' },
};

export const ReportsPage: React.FC = () => {
  const navigate = useNavigate();
  const { canMutate } = useAuth();
  const [reports, setReports] = useState<ReportListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>('');
  const [search, setSearch] = useState('');

  const loadReports = useCallback(async () => {
    try {
      setLoading(true);
      const data = await apiService.listReports(100, filter || undefined);
      setReports(data.reports);
      setError(null);
    } catch {
      setError('Unable to load compliance dossiers. Please verify the backend service is running.');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const handleDelete = async (e: React.MouseEvent, id: number) => {
    e.stopPropagation();
    if (!window.confirm('Delete this regulatory compliance dossier and associated SBOM?')) return;
    try {
      await apiService.deleteReport(id);
      setReports((prev) => prev.filter((r) => r.report_id !== id));
    } catch {
      alert('Failed to delete report.');
    }
  };

  const filtered = reports.filter(
    (r) => search === '' || r.filename.toLowerCase().includes(search.toLowerCase())
  );

  const formatDate = (iso: string | null) => {
    if (!iso) return '—';
    return new Date(iso).toLocaleString();
  };

  const formatTime = (t?: number) => (t != null ? `${t.toFixed(3)}s` : '—');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">
            Compliance Dossier Registry
          </h1>
          <p className="text-slate-500 text-sm mt-0.5">
            Audit history conforming to EU CRA Article 13 &amp; ENISA Technical Advisory (October 2026)
          </p>
        </div>
        <Link
          to="/upload"
          className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white font-bold rounded-xl text-sm shadow-sm transition-colors self-start sm:self-auto flex items-center gap-1.5"
        >
          <span>🚀</span> Ingest New SBOM
        </Link>
      </div>

      {/* Filters & Search */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-col sm:flex-row gap-3 shadow-sm">
        <input
          type="text"
          placeholder="🔍 Search dossiers by filename..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 px-3.5 py-2 border border-slate-300 rounded-lg text-xs focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
        />
        <div className="flex gap-2">
          {[
            { id: '', label: 'All' },
            { id: 'PASS', label: 'PASS' },
            { id: 'WARNING', label: 'WARNING' },
            { id: 'FAIL', label: 'FAIL' },
          ].map((s) => (
            <button
              key={s.id}
              onClick={() => setFilter(s.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors ${
                filter === s.id
                  ? 'bg-primary-900 text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="text-center py-20">
          <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-600 mx-auto" />
          <p className="text-slate-500 text-sm mt-4">Loading regulatory dossiers...</p>
        </div>
      ) : error ? (
        <div className="bg-red-50 border border-red-200 rounded-xl p-5 text-red-800 text-sm font-medium">
          {error}
        </div>
      ) : filtered.length === 0 ? (
        <div className="bg-white rounded-2xl border border-slate-200 p-12 text-center text-slate-500">
          <div className="text-3xl mb-2">📂</div>
          <p className="font-semibold text-slate-700">No regulatory dossiers found</p>
          <p className="text-xs text-slate-400 mt-1">Upload an SBOM to perform an ENISA/CRA compliance audit.</p>
        </div>
      ) : (
        <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
          <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
            <thead className="bg-slate-50 text-slate-700 font-bold uppercase tracking-wider text-[10px]">
              <tr>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Filename</th>
                <th className="py-3 px-4">Standard</th>
                <th className="py-3 px-4">Components</th>
                <th className="py-3 px-4">Audit Date</th>
                <th className="py-3 px-4">Duration</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 bg-white">
              {filtered.map((r) => {
                const sInfo = STATUS_INFO[r.overall_status as OverallStatus] || {
                  label: r.overall_status,
                  className: 'bg-slate-100 text-slate-700',
                  icon: '⚪',
                };
                return (
                  <tr
                    key={r.report_id}
                    onClick={() => navigate(`/reports/${r.report_id}`)}
                    className="hover:bg-slate-50/80 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-extrabold border ${sInfo.className}`}
                      >
                        <span>{sInfo.icon}</span>
                        <span>{sInfo.label}</span>
                      </span>
                    </td>
                    <td className="py-3 px-4 font-bold text-slate-900 truncate max-w-xs" title={r.filename}>
                      {r.filename}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 bg-slate-100 text-slate-800 rounded font-semibold text-[10px] uppercase">
                        {r.format}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-700">
                      {r.statistics?.components_total ?? '—'}
                    </td>
                    <td className="py-3 px-4 text-slate-500 font-medium">{formatDate(r.validation_timestamp)}</td>
                    <td className="py-3 px-4 text-slate-500 font-mono text-[11px]">{formatTime(r.processing_time)}</td>
                    <td className="py-3 px-4 text-right">
                      <div className="inline-flex items-center gap-2">
                        <Link
                          to={`/reports/${r.report_id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="px-2.5 py-1 bg-primary-50 text-primary-700 hover:bg-primary-100 rounded-md font-semibold text-xs transition-colors"
                        >
                          View Dossier →
                        </Link>
                        {canMutate && (
                          <button
                            onClick={(e) => handleDelete(e, r.report_id)}
                            className="p-1 text-slate-400 hover:text-red-600 transition-colors"
                            title="Delete dossier"
                          >
                            🗑️
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default ReportsPage;
