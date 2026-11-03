import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import apiService from '../services/api';
import type { DashboardStats } from '../types';

export const HomePage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    apiService.getDashboardStats().then(setStats).catch(() => {});
  }, []);

  const formatDate = (iso: string | null) => {
    if (!iso) return '—';
    return new Date(iso).toLocaleString();
  };

  return (
    <div className="space-y-8">
      {/* Hero Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-950 via-slate-900 to-primary-950 text-white p-8 sm:p-10 shadow-xl border border-slate-800">
        <div className="relative z-10 max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-primary-500/20 border border-primary-400/30 rounded-full text-xs font-bold text-primary-300 uppercase tracking-wider mb-4">
            <span>🛡️</span> ENISA Advisory 2026 &amp; BSI TR-03183-2 Ready
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white leading-tight">
            ReguBOM — Enterprise Cyber Resilience &amp; Regulatory SBOM Gateway
          </h1>
          <p className="text-slate-300 text-sm sm:text-base mt-3 leading-relaxed">
            Commercial SaaS and on-premise regulatory gateway automating SBOM technical documentation compliance
            under <strong>EU Cyber Resilience Act (CRA Art. 13 &amp; Annex II)</strong>,{' '}
            <strong>ENISA Technical Advisory (October 2026)</strong>, and <strong>CISA 2026 Minimum Elements</strong>.
          </p>

          <div className="flex flex-wrap gap-3 mt-6">
            <Link
              to="/upload"
              className="px-5 py-2.5 bg-primary-600 hover:bg-primary-500 text-white font-bold rounded-xl text-sm shadow-md transition-all flex items-center gap-2"
            >
              <span>🚀</span> Ingest &amp; Audit SBOM
            </Link>
            <Link
              to="/reports"
              className="px-5 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold rounded-xl text-sm transition-all flex items-center gap-2"
            >
              <span>📋</span> Compliance Dossiers
            </Link>
          </div>
        </div>

        {/* Ambient background styling */}
        <div className="absolute -top-12 -right-12 w-64 h-64 rounded-full bg-primary-600/10 blur-3xl" />
        <div className="absolute bottom-0 right-16 w-48 h-48 rounded-full bg-blue-500/10 blur-2xl" />
      </div>

      {/* Aggregate Statistics */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
            <div className="text-2xl font-extrabold text-slate-900">{stats.total_validations}</div>
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mt-1">Total Dossiers</div>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
            <div className="text-2xl font-extrabold text-emerald-600">{stats.passed}</div>
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mt-1">Fully Compliant (PASS)</div>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
            <div className="text-2xl font-extrabold text-red-600">{stats.failed}</div>
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mt-1">Non-Compliant (FAIL)</div>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
            <div className="text-2xl font-extrabold text-primary-600">{stats.pass_rate}%</div>
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mt-1">Compliance Rate</div>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm col-span-2 md:col-span-1">
            <div className="text-xs font-bold text-slate-900 truncate mt-1.5">{formatDate(stats.last_validation)}</div>
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mt-1">Latest Audit</div>
          </div>
        </div>
      )}

      {/* Product Capability Cards */}
      <div className="grid md:grid-cols-3 gap-6">
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm flex flex-col justify-between">
          <div>
            <div className="text-3xl mb-3">📑</div>
            <h2 className="text-base font-bold text-slate-900 mb-1">ENISA &amp; BSI Compliance Engine</h2>
            <p className="text-xs text-slate-600 leading-relaxed mb-4">
              Automated auditing of SBOM Table 1 document metadata, 12-point regulatory checklist, and component completeness matrices.
            </p>
            <div className="flex flex-wrap gap-1.5 mb-4">
              {['CycloneDX 1.6 & 1.7', 'SPDX 2.3 & 3.0.1', 'ECMA-424'].map((b) => (
                <span key={b} className="text-[10px] font-bold px-2 py-0.5 bg-blue-50 text-blue-800 rounded">
                  {b}
                </span>
              ))}
            </div>
          </div>
          <Link
            to="/upload"
            className="w-full text-center px-4 py-2 bg-primary-50 hover:bg-primary-100 text-primary-800 font-bold rounded-lg text-xs transition-colors"
          >
            Launch Ingestion Engine →
          </Link>
        </div>

        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm flex flex-col justify-between">
          <div>
            <div className="text-3xl mb-3">⚖️</div>
            <h2 className="text-base font-bold text-slate-900 mb-1">Bifurcated Proprietary vs. OSS Logic</h2>
            <p className="text-xs text-slate-600 leading-relaxed mb-4">
              Configurable tenant prefixing (defaulting to <code className="bg-slate-100 px-1 py-0.5 rounded text-[11px]">regubom:proprietary</code>).
              Strict enforcement on first-party software; advisory non-blocking warnings on open-source libraries.
            </p>
            <div className="flex flex-wrap gap-1.5 mb-4">
              {['Proprietary Strictness', 'OSS Upstream Warnings', 'CRA Art. 13'].map((b) => (
                <span key={b} className="text-[10px] font-bold px-2 py-0.5 bg-emerald-50 text-emerald-800 rounded">
                  {b}
                </span>
              ))}
            </div>
          </div>
          <Link
            to="/reports"
            className="w-full text-center px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-800 font-bold rounded-lg text-xs transition-colors"
          >
            View Regulatory Reports →
          </Link>
        </div>

        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm flex flex-col justify-between">
          <div>
            <div className="text-3xl mb-3">📜</div>
            <h2 className="text-base font-bold text-slate-900 mb-1">CRA Annex II Technical File Suite</h2>
            <p className="text-xs text-slate-600 leading-relaxed mb-4">
              Download formal JSON Compliance Certificates and generate standalone print-ready HTML &amp; PDF Technical Files ready for regulatory authorities.
            </p>
            <div className="flex flex-wrap gap-1.5 mb-4">
              {['JSON Certificate', 'Print-Ready HTML', 'WeasyPrint PDF'].map((b) => (
                <span key={b} className="text-[10px] font-bold px-2 py-0.5 bg-purple-50 text-purple-800 rounded">
                  {b}
                </span>
              ))}
            </div>
          </div>
          <Link
            to="/upload"
            className="w-full text-center px-4 py-2 bg-purple-50 hover:bg-purple-100 text-purple-800 font-bold rounded-lg text-xs transition-colors"
          >
            Create Compliance Dossier →
          </Link>
        </div>
      </div>
    </div>
  );
};

export default HomePage;
