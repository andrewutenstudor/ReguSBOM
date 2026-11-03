import React from 'react';
import { isEE } from '../config/edition';

export const Footer: React.FC = () => {
  const currentYear = 2026;

  return (
    <footer className="bg-slate-900 border-t border-slate-800 text-slate-400 text-xs mt-auto">
      {/* Upper Grid */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Col 1: Identity & Brand */}
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <img
                src="/logo.jpeg"
                alt="ReguBOM Logo"
                className="h-9 w-auto rounded-md shadow-sm border border-slate-700/50 object-contain"
              />
              <div className="flex flex-col">
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold tracking-tight text-white">ReguBOM</span>
                  <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    {isEE ? 'Enterprise Sovereign' : 'Community Edition'}
                  </span>
                </div>
                <span className="text-[11px] text-slate-400 -mt-0.5">Regulatory SBOM Ledger</span>
              </div>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Sovereign software supply chain compliance engine for validating, inspecting, certifying, and managing Software Bill of Materials (SBOMs) under mandatory EU and international regulations.
            </p>
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700/60 text-[11px] text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]"></span>
              <span>Zero External Telemetry • Hermetic Air-Gap</span>
            </div>
          </div>

          {/* Col 2: Regulatory Directives */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">Regulatory Frameworks</h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li className="flex items-start gap-1.5">
                <span className="text-blue-400 font-mono text-[11px] mt-0.5">▪</span>
                <span><strong className="text-slate-300">EU CRA</strong> (Regulation EU 2024/2847 Art. 13 &amp; Annex II)</span>
              </li>
              <li className="flex items-start gap-1.5">
                <span className="text-blue-400 font-mono text-[11px] mt-0.5">▪</span>
                <span><strong className="text-slate-300">ENISA Advisory</strong> on SBOM (October 2026 Checklist)</span>
              </li>
              <li className="flex items-start gap-1.5">
                <span className="text-blue-400 font-mono text-[11px] mt-0.5">▪</span>
                <span><strong className="text-slate-300">BSI TR-03183-2 v2.1.0</strong> (Federal Office for InfoSec)</span>
              </li>
              <li className="flex items-start gap-1.5">
                <span className="text-blue-400 font-mono text-[11px] mt-0.5">▪</span>
                <span><strong className="text-slate-300">ACN modulo_SBOM</strong> (Italian Cybersecurity Agency, EUPL v1.2)</span>
              </li>
              <li className="flex items-start gap-1.5">
                <span className="text-blue-400 font-mono text-[11px] mt-0.5">▪</span>
                <span><strong className="text-slate-300">CISA 2026</strong> Minimum Elements &amp; NTIA Framing</span>
              </li>
            </ul>
          </div>

          {/* Col 3: Supported Standards */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">Standards &amp; Specifications</h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li className="flex items-start gap-1.5">
                <span className="text-emerald-400 font-mono text-[11px] mt-0.5">▪</span>
                <span><strong className="text-slate-300">CycloneDX</strong> v1.4, v1.5, v1.6 &amp; v1.7 (ECMA-424)</span>
              </li>
              <li className="flex items-start gap-1.5">
                <span className="text-emerald-400 font-mono text-[11px] mt-0.5">▪</span>
                <span><strong className="text-slate-300">SPDX</strong> v2.2, v2.3 &amp; v3.0.1 (ISO/IEC 5962:2021)</span>
              </li>
              <li className="flex items-start gap-1.5">
                <span className="text-emerald-400 font-mono text-[11px] mt-0.5">▪</span>
                <span><strong className="text-slate-300">RFC 3339 / ISO 8601</strong> UTC Timestamp Enforcements</span>
              </li>
              <li className="flex items-start gap-1.5">
                <span className="text-emerald-400 font-mono text-[11px] mt-0.5">▪</span>
                <span><strong className="text-slate-300">RFC 5322</strong> Author &amp; Creator Email Standards</span>
              </li>
              <li className="flex items-start gap-1.5">
                <span className="text-emerald-400 font-mono text-[11px] mt-0.5">▪</span>
                <span><strong className="text-slate-300">Ed25519 &amp; in-toto</strong> Cryptographic Attestation</span>
              </li>
            </ul>
          </div>

          {/* Col 4: Legal & Architecture */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">Legal &amp; Deployment</h4>
            <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60 space-y-1.5 text-[11px]">
              <div className="text-slate-200 font-semibold flex items-center gap-1.5">
                <span>⚖️</span>
                <span>{isEE ? 'ReguBOM Enterprise Edition' : 'ReguBOM Community Edition'}</span>
              </div>
              <p className="text-slate-400 leading-normal">
                {isEE
                  ? 'Air-Gapped Sovereign Commercial License. Mission-critical deployments (RKE2, OpenShift, PostgreSQL 16).'
                  : 'Open-Source copyleft licensed under GNU Affero General Public License v3.0 (AGPLv3). Complete source must accompany any network distribution.'}
              </p>
            </div>
            <p className="text-[11px] text-slate-400">
              Integrates the foundational <span className="text-slate-300 font-medium">modulo_SBOM</span> engine authored by the Italian National Cybersecurity Agency (<strong className="text-slate-300">ACN</strong>).
            </p>
          </div>
        </div>

        {/* Lower Divider & Copyright */}
        <div className="mt-10 pt-6 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-4 text-[11px] text-slate-400">
          <div>
            © {currentYear} Andrei Tudor &amp; ReguBOM Contributors. All rights reserved.
          </div>
          <div className="flex items-center gap-4 text-slate-400">
            <span>Air-Gap Sovereign Gateway</span>
            <span>•</span>
            <span>EU Cyber Resilience Act Ready</span>
            <span>•</span>
            <span className="font-mono text-slate-400">{isEE ? 'v2.0.0-ee' : 'v2.0.0-ce (AGPLv3)'}</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
