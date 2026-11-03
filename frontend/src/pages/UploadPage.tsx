import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import apiService from '../services/api';
import { useAuth } from '../context/AuthContext';
import { ValidateResponse } from '../types';

export const UploadPage: React.FC = () => {
  const navigate = useNavigate();
  const { canMutate, role } = useAuth();
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ValidateResponse | null>(null);

  const [options, setOptions] = useState<{
    maxSize: number;
    profile: string;
    proprietaryPrefix: string;
    proprietarySupplier: string;
  }>({
    maxSize: 500,
    profile: 'ENISA_2026',
    proprietaryPrefix: 'regubom:proprietary',
    proprietarySupplier: '',
  });

  const isValidFile = (fileName: string): boolean => {
    const lower = fileName.toLowerCase();
    return lower.endsWith('.json') || lower.endsWith('.cdx') || lower.endsWith('.spdx');
  };

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile && isValidFile(droppedFile.name)) {
      setFile(droppedFile);
      setError(null);
    } else {
      setError(
        '⚠️ Accepted formats: CycloneDX v1.6/v1.7 JSON (.json, .cdx) or SPDX v2.3/v3.0.1 JSON (.json, .spdx). Excel and unstructured text are rejected.'
      );
    }
  }, []);

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const onDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const onFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      if (isValidFile(selectedFile.name)) {
        setFile(selectedFile);
        setError(null);
      } else {
        setError(
          '⚠️ Accepted formats: CycloneDX v1.6/v1.7 JSON (.json, .cdx) or SPDX v2.3/v3.0.1 JSON (.json, .spdx). Excel and unstructured text are rejected.'
        );
      }
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setError('Please select an SBOM file first');
      return;
    }

    setIsUploading(true);
    setUploadProgress(0);
    setError(null);

    let progressInterval: any = null;
    try {
      progressInterval = setInterval(() => {
        setUploadProgress((prev) => Math.min(prev + 12, 90));
      }, 200);

      const response = await apiService.validateSbom(file, {
        maxSize: options.maxSize,
        profile: options.profile,
        proprietaryPrefix: options.proprietaryPrefix,
        proprietarySupplier: options.proprietarySupplier,
      });

      if (progressInterval) clearInterval(progressInterval);
      setUploadProgress(100);
      setResult(response);

      setTimeout(() => {
        navigate(`/reports/${response.report_id}`);
      }, 1200);
    } catch (err: any) {
      if (progressInterval) clearInterval(progressInterval);
      setError(err.response?.data?.detail || err.message || 'Audit validation failed.');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Page Title */}
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
          Regulatory SBOM Ingestion &amp; Audit Engine
        </h1>
        <p className="text-slate-600 mt-1 text-sm">
          Upload Software Bills of Materials for formal compliance evaluation against{' '}
          <strong>ENISA Technical Advisory (October 2026)</strong>, <strong>BSI TR-03183-2 v2.1.0</strong>, and{' '}
          <strong>EU CRA Art. 13</strong>.
        </p>
      </div>

      {/* Main Upload Card */}
      <div className="bg-white rounded-2xl shadow-sm border border-slate-200 p-6 sm:p-8 space-y-6">
        {/* Dropzone */}
        <div
          onDrop={onDrop}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all duration-200 ${
            isDragging
              ? 'border-primary-500 bg-primary-50/50 scale-[0.99]'
              : file
              ? 'border-emerald-400 bg-emerald-50/30'
              : 'border-slate-300 hover:border-slate-400 bg-slate-50/50'
          }`}
          onClick={() => document.getElementById('file-input')?.click()}
        >
          <input
            id="file-input"
            type="file"
            accept=".json,.cdx,.spdx"
            onChange={onFileSelect}
            className="hidden"
          />

          <div className="space-y-3">
            <div className="text-4xl">
              {file ? '📄' : isDragging ? '📂' : '📥'}
            </div>

            {file ? (
              <div>
                <p className="text-base font-bold text-slate-900">{file.name}</p>
                <p className="text-xs text-slate-500 mt-0.5">
                  {(file.size / (1024 * 1024)).toFixed(2)} MB · Click to change file
                </p>
              </div>
            ) : (
              <div>
                <p className="text-base font-bold text-slate-900">
                  Drag and drop your SBOM document here
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  or <span className="text-primary-600 font-semibold underline">browse from your computer</span>
                </p>
                <p className="text-[11px] text-slate-400 mt-2 font-medium">
                  Accepted: CycloneDX v1.6 &amp; v1.7 (ECMA-424) · SPDX v2.3 &amp; v3.0.1 (JSON)
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="p-4 bg-red-50 border border-red-200 rounded-xl text-xs text-red-800 font-medium flex items-start gap-2.5">
            <span className="text-base">⚠️</span>
            <div className="flex-1">{error}</div>
          </div>
        )}

        {/* Progress Bar */}
        {isUploading && (
          <div className="space-y-2">
            <div className="flex justify-between text-xs font-semibold text-slate-700">
              <span>Auditing regulatory compliance (ENISA 2026 / BSI)...</span>
              <span>{uploadProgress}%</span>
            </div>
            <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden">
              <div
                className="bg-primary-600 h-2.5 rounded-full transition-all duration-300"
                style={{ width: `${uploadProgress}%` }}
              ></div>
            </div>
          </div>
        )}

        {/* Tenant Configuration Settings (Bifurcated 1st vs 3rd Party Rules) */}
        <div className="border-t border-slate-200 pt-6 space-y-4">
          <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
            <span>⚙️</span> Tenant Configuration &amp; Proprietary Component Identification
          </h3>
          <p className="text-xs text-slate-500">
            Define how your organization identifies proprietary (1st-party) components in the inventory.
            Under CRA and ENISA guidelines, missing data on proprietary software triggers non-compliance,
            while third-party open-source omissions produce non-blocking warnings.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Proprietary Property Prefix
              </label>
              <input
                type="text"
                value={options.proprietaryPrefix}
                onChange={(e) => setOptions({ ...options, proprietaryPrefix: e.target.value })}
                placeholder="regubom:proprietary"
                className="w-full px-3 py-2 border border-slate-300 rounded-lg text-xs font-mono focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
              <span className="text-[10px] text-slate-400 mt-1 block">
                Matches property names starting with this prefix (default: regubom:proprietary).
              </span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Proprietary Supplier Name (Optional)
              </label>
              <input
                type="text"
                value={options.proprietarySupplier}
                onChange={(e) => setOptions({ ...options, proprietarySupplier: e.target.value })}
                placeholder="e.g. MyEnterprise Corp"
                className="w-full px-3 py-2 border border-slate-300 rounded-lg text-xs focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
              <span className="text-[10px] text-slate-400 mt-1 block">
                Components authored by this supplier will be classified as proprietary.
              </span>
            </div>
          </div>
        </div>

        {/* Auditor Read-Only Notification */}
        {!canMutate && (
          <div className="bg-purple-50 border border-purple-200 text-purple-900 rounded-xl p-4 text-xs flex items-center gap-3">
            <span className="text-xl">🔒</span>
            <div>
              <p className="font-bold">Modalità Sola Lettura (Ruolo: {role})</p>
              <p className="text-purple-700">
                Il caricamento e l'audit di nuovi file SBOM sono riservati agli utenti con ruolo <strong>admin</strong> o <strong>operator</strong>.
              </p>
            </div>
          </div>
        )}

        {/* Submit Button */}
        <div className="pt-2 flex justify-end">
          <button
            onClick={handleUpload}
            disabled={!file || isUploading || !canMutate}
            title={!canMutate ? "Operazione non consentita per il ruolo auditor" : undefined}
            className="w-full sm:w-auto px-6 py-2.5 bg-primary-600 hover:bg-primary-700 text-white rounded-xl text-sm font-bold shadow-sm disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
          >
            {isUploading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>
                <span>Executing Regulatory Audit...</span>
              </>
            ) : (
              <>
                <span>🚀</span>
                <span>Audit SBOM Compliance</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default UploadPage;
