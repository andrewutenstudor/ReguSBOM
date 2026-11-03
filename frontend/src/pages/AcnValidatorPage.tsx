import React, { useState, useCallback } from 'react';
// @ts-ignore
import html2pdf from 'html2pdf.js';
import apiService from '../services/api';
import type { AcnValidateResponse, ValidateOptions } from '../types';

const AcnValidatorPage: React.FC = () => {
    const [file, setFile] = useState<File | null>(null);
    const [isDragging, setIsDragging] = useState(false);
    const [isValidating, setIsValidating] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [result, setResult] = useState<AcnValidateResponse | null>(null);
    const [options, setOptions] = useState<ValidateOptions>({ maxSize: 50, skipSchema: false, verbose: false });

    const onDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);
        const f = e.dataTransfer.files[0];
        if (f?.name.toLowerCase().endsWith('.json')) { setFile(f); setError(null); }
        else setError('Il validatore ACN richiede file .json (CycloneDX v1.6)');
    }, []);

    const onFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        const f = e.target.files?.[0];
        if (!f) return;
        if (f.name.toLowerCase().endsWith('.json')) { setFile(f); setError(null); }
        else setError('Il validatore ACN richiede file .json (CycloneDX v1.6)');
    };

    const handleValidate = async () => {
        if (!file) return;
        setIsValidating(true);
        setError(null);
        setResult(null);
        try {
            const res = await apiService.validateAcnOnly(file, options);
            setResult(res);
        } catch (err: any) {
            setError(err.response?.data?.detail || err.message || 'Validazione fallita');
        } finally {
            setIsValidating(false);
        }
    };

    const colorLine = (line: string): string => {
        if (line.includes('✅')) return 'line-success';
        if (line.includes('❌')) return 'line-error';
        if (line.includes('⚠️')) return 'line-warning';
        if (line.startsWith('=') || line.startsWith('-')) return 'line-sep';
        return '';
    };

    const exportToPdf = () => {
        const element = document.getElementById('acn-report-content');
        if (!element) return;

        const opt: any = {
            margin: 10,
            filename: `acn-validation-${file?.name || 'report'}.pdf`,
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { scale: 2 },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
        };

        html2pdf().set(opt).from(element).save();
    };

    const downloadTextReport = () => {
        if (!result) return;
        const content = result.output_lines.join('\n');
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `acn-validation-${file?.name || 'report'}.txt`;
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div className="max-w-4xl mx-auto space-y-6 fade-in">
            {/* Header */}
            <div>
                <div className="flex items-center gap-3 mb-1">
                    <span className="text-3xl">🏛️</span>
                    <h1 className="text-2xl font-bold text-gray-900">Validatore ACN — modulo_SBOM</h1>
                </div>
                <p className="text-gray-600 text-sm">
                    Esegue la validazione originale di{' '}
                    <a href="https://github.com/ACN-IT/modulo_SBOM" target="_blank" rel="noopener noreferrer"
                        className="text-primary-600 underline">modulo_SBOM</a>{' '}
                    (Agenzia per la Cybersicurezza Nazionale) su file SBOM CycloneDX v1.6 JSON.
                    Applicabile ai criteri di premialità ex art. 4 del DPCM 30 aprile 2025.
                </p>
            </div>

            {/* Info banner */}
            <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 text-sm text-blue-800">
                ℹ️ Questo tab esegue <strong>solo</strong> la validazione ACN (schema CycloneDX v1.6, metadata, componenti, servizi, whitelist paesi).
                Per i controlli completi CRA e NIS2, usa la sezione <strong>"Carica SBOM"</strong>.
            </div>

            {/* Upload zone */}
            <div
                className={`border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer ${isDragging ? 'border-primary-500 bg-primary-50 drag-active' : 'border-gray-300 hover:border-primary-400 hover:bg-gray-50'
                    }`}
                onDrop={onDrop}
                onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={e => { e.preventDefault(); setIsDragging(false); }}
                onClick={() => document.getElementById('acn-file-input')?.click()}
            >
                {file ? (
                    <div>
                        <div className="text-4xl mb-2">📄</div>
                        <p className="font-semibold text-gray-900">{file.name}</p>
                        <p className="text-xs text-gray-500 mt-1">{(file.size / 1024).toFixed(1)} KB</p>
                        <button onClick={e => { e.stopPropagation(); setFile(null); setResult(null); }}
                            className="mt-3 text-sm text-primary-600 hover:text-primary-700">
                            Cambia file
                        </button>
                    </div>
                ) : (
                    <>
                        <div className="text-5xl mb-3">📤</div>
                        <p className="text-gray-700 font-medium">Trascina qui il file SBOM o clicca per sfogliare</p>
                        <p className="text-xs text-gray-400 mt-1">Solo .json — CycloneDX v1.6</p>
                    </>
                )}
                <input id="acn-file-input" type="file" accept=".json" onChange={onFileSelect} className="hidden" />
            </div>

            {/* Options */}
            {file && !isValidating && (
                <div className="card">
                    <h3 className="font-semibold text-gray-800 mb-3">Opzioni validazione</h3>
                    <div className="flex flex-wrap gap-4">
                        <label className="flex items-center gap-2 text-sm cursor-pointer">
                            <input type="checkbox" checked={options.skipSchema ?? false}
                                onChange={e => setOptions((o: ValidateOptions) => ({ ...o, skipSchema: e.target.checked }))}
                                className="rounded" />
                            Salta validazione schema
                        </label>
                        <label className="flex items-center gap-2 text-sm cursor-pointer">
                            <input type="checkbox" checked={options.verbose ?? false}
                                onChange={e => setOptions((o: ValidateOptions) => ({ ...o, verbose: e.target.checked }))}
                                className="rounded" />
                            Output dettagliato (verbose)
                        </label>
                    </div>
                </div>
            )}

            {error && (
                <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-red-700 text-sm">❌ {error}</div>
            )}

            {file && !isValidating && (
                <div className="flex justify-end">
                    <button onClick={handleValidate} className="btn-primary text-base px-6 py-3">
                        🏛️ Avvia Validazione ACN
                    </button>
                </div>
            )}

            {isValidating && (
                <div className="card text-center py-8">
                    <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-600 mx-auto mb-4" />
                    <p className="text-gray-600">Validazione ACN in corso...</p>
                </div>
            )}

            {/* Results */}
            {result && (
                <div className="space-y-5 fade-in">
                    {/* Overall result */}
                    <div className={`rounded-xl p-5 border font-semibold flex items-center gap-3 ${result.overall_valid
                        ? 'bg-green-50 border-green-200 text-green-800'
                        : 'bg-red-50 border-red-200 text-red-800'
                        }`}>
                        <span className="text-2xl">{result.overall_valid ? '✅' : '❌'}</span>
                        <div>
                            <div className="text-lg">
                                {result.overall_valid
                                    ? 'Validazione ACN completata con successo'
                                    : 'Validazione ACN: non conformità rilevate'}
                            </div>
                            <div className="font-normal text-sm opacity-75">File: {result.filename}</div>
                        </div>
                    </div>

                    {/* Summary stats */}
                    {result.results && (
                        <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
                            {[
                                { label: 'Schema', val: result.results.schema_skipped ? 'N/A' : result.results.schema_valid ? '✅' : '❌' },
                                { label: 'Metadata', val: result.results.metadata_valid ? '✅' : '❌' },
                                { label: 'Componenti', val: `${result.results.valid_components}/${result.results.components_total}` },
                                { label: 'Servizi', val: `${result.results.valid_services}/${result.results.services_total}` },
                            ].map(s => (
                                <div key={s.label} className="stat-card">
                                    <div className="stat-value text-xl">{s.val}</div>
                                    <div className="stat-label">{s.label}</div>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* Raw ACN text output */}
                    <div className="card">
                        <div className="flex flex-col md:flex-row md:items-center justify-between mb-4 gap-3">
                            <div>
                                <h3 className="font-semibold text-gray-900 text-lg flex items-center gap-2">
                                    <span>🖥️</span> Output Validazione ACN
                                </h3>
                                <p className="text-xs text-gray-400 mt-1">
                                    Report originale dal modulo_SBOM dell'Agenzia per la Cybersicurezza Nazionale
                                </p>
                            </div>
                            <div className="flex gap-2">
                                <button onClick={exportToPdf} className="btn-primary shadow flex-shrink-0">
                                    📄 Esporta PDF
                                </button>
                                <button onClick={downloadTextReport} className="btn-secondary flex-shrink-0">
                                    📥 Scarica TXT
                                </button>
                            </div>
                        </div>

                        <div id="acn-report-content" className="report-container">
                            <div className="report-header">
                                Report di Validazione: <strong>{result.filename}</strong>
                            </div>

                            <div className="terminal premium-terminal">
                                {result.output_lines.length > 0 ? (
                                    result.output_lines.map((line: string, i: number) => (
                                        <div key={i} className={colorLine(line)}>
                                            {line}
                                        </div>
                                    ))
                                ) : (
                                    <span className="text-gray-500">Nessun output disponibile.</span>
                                )}
                            </div>

                            <div className="report-footer">
                                Generato in data: {new Date().toLocaleString('it-IT')}
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AcnValidatorPage;