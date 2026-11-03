/**
 * ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
 * Frontend API Service.
 */
import axios from 'axios';
import {
  ValidateResponse,
  ReportListItem,
  ReportDetail,
  SbomListItem,
  HealthResponse,
  DashboardStats,
  ValidateOptions,
  AcnValidateResponse,
  SbomViewerData,
  ProductItem,
  ProductReleaseItem,
  ComponentSearchResult,
  LicenseInfo,
  DiffCandidate,
  DiffResult,
  UserProfile,
  LoginResponse,
  ApiKeyItem,
  AuthProvidersResponse,
  MfaSetupResponse,
  MfaEnableResponse,
} from '../types';

const rawApiUrl = (import.meta.env.VITE_API_URL || '').trim().replace(/\/+$/, '');
const API_BASE_URL = (rawApiUrl === '/api' || rawApiUrl === '/') ? '' : rawApiUrl;

const apiClient = axios.create({
  baseURL: API_BASE_URL || undefined,
  timeout: 300000, // 5 minutes for large enterprise SBOM files
});

// Automatic JWT bearer token injection for authenticated sessions
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('regubom_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => Promise.reject(error));

// Global response interceptor handling session expirations
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !window.location.pathname.startsWith('/login')) {
      localStorage.removeItem('regubom_token');
      localStorage.removeItem('regubom_user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const apiService = {
  /**
   * Upload and audit an SBOM file against ENISA Advisory 2026 and EU CRA Art. 13.
   */
  async validateSbom(
    file: File,
    options: ValidateOptions = {}
  ): Promise<ValidateResponse> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('max_size', String(options.maxSize || 500));
    formData.append('profile', options.profile || 'ENISA_2026');
    if (options.proprietaryPrefix) {
      formData.append('proprietary_prefix', options.proprietaryPrefix);
    }
    if (options.proprietarySupplier) {
      formData.append('proprietary_supplier', options.proprietarySupplier);
    }

    const response = await apiClient.post<ValidateResponse>('/api/validate', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      timeout: 300000,
    });
    return response.data;
  },

  /**
   * Dedicated ACN module validation.
   */
  async validateAcnOnly(
    file: File,
    options: { maxSize?: number; skipSchema?: boolean; verbose?: boolean } = {}
  ): Promise<AcnValidateResponse> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('max_size', String(options.maxSize || 500));
    formData.append('skip_schema', String(options.skipSchema || false));
    formData.append('verbose', String(options.verbose || false));

    const response = await apiClient.post<AcnValidateResponse>('/api/validate/acn', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      timeout: 300000,
    });
    return response.data;
  },

  /**
   * List all historical validation reports.
   */
  async listReports(limit: number = 50, filter?: string): Promise<{ reports: ReportListItem[] }> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (filter) {
      params.append('status', filter);
    }
    const response = await apiClient.get<{ reports: ReportListItem[] }>(
      `/api/reports?${params.toString()}`
    );
    return response.data;
  },

  /**
   * Get a specific validation report and regulatory dossier.
   */
  async getReport(reportId: number): Promise<ReportDetail> {
    const response = await apiClient.get<ReportDetail>(`/api/reports/${reportId}`);
    return response.data;
  },

  /**
   * Download a report in the specified format (json, html, pdf, or certificate).
   */
  downloadReport(reportId: number, format: 'json' | 'html' | 'pdf' | 'certificate'): string {
    if (format === 'certificate') {
      return `${API_BASE_URL}/api/reports/${reportId}/certificate`;
    }
    return `${API_BASE_URL}/api/reports/${reportId}/download/${format}`;
  },

  /**
   * Get Standalone JSON Compliance Certificate.
   */
  downloadCertificate(reportId: number): string {
    return `${API_BASE_URL}/api/reports/${reportId}/certificate`;
  },

  /**
   * Get original SBOM raw content.
   */
  async getSbom(sbomId: number): Promise<any> {
    const response = await apiClient.get(`/api/sboms/${sbomId}`);
    return response.data;
  },

  /**
   * List all uploaded SBOMs.
   */
  async listSboms(limit: number = 50): Promise<{ sboms: SbomListItem[] }> {
    const response = await apiClient.get<{ sboms: SbomListItem[] }>(
      `/api/sboms?limit=${limit}`
    );
    return response.data;
  },

  /**
   * Delete a validation report and associated SBOM.
   */
  async deleteReport(reportId: number): Promise<{ message: string }> {
    const response = await apiClient.delete<{ message: string }>(
      `/api/reports/${reportId}`
    );
    return response.data;
  },

  /**
   * Health check.
   */
  async healthCheck(): Promise<HealthResponse> {
    const response = await apiClient.get<HealthResponse>('/api/health');
    return response.data;
  },

  /**
   * Dashboard statistics.
   */
  async getDashboardStats(): Promise<DashboardStats> {
    const response = await apiClient.get<DashboardStats>('/api/stats');
    return response.data;
  },

  /**
   * Get interactive viewer data.
   */
  async getSbomViewer(id: number, byReportId: boolean = false): Promise<SbomViewerData> {
    const endpoint = byReportId ? `/api/reports/${id}/viewer` : `/api/sboms/${id}/viewer`;
    const response = await apiClient.get<SbomViewerData>(endpoint);
    return response.data;
  },

  async getSbomViewerData(id: number): Promise<SbomViewerData> {
    return this.getSbomViewer(id, false);
  },

  async getReportViewerData(id: number): Promise<SbomViewerData> {
    return this.getSbomViewer(id, true);
  },

  /**
   * Product & Release Asset Catalog Endpoints
   */
  async listProducts(search?: string, businessUnit?: string): Promise<ProductItem[]> {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (businessUnit) params.append('business_unit', businessUnit);
    const qs = params.toString() ? `?${params.toString()}` : '';
    const response = await apiClient.get<ProductItem[]>(`/api/products${qs}`);
    return response.data;
  },

  async getProduct(productRef: string | number): Promise<ProductItem> {
    const response = await apiClient.get<ProductItem>(`/api/products/${productRef}`);
    return response.data;
  },

  async createProduct(payload: {
    name: string;
    slug?: string;
    description?: string;
    business_unit?: string;
  }): Promise<ProductItem> {
    const response = await apiClient.post<ProductItem>('/api/products', payload);
    return response.data;
  },

  async deleteProduct(productRef: string | number): Promise<{ message: string }> {
    const response = await apiClient.delete<{ message: string }>(`/api/products/${productRef}`);
    return response.data;
  },

  async createRelease(
    productRef: string | number,
    payload: { version: string; release_date?: string; lifecycle_status?: string }
  ): Promise<ProductReleaseItem> {
    const response = await apiClient.post<ProductReleaseItem>(
      `/api/products/${productRef}/releases`,
      payload
    );
    return response.data;
  },

  async updateRelease(
    productRef: string | number,
    releaseId: number,
    payload: { lifecycle_status?: string; release_date?: string }
  ): Promise<ProductReleaseItem> {
    const response = await apiClient.patch<ProductReleaseItem>(
      `/api/products/${productRef}/releases/${releaseId}`,
      payload
    );
    return response.data;
  },

  async deleteRelease(
    productRef: string | number,
    releaseId: number
  ): Promise<{ message: string }> {
    const response = await apiClient.delete<{ message: string }>(
      `/api/products/${productRef}/releases/${releaseId}`
    );
    return response.data;
  },

  async uploadSbomToRelease(
    productRef: string | number,
    version: string,
    file: File,
    tier: string = 'APPLICATION',
    proprietaryPrefix?: string,
    proprietarySupplier?: string
  ): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('tier', tier);
    if (proprietaryPrefix) {
      formData.append('proprietary_prefix', proprietaryPrefix);
    }
    if (proprietarySupplier) {
      formData.append('proprietary_supplier', proprietarySupplier);
    }

    const response = await apiClient.post(
      `/api/products/${productRef}/releases/${encodeURIComponent(version)}/upload`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        timeout: 300000,
      }
    );
    return response.data;
  },

  async searchCatalogComponents(name: string, version?: string): Promise<ComponentSearchResult> {
    const params = new URLSearchParams({ name });
    if (version) params.append('version', version);
    const response = await apiClient.get<ComponentSearchResult>(
      `/api/catalog/search-component?${params.toString()}`
    );
    return response.data;
  },

  /**
   * Offline Cryptographic License Status & Ingestion
   */
  async getLicenseStatus(): Promise<LicenseInfo> {
    const response = await apiClient.get<LicenseInfo>('/api/license');
    return response.data;
  },

  async uploadLicense(file: File): Promise<{ message: string; license: LicenseInfo }> {
    const formData = new FormData();
    formData.append('file', file);
    const response = await apiClient.post<{ message: string; license: LicenseInfo }>(
      '/api/license/upload',
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      }
    );
    return response.data;
  },

  /**
   * SBOM Differential & Drift Engine Endpoints
   */
  async getDiffCandidates(): Promise<DiffCandidate[]> {
    const response = await apiClient.get<DiffCandidate[]>('/api/diff/candidates');
    return response.data;
  },

  async getSbomDiff(baseId: number, targetId: number): Promise<DiffResult> {
    const response = await apiClient.get<DiffResult>(`/api/diff?base_id=${baseId}&target_id=${targetId}`);
    return response.data;
  },

  /**
   * RBAC Authentication, Identity, MFA & Scoped Tokens
   */
  async getAuthProviders(): Promise<AuthProvidersResponse> {
    const response = await apiClient.get<AuthProvidersResponse>('/api/auth/providers');
    return response.data;
  },

  async login(username: string, password: string): Promise<LoginResponse> {
    const response = await apiClient.post<LoginResponse>('/api/auth/login', { username, password });
    return response.data;
  },

  async verifyMfa(mfa_token: string, totp_code: string): Promise<LoginResponse> {
    const response = await apiClient.post<LoginResponse>('/api/auth/mfa/verify', {
      mfa_token,
      totp_code,
    });
    return response.data;
  },

  async setupMfa(): Promise<MfaSetupResponse> {
    const response = await apiClient.post<MfaSetupResponse>('/api/auth/mfa/setup');
    return response.data;
  },

  async enableMfa(code: string): Promise<MfaEnableResponse> {
    const response = await apiClient.post<MfaEnableResponse>('/api/auth/mfa/enable', { code });
    return response.data;
  },

  async disableMfa(password: string, totp_code: string): Promise<{ enabled: boolean; message: string }> {
    const response = await apiClient.post('/api/auth/mfa/disable', { password, totp_code });
    return response.data;
  },

  async forgotPassword(email: string): Promise<{ message: string }> {
    const response = await apiClient.post<{ message: string }>('/api/auth/forgot-password', { email });
    return response.data;
  },

  async resetPassword(token: string, new_password: string): Promise<{ message: string }> {
    const response = await apiClient.post<{ message: string }>('/api/auth/reset-password', {
      token,
      new_password,
    });
    return response.data;
  },

  async getOidcLoginUrl(): Promise<{ authorization_url: string; state: string }> {
    const response = await apiClient.get<{ authorization_url: string; state: string }>('/api/auth/oidc/login');
    return response.data;
  },

  async logout(): Promise<void> {
    try {
      await apiClient.post('/api/auth/logout');
    } catch {
      // Ignore network errors during logout
    }
  },

  async getMe(): Promise<UserProfile> {
    const response = await apiClient.get<UserProfile>('/api/auth/me');
    return response.data;
  },

  async createApiKey(
    name: string,
    role: string = 'operator',
    expiresInDays?: number,
    allowedProducts: string[] = ['*']
  ): Promise<any> {
    const response = await apiClient.post('/api/auth/api-keys', {
      name,
      role,
      expires_in_days: expiresInDays,
      allowed_products: allowedProducts,
    });
    return response.data;
  },

  async listApiKeys(): Promise<ApiKeyItem[]> {
    const response = await apiClient.get<ApiKeyItem[]>('/api/auth/api-keys');
    return response.data;
  },

  async revokeApiKey(keyId: number): Promise<void> {
    await apiClient.delete(`/api/auth/api-keys/${keyId}`);
  },
};

export default apiService;
