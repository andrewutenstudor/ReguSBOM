/**
 * ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
 * Frontend Type Definitions for ENISA Advisory 2026, BSI TR-03183-2, and CRA Art. 13.
 */

export type OverallStatus = 'PASS' | 'FAIL' | 'WARNING';

export interface CheckResult {
  name: string;
  category: string;
  passed: boolean;
  message: string;
  details?: Record<string, any>;
}

export interface FileImprint {
  sha256: string;
  sha512: string;
  file_size_mb: number;
  file_size_bytes: number;
}

export interface RootProduct {
  name: string;
  version: string;
  type?: string;
  supplier?: string;
  purl?: string | null;
  cpe?: string | null;
  serialNumber?: string;
}

export interface FormatInfo {
  format: string;
  version: string;
  display: string;
  standard: string;
  is_supported: boolean;
  regulatory_verdict: string;
}

export interface DocumentMetadata {
  author_valid: boolean;
  authors: string[];
  timestamp: string;
  timestamp_valid: boolean;
  has_lifecycle: boolean;
  lifecycle_phase: string;
  tools_valid: boolean;
  tools: string[];
  has_signature: boolean;
  signature_details: string[];
  root_product: RootProduct;
  serial_number: string;
}

export interface CraChecklistItem {
  id: string;
  title: string;
  status: 'PASS' | 'FAIL' | 'WARNING';
  passed: boolean;
  total_count: number;
  missing_count: number;
  detail: string;
}

export interface ComponentMatrixItem {
  name: string;
  version: string;
  has_version: '✓' | '✕';
  is_core: boolean;
  is_proprietary?: boolean;
  component_type?: string;
  has_id: '✓' | '✕';
  purl?: string | null;
  cpe?: string | null;
  supplier: string;
  has_supplier: '✓' | '✕';
  has_hash: '✓' | '✕';
  hashes?: string[];
  has_license: '✓' | '!' | '✕';
  license: string;
  has_dependencies: '✓' | '✕';
  bsi_properties?: {
    has_executable?: boolean;
    has_archive?: boolean;
    has_structured_metadata?: boolean;
  };
  known_unknowns?: boolean;
  is_compliant?: boolean;
}

export interface Statistics {
  components_total: number;
  proprietary_count?: number;
  third_party_count?: number;
  proprietary_with_gaps?: number;
  third_party_with_gaps?: number;
  missing_hashes_count?: number;
  non_spdx_licenses_count?: number;
  missing_licenses_count?: number;
  orphaned_count?: number;
  compliance_rate?: number;
  total_checks?: number;
  passed_checks?: number;
  failed_checks?: number;
  processing_time_seconds?: number;
  core_components_count?: number;
  third_party_components_count?: number;
}

export interface ValidationReportData {
  filename?: string;
  format: string;
  schema_version: string;
  profile?: string;
  overall_status: OverallStatus;
  overall_valid: boolean;
  processing_time: number;
  format_info?: FormatInfo;
  document_metadata?: DocumentMetadata;
  root_product?: RootProduct;
  root_product_name?: string;
  root_product_version?: string;
  serialNumber?: string;
  serial_number?: string;
  file_imprint?: FileImprint;
  cra_checklist: CraChecklistItem[];
  component_matrix: ComponentMatrixItem[];
  statistics: Statistics;
  certificate_data?: Record<string, any>;
  checks?: CheckResult[];
}

export interface ValidateResponse {
  sbom_id: number;
  report_id: number;
  filename: string;
  format: string;
  schema_version: string;
  profile?: string;
  overall_status: OverallStatus;
  overall_valid: boolean;
  processing_time: number;
  format_info: FormatInfo;
  document_metadata: DocumentMetadata;
  root_product: RootProduct;
  file_imprint: FileImprint;
  cra_checklist: CraChecklistItem[];
  component_matrix: ComponentMatrixItem[];
  statistics: Statistics;
  certificate_data: Record<string, any>;
  report_urls: {
    json: string;
    html: string;
    pdf: string;
    certificate: string;
  };
}

export interface ReportListItem {
  report_id: number;
  sbom_id: number;
  filename: string;
  format: string;
  overall_status: string;
  overall_valid: boolean;
  processing_time: number;
  validation_timestamp: string;
  statistics: Statistics;
}

export interface ReportDetail {
  report_id: number;
  sbom_id: number;
  filename: string;
  format: string;
  schema_version: string;
  overall_valid: boolean;
  overall_status: OverallStatus;
  processing_time: number;
  validation_timestamp: string;
  report_data: ValidationReportData;
}

export interface SbomListItem {
  id: number;
  filename: string;
  original_filename: string;
  file_size: number;
  sbom_format: string;
  schema_version: string;
  upload_timestamp: string;
}

export interface HealthResponse {
  status: string;
  service?: string;
  version?: string;
  timestamp: string;
}

export interface DashboardStats {
  total_validations: number;
  passed: number;
  failed: number;
  pass_rate: number;
  total_sboms: number;
  last_validation: string | null;
}

export interface ValidateOptions {
  maxSize?: number;
  skipSchema?: boolean;
  verbose?: boolean;
  profile?: string;
  autoMend?: boolean;
  proprietaryPrefix?: string;
  proprietarySupplier?: string;
}

export type CategoryType = "schema" | "metadata" | "component" | "service" | "cra" | "nis2";

export interface CategoryInfo {
  label: string;
  color: string;
  bgColor: string;
  icon: string;
}

export interface AcnValidateResponse {
  filename: string;
  acn_available: boolean;
  overall_valid: boolean;
  output_lines: string[];
  results: {
    schema_valid: boolean;
    schema_skipped: boolean;
    metadata_valid: boolean;
    components_total: number;
    valid_components: number;
    services_total: number;
    valid_services: number;
    processing_time: number;
  };
  report_path: string | null;
  error: string | null;
}

export interface ComponentViewerItem {
  index: number;
  name: string;
  version: string;
  type: string;
  supplier: string;
  licenses: string[];
  hashes_count: number;
  purl: string | null;
  cpe: string | null;
  bom_ref?: string;
  description?: string;
  is_core: boolean;
  has_id?: '✓' | '✕' | 'X' | boolean;
  has_id_symbol?: '✓' | '✕' | 'X';
  has_supplier: string | boolean;
  has_supplier_symbol?: '✓' | '✕' | 'X';
  has_version: boolean;
  has_version_symbol?: '✓' | '✕' | 'X';
  has_hash?: '✓' | '✕' | 'X' | boolean;
  has_hash_symbol?: '✓' | '✕' | 'X';
  has_hashes?: boolean;
  has_dependencies?: '✓' | '✕' | 'X' | boolean;
  has_dependencies_symbol?: '✓' | '✕' | 'X';
  has_license?: '✓' | '!' | '✕' | 'X' | string;
  has_license_symbol?: '✓' | '!' | '✕' | 'X' | string;
  has_all_desirable?: boolean;
  completeness_score: number;
  missing_desirable: string[];
  desirable_gaps?: string[];
  raw?: any;
  [key: string]: any;
}

export interface SbomViewerData {
  sbom_id: number;
  filename: string;
  format: string;
  schema_version: string;
  file_size: number;
  upload_timestamp: string | null;
  root_metadata?: any;
  statistics: any;
  components: ComponentViewerItem[];
  cra_checklist?: any[];
  component_matrix?: any[];
}

export type SystemTier = 'OS' | 'CONTAINER' | 'APPLICATION' | 'FIRMWARE';
export type LifecycleStatus = 'DRAFT' | 'VALIDATED' | 'RELEASED' | 'EOL';

export interface SBOMArtifactItem {
  id: number;
  release_id: number;
  tier: SystemTier;
  format: string;
  spec_version: string | null;
  file_path: string;
  sha256_hash: string;
  sha512_hash?: string | null;
  overall_status: OverallStatus;
  validation_report_id?: number | null;
  sbom_record_id?: number | null;
  created_at: string;
}

export interface ProductReleaseItem {
  id: number;
  product_id: number;
  version: string;
  release_date: string | null;
  lifecycle_status: LifecycleStatus;
  created_at: string;
  artifacts_count: number;
  tiers: SystemTier[];
  overall_verdict: OverallStatus | 'NO_ARTIFACTS';
  artifacts?: SBOMArtifactItem[];
}

export interface ProductItem {
  id: number;
  name: string;
  slug: string;
  description?: string | null;
  business_unit?: string | null;
  created_at: string;
  release_count: number;
  latest_release?: string | null;
  latest_status?: LifecycleStatus | null;
  latest_verdict?: OverallStatus | 'NO_RELEASES' | 'NO_ARTIFACTS' | null;
  releases?: ProductReleaseItem[];
}

export interface ComponentSearchMatch {
  product_id: number;
  product_name: string;
  product_slug: string;
  business_unit?: string | null;
  release_id: number;
  release_version: string;
  release_status: LifecycleStatus;
  tier: SystemTier;
  artifact_id: number;
  artifact_status: OverallStatus;
  validation_report_id: number | null;
  component: {
    name: string;
    version: string;
    supplier: string;
    license: string;
    purl?: string | null;
    cpe?: string | null;
    is_proprietary: boolean;
    has_hash: string;
    has_license: string;
    has_dependencies: string;
  };
}

export interface ComponentSearchResult {
  query: {
    name: string;
    version?: string | null;
  };
  total_matches: number;
  matches: ComponentSearchMatch[];
}

export interface LicenseInfo {
  valid: boolean;
  status: 'ACTIVE' | 'LICENSE_EXPIRED' | 'LICENSE_NOT_FOUND' | 'INVALID_SIGNATURE' | string;
  customer_id: string;
  customer_name: string;
  max_products: number;
  expiry_date: string | null;
  days_remaining: number;
  airgap_authorized: boolean;
  tier: string;
  features?: string[];
  error?: string | null;
}

export interface DiffCandidate {
  id: number;
  type: 'artifact' | 'report' | 'sbom_record';
  category: string;
  label: string;
  product_name?: string;
  release_version?: string;
  tier?: string;
  status?: string;
  created_at?: string;
}

export interface DiffSummary {
  base_total_components: number;
  target_total_components: number;
  net_component_delta: number;
  added_count: number;
  removed_count: number;
  modified_count: number;
  unchanged_count: number;
  license_drift_count: number;
  hash_drop_count: number;
  supplier_drift_count: number;
  version_drift_count: number;
  edges_added_count: number;
  edges_removed_count: number;
  posture_verdict: 'IMPROVED' | 'DEGRADED' | 'STABLE';
  posture_message: string;
}

export interface ModifiedComponentItem {
  name: string;
  drift_type: 'MODIFIED';
  base: {
    version: string;
    license: string;
    supplier: string;
    has_strong_hash: boolean;
    purl?: string | null;
  };
  target: {
    version: string;
    license: string;
    supplier: string;
    has_strong_hash: boolean;
    purl?: string | null;
  };
  drift: {
    version_changed: boolean;
    license_changed: boolean;
    supplier_changed: boolean;
    hash_dropped: boolean;
    hash_added: boolean;
  };
}

export interface DiffResult {
  base: Record<string, any>;
  target: Record<string, any>;
  summary: DiffSummary;
  added_components: Array<{
    name: string;
    version: string;
    license: string;
    supplier: string;
    purl?: string | null;
    has_strong_hash: boolean;
    drift_type: 'ADDED';
  }>;
  removed_components: Array<{
    name: string;
    version: string;
    license: string;
    supplier: string;
    purl?: string | null;
    has_strong_hash: boolean;
    drift_type: 'REMOVED';
  }>;
  modified_components: ModifiedComponentItem[];
  dependency_graph_delta: {
    added_edges: Array<{ source: string; target: string }>;
    removed_edges: Array<{ source: string; target: string }>;
    total_base_edges: number;
    total_target_edges: number;
  };
}

export type UserRole = 'admin' | 'operator' | 'auditor';

export interface UserProfile {
  id: number;
  username: string;
  email: string | null;
  full_name: string;
  role: UserRole;
  is_ldap_user: boolean;
  is_oidc_user?: boolean;
  mfa_enabled?: boolean;
  is_active: boolean;
  created_at: string | null;
  last_login: string | null;
}

export interface LoginResponse {
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  user?: UserProfile;
  mfa_required?: boolean;
  mfa_token?: string;
  username?: string;
}

export interface ApiKeyItem {
  id: number;
  name: string;
  key_prefix: string;
  role: UserRole;
  user_id: number | null;
  allowed_products?: string[];
  expires_at: string | null;
  created_at: string | null;
  last_used_at: string | null;
  is_expired: boolean;
}

export interface AuthProvidersResponse {
  ldap_enabled: boolean;
  oidc_enabled: boolean;
  mfa_supported: boolean;
}

export interface MfaSetupResponse {
  secret: string;
  otpauth_uri: string;
  qr_code: string;
  instructions: string;
}

export interface MfaEnableResponse {
  enabled: boolean;
  recovery_codes: string[];
  message: string;
}




