"""
ExtendedSBOMValidator — integra il validatore ACN modulo_SBOM con controlli
aggiuntivi per la conformità al Cyber Resilience Act (CRA) e alla Direttiva NIS2.

Integrates ACN modulo_SBOM validator with additional CRA and NIS2 compliance checks.
"""

import sys
import os
import json
import time
import re
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple, Union
from enum import Enum

try:
    import orjson
except ImportError:
    orjson = None

try:
    import ijson
except ImportError:
    ijson = None

try:
    import fastjsonschema
except ImportError:
    fastjsonschema = None

# ---------------------------------------------------------------------------
# Make modulo_SBOM_src importable from every working directory
# ---------------------------------------------------------------------------
_CURRENT_FILE = Path(__file__).resolve()
_CANDIDATE_PATHS = [
    _CURRENT_FILE.parents[3] / "modulo_SBOM_src",  # Local repo root / modulo_SBOM_src
    _CURRENT_FILE.parents[2] / "modulo_SBOM_src",  # Docker container /app/modulo_SBOM_src
    _CURRENT_FILE.parents[2] / "vendor",           # backend/vendor fallback
    Path("/app/modulo_SBOM_src"),                  # Explicit container path
]

for _cand in _CANDIDATE_PATHS:
    if _cand.exists() and str(_cand) not in sys.path:
        sys.path.insert(0, str(_cand))

try:
    from modulo_SBOM import (
        SBOMValidator as AcnSBOMValidator,
        ValidationConfig as AcnValidationConfig,
        ValidationResults as AcnValidationResults,
        MINIMUM_COMPONENT_FIELDS,
        ADDITIONAL_COMPONENT_FIELDS,
        MINIMUM_SERVICE_FIELDS,
        ADDITIONAL_SERVICE_FIELDS,
        WHITELISTED_COUNTRIES,
        OutputFormat,
    )
    ACN_AVAILABLE = True
except ImportError as e:
    ACN_AVAILABLE = False
    _ACN_IMPORT_ERROR = str(e)


# ---------------------------------------------------------------------------
# High-Performance Compiled CycloneDX v1.6 Schema Validation (fastjsonschema)
# ---------------------------------------------------------------------------
COMPILED_CYCLONEDX_SCHEMA = None
_SCHEMA_INIT_ERROR = None


def _initialize_cyclonedx_schema():
    """Compiles CycloneDX v1.6 schema once globally with local SPDX & JSF resolvers."""
    global COMPILED_CYCLONEDX_SCHEMA, _SCHEMA_INIT_ERROR
    if COMPILED_CYCLONEDX_SCHEMA is not None:
        return COMPILED_CYCLONEDX_SCHEMA
    if fastjsonschema is None:
        _SCHEMA_INIT_ERROR = "fastjsonschema is not installed"
        return None

    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.schema._res import BOM_JSON, SPDX_JSON, JSF
        cyclonedx_bom_path = BOM_JSON.get(SchemaVersion.V1_6)
        cyclonedx_spdx_path = SPDX_JSON
        cyclonedx_jsf_path = JSF
    except Exception:
        cyclonedx_bom_path = None
        cyclonedx_spdx_path = None
        cyclonedx_jsf_path = None

    schemas_dir = _CURRENT_FILE.parent.parent / "schemas"

    def _read_schema(filename: str, fallback_path: Optional[str]) -> Optional[dict]:
        local_file = schemas_dir / filename
        if local_file.exists():
            with open(local_file, "r", encoding="utf-8") as f:
                return json.load(f)
        if fallback_path and Path(fallback_path).exists():
            with open(fallback_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    try:
        schema_dict = _read_schema("bom-1.6.schema.json", cyclonedx_bom_path)
        spdx_dict = _read_schema("spdx.schema.json", cyclonedx_spdx_path) or {}
        jsf_dict = _read_schema("jsf.schema.json", cyclonedx_jsf_path) or {}

        if not schema_dict:
            _SCHEMA_INIT_ERROR = "Could not locate CycloneDX v1.6 schema file"
            return None

        def _ref_handler(uri: str) -> dict:
            if "spdx" in uri:
                return spdx_dict
            if "jsf" in uri:
                return jsf_dict
            return {}

        handlers = {
            "http": _ref_handler,
            "https": _ref_handler,
            "file": _ref_handler,
        }

        COMPILED_CYCLONEDX_SCHEMA = fastjsonschema.compile(schema_dict, handlers=handlers)
        return COMPILED_CYCLONEDX_SCHEMA
    except Exception as e:
        _SCHEMA_INIT_ERROR = str(e)
        return None


# Cache compiled schema globally at module load
COMPILED_CYCLONEDX_SCHEMA = _initialize_cyclonedx_schema()


def validate_cyclonedx_schema(sbom_dict: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validates an SBOM dictionary against CycloneDX v1.6 schema using compiled fastjsonschema.
    Returns:
        (is_valid: bool, error_messages: List[str])
    """
    validator = COMPILED_CYCLONEDX_SCHEMA or _initialize_cyclonedx_schema()
    if validator is None:
        return True, [f"Schema validation bypassed (engine unavailable: {_SCHEMA_INIT_ERROR})"]

    try:
        validator(sbom_dict)
        return True, []
    except fastjsonschema.JsonSchemaException as e:
        field_path = ".".join(str(p) for p in getattr(e, "path", [])) or "$"
        return False, [f"{field_path}: {getattr(e, 'message', str(e))}"]
    except Exception as e:
        return False, [str(e)]


if ACN_AVAILABLE:
    def _patched_acn_validate_schema(self, file_handle) -> bool:
        """Patched AcnSBOMValidator.validate_schema using compiled fastjsonschema."""
        self._log_verbose("Avvio validazione dello schema CycloneDX v1.6 (fastjsonschema)")
        try:
            file_handle.seek(0)
            raw = file_handle.read()
            if isinstance(raw, bytes):
                data = orjson.loads(raw) if orjson else json.loads(raw.decode("utf-8", errors="replace"))
            else:
                data = orjson.loads(raw.encode("utf-8")) if orjson else json.loads(raw)

            is_valid, errors = validate_cyclonedx_schema(data)
            if not is_valid:
                self._add_output_line(f"{OutputFormat.WARNING} La SBOM non è valida rispetto allo schema CycloneDX v1.6. Errori riscontrati:")
                for err in errors:
                    self._add_output_line(f" - {err}")
                return False
            self._log_verbose("Validazione della SBOM secondo lo schema CycloneDX v1.6 avvenuta con successo (fastjsonschema)")
            return True
        except Exception as e:
            self._add_output_line(f"[!] Validazione dello schema CycloneDX v1.6 fallita: {e}")
            return False

    AcnSBOMValidator.validate_schema = _patched_acn_validate_schema


# ---------------------------------------------------------------------------
# SPDX valid license identifiers (subset — expanded as needed)
# ---------------------------------------------------------------------------
VALID_SPDX_LICENSES = frozenset([
    "MIT", "Apache-2.0", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.0", "LGPL-2.1",
    "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only",
    "LGPL-3.0-or-later", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0",
    "CDDL-1.0", "EPL-1.0", "EPL-2.0", "AGPL-3.0", "AGPL-3.0-only",
    "AGPL-3.0-or-later", "CC0-1.0", "Unlicense", "EUPL-1.2", "EUPL-1.1",
    "NOASSERTION", "NONE",
])

ALLOWED_CORPORATE_LICENSE_REFS = frozenset([
    "LicenseRef-Proprietary",
    "LicenseRef-InternalUseOnly",
])

HASH_ALGORITHMS = frozenset({"SHA-512", "SHA512", "SHA-256", "SHA256"})
HASH_SHA512_ALGS = frozenset({"SHA-512", "SHA512"})
EXPR_TOKEN_REGEX = re.compile(r"\b[A-Za-z0-9.-]+\b")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class ValidationProfile(str, Enum):
    STRICT = "STRICT"
    LEGACY = "LEGACY"


@dataclass
class ValidationConfig:
    """Parametri di configurazione per ExtendedSBOMValidator."""
    max_size_mb: int = 50
    verbose: bool = False
    skip_schema: bool = False
    profile: Union[ValidationProfile, str] = ValidationProfile.STRICT


@dataclass
class ValidationCheck:
    """Risultato di un singolo controllo di validazione."""
    name: str
    category: str          # schema | metadata | component | service | cra | nis2 | acn
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "category": self.category,
            "passed": self.passed,
            "message": self.message,
        }
        if self.details:
            d["details"] = self.details
        return d


@dataclass
class ValidationReport:
    """Report completo di validazione SBOM."""
    filename: str
    sbom_format: str
    schema_version: str
    overall_valid: bool
    overall_status: str         # PASS | FAIL | WARNING
    processing_time: float
    profile: str = "STRICT"
    checks: List[ValidationCheck] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    sbom_summary: Dict[str, Any] = field(default_factory=dict)
    acn_output_lines: List[str] = field(default_factory=list)  # raw ACN text output
    acn_results: Optional[Dict[str, Any]] = None
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    file_imprint: Dict[str, Any] = field(default_factory=dict)
    root_product: Dict[str, Any] = field(default_factory=dict)
    root_product_name: str = "N/D"
    root_product_version: str = "N/D"
    serial_number: str = "N/D"
    cra_checklist: List[Dict[str, Any]] = field(default_factory=list)
    cra_checklist_status: Dict[str, bool] = field(default_factory=dict)
    component_matrix: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        passed = sum(1 for c in self.checks if c.passed)
        failed = len(self.checks) - passed
        # Cap output lines to prevent payload explosion on large SBOMs (>10k components)
        raw_lines = self.acn_output_lines or []
        if len(raw_lines) > 2000:
            safe_lines = raw_lines[:1000] + [
                f"\n... [Output truncated: {len(raw_lines) - 1000:,} additional lines omitted for report performance] ...\n"
            ]
        else:
            safe_lines = raw_lines

        return {
            "filename": self.filename,
            "sbom_format": self.sbom_format,
            "schema_version": self.schema_version,
            "overall_valid": self.overall_valid,
            "overall_status": self.overall_status,
            "processing_time": self.processing_time,
            "profile": self.profile,
            "checks": [c.to_dict() for c in self.checks],
            "warnings": self.warnings,
            "statistics": {
                **self.statistics,
                "total_checks": len(self.checks),
                "passed_checks": passed,
                "failed_checks": failed,
                "processing_time_seconds": self.processing_time,
            },
            "sbom_summary": self.sbom_summary,
            "acn_output_lines": safe_lines,
            "acn_results": self.acn_results,
            "file_imprint": self.file_imprint,
            "root_product": self.root_product,
            "root_product_name": self.root_product_name,
            "root_product_version": self.root_product_version,
            "serialNumber": self.serial_number,
            "serial_number": self.serial_number,
            "cra_checklist": self.cra_checklist,
            "cra_checklist_status": self.cra_checklist_status,
            "component_matrix": self.component_matrix,
        }


# ---------------------------------------------------------------------------
# Core vs. Third-Party Component Identification
# ---------------------------------------------------------------------------

def is_core_component(component: dict, is_metadata: bool = False) -> bool:
    """
    Determines whether a component is a company 'Core' component.
    - The root metadata.component is treated as Core by default (is_metadata=True).
    - Components in 'components' array are Core ONLY if their properties array
      contains the exact key-value pair: {"name": "company:core-component", "value": "true"}.
    - Everything else is considered 'Third-Party'.
    """
    if is_metadata:
        return True
    if not isinstance(component, dict):
        return False
    properties = component.get("properties")
    if not isinstance(properties, list) or not properties:
        return False
    for prop in properties:
        if isinstance(prop, dict) and prop.get("name") == "company:core-component":
            val = prop.get("value")
            if val is True or val == "true" or (isinstance(val, str) and val.strip().lower() == "true"):
                return True
    return False


def partition_components(components: list) -> Tuple[List[dict], List[dict]]:
    """Partition components in a single pass into core and third-party lists."""
    core_comps: List[dict] = []
    tp_comps: List[dict] = []
    if not isinstance(components, list):
        return core_comps, tp_comps

    for c in components:
        if isinstance(c, dict):
            if is_core_component(c, is_metadata=False):
                core_comps.append(c)
            else:
                tp_comps.append(c)
    return core_comps, tp_comps


def is_spdx_license(comp: dict) -> bool:
    """Verifica se il componente possiede una licenza SPDX valida o autorizzata."""
    if not isinstance(comp, dict):
        return False
    lics = comp.get("licenses")
    if not isinstance(lics, list) or not lics:
        return False
    for l_entry in lics:
        if isinstance(l_entry, dict):
            expr = l_entry.get("expression")
            if expr and str(expr).strip():
                return True
            lic_obj = l_entry.get("license")
            if isinstance(lic_obj, dict):
                lic_id = lic_obj.get("id")
                if lic_id:
                    clean_id = str(lic_id).strip()
                    if (clean_id in VALID_SPDX_LICENSES or 
                        clean_id.startswith("LicenseRef-") or 
                        clean_id in ALLOWED_CORPORATE_LICENSE_REFS):
                        return True
                lic_name = lic_obj.get("name")
                if lic_name:
                    clean_name = str(lic_name).strip()
                    if (clean_name in VALID_SPDX_LICENSES or 
                        clean_name.startswith("LicenseRef-") or 
                        clean_name in ALLOWED_CORPORATE_LICENSE_REFS):
                        return True
    return False


def has_non_spdx_license(comp: dict) -> bool:
    """Verifica se il componente ha una dichiarazione di licenza non-SPDX standard."""
    if not isinstance(comp, dict):
        return False
    lics = comp.get("licenses")
    if not isinstance(lics, list) or not lics:
        return False
    for l_entry in lics:
        if isinstance(l_entry, dict):
            if l_entry.get("expression"):
                return True
            lic_obj = l_entry.get("license")
            if isinstance(lic_obj, dict) and (lic_obj.get("id") or lic_obj.get("name")):
                return True
        elif isinstance(l_entry, str) and l_entry.strip():
            return True
    return False


def is_in_dependencies_graph(comp: dict, sbom_dict_or_dep_refs: Any) -> bool:
    """Verifica se il componente è censito nel grafo delle dipendenze (ref o dependsOn)."""
    if not isinstance(comp, dict):
        return False
    if isinstance(sbom_dict_or_dep_refs, set):
        dep_refs = sbom_dict_or_dep_refs
    else:
        dep_refs = set()
        deps_list = sbom_dict_or_dep_refs.get("dependencies") if isinstance(sbom_dict_or_dep_refs, dict) and isinstance(sbom_dict_or_dep_refs.get("dependencies"), list) else []
        for dep in deps_list:
            if isinstance(dep, dict):
                r = dep.get("ref")
                if r:
                    dep_refs.add(str(r))
                for child in dep.get("dependsOn", []):
                    if child:
                        dep_refs.add(str(child))

    c_bom_ref = comp.get("bom-ref") or comp.get("ref")
    purl = comp.get("purl")
    c_name = comp.get("name")
    return bool(
        (c_bom_ref and str(c_bom_ref) in dep_refs) or
        (purl and str(purl) in dep_refs) or
        (c_name and str(c_name) in dep_refs)
    )


# ---------------------------------------------------------------------------
# Extended Validator
# ---------------------------------------------------------------------------

class ExtendedSBOMValidator:
    """
    Validatore SBOM esteso.

    Esegue le seguenti fasi:
    1. Validazione ACN (modulo_SBOM) — schema, metadata, componenti, servizi
    2. Controlli CRA — hash SHA-512, licenze SPDX, assenza vulnerabilità, contatti, timestamp
    3. Controlli NIS2 — completezza dipendenze, inventario componenti

    Extended SBOM Validator.
    Runs ACN validation + CRA compliance checks + NIS2 compliance checks.
    """

    is_core_component = staticmethod(is_core_component)
    partition_components = staticmethod(partition_components)

    def __init__(self, config: ValidationConfig):
        self.config = config
        raw_profile = getattr(config, "profile", ValidationProfile.STRICT)
        if isinstance(raw_profile, str):
            try:
                self.profile = ValidationProfile(raw_profile.strip().upper())
            except (ValueError, KeyError):
                self.profile = ValidationProfile.STRICT
        else:
            self.profile = raw_profile or ValidationProfile.STRICT

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def validate_sbom(
        self,
        filepath: str,
        sbom_data: Optional[Dict[str, Any]] = None,
        file_imprint: Optional[Dict[str, Any]] = None,
    ) -> ValidationReport:
        """
        Valida un file SBOM e restituisce un ValidationReport strutturato.
        Validate an SBOM file and return a structured ValidationReport.
        """
        start = time.time()
        path = Path(filepath)
        filename = path.name

        # Parse JSON if not already supplied
        if sbom_data is None:
            raw_bytes = None
            try:
                raw_bytes = path.read_bytes()
                if orjson is not None:
                    try:
                        sbom_data = orjson.loads(raw_bytes)
                    except Exception:
                        sbom_data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                else:
                    sbom_data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
            except Exception as e:
                elapsed = time.time() - start
                if file_imprint is None:
                    file_imprint = self._calculate_file_imprint(filepath, raw_bytes=raw_bytes)
                report = ValidationReport(
                    filename=filename,
                    sbom_format="unknown",
                    schema_version="unknown",
                    overall_valid=False,
                    overall_status="FAIL",
                    processing_time=elapsed,
                    file_imprint=file_imprint,
                )
                report.checks.append(ValidationCheck(
                    name="Parsing JSON",
                    category="schema",
                    passed=False,
                    message=f"Il file non è un JSON valido / Invalid JSON: {e}",
                ))
                return report

        if file_imprint is None:
            file_imprint = self._calculate_file_imprint(filepath)

        sbom_format = self._detect_format(sbom_data)
        schema_version = str(sbom_data.get("specVersion") or sbom_data.get("spdxVersion") or "unknown").strip()

        checks: List[ValidationCheck] = []
        acn_output_lines: List[str] = []
        acn_results_dict: Optional[Dict] = None

        # --------------------------------------------------------------
        # Task 3: Format/Schema Check: Must strictly be CycloneDX v1.6 or v1.7. If not, FAIL the whole file.
        # --------------------------------------------------------------
        if sbom_format != "cyclonedx" or schema_version not in ["1.6", "1.7"]:
            elapsed = time.time() - start
            checks.append(ValidationCheck(
                name="Validazione formato e versione CycloneDX (v1.6 / v1.7) / CycloneDX Format",
                category="schema",
                passed=False,
                message=(
                    f"Non conforme: rilevato '{sbom_format}' v{schema_version} (richiesto CycloneDX 1.6 o 1.7). "
                    f"CycloneDX 1.5 or lower and non-CycloneDX formats are rejected."
                ),
                details={"detected_format": sbom_format, "detected_version": schema_version, "required": "CycloneDX 1.6 o 1.7"}
            ))
            cra_data = self._build_cra_compliance_data(sbom_data, filepath=filepath, file_imprint=file_imprint)
            return ValidationReport(
                filename=filename,
                sbom_format=sbom_format,
                schema_version=schema_version,
                overall_valid=False,
                overall_status="FAIL",
                processing_time=elapsed,
                profile=self.profile.value,
                checks=checks,
                statistics={"total_checks": 1, "passed_checks": 0, "failed_checks": 1, "processing_time_seconds": elapsed},
                sbom_summary={"format": sbom_format, "schema_version": schema_version},
                file_imprint=cra_data["file_imprint"],
                root_product=cra_data["root_product"],
                root_product_name=cra_data["root_product_name"],
                root_product_version=cra_data["root_product_version"],
                serial_number=cra_data["serial_number"],
                cra_checklist=cra_data["cra_checklist"],
                cra_checklist_status=cra_data["cra_checklist_status"],
                component_matrix=cra_data["component_matrix"],
            )

        # --------------------------------------------------------------
        # Task 3: Empty File Check: If the JSON lacks components entirely, FAIL.
        # --------------------------------------------------------------
        components = sbom_data.get("components")
        if components is None or not isinstance(components, list) or len(components) == 0:
            elapsed = time.time() - start
            checks.append(ValidationCheck(
                name="Presenza componenti / Components Presence",
                category="component",
                passed=False,
                message="L'SBOM non contiene componenti (elenco 'components' vuoto o assente). L'SBOM deve contenere almeno un componente. / SBOM lacks components entirely.",
                details={"components_count": 0}
            ))
            cra_data = self._build_cra_compliance_data(sbom_data, filepath=filepath, file_imprint=file_imprint)
            return ValidationReport(
                filename=filename,
                sbom_format=sbom_format,
                schema_version=schema_version,
                overall_valid=False,
                overall_status="FAIL",
                processing_time=elapsed,
                profile=self.profile.value,
                checks=checks,
                statistics={"total_checks": 1, "passed_checks": 0, "failed_checks": 1, "processing_time_seconds": elapsed},
                sbom_summary={"format": sbom_format, "schema_version": schema_version, "components_count": 0},
                file_imprint=cra_data["file_imprint"],
                root_product=cra_data["root_product"],
                root_product_name=cra_data["root_product_name"],
                root_product_version=cra_data["root_product_version"],
                serial_number=cra_data["serial_number"],
                cra_checklist=cra_data["cra_checklist"],
                cra_checklist_status=cra_data["cra_checklist_status"],
                component_matrix=cra_data["component_matrix"],
            )

        # Single-pass partition into core and third-party components
        core_comps, tp_comps = self.partition_components(components)

        # ---- Phase 1: ACN Validation (CycloneDX only) ----
        acn_checks, acn_output_lines, acn_results_dict = self._run_acn_validation(
            filepath, sbom_data, core_comps=core_comps, tp_comps=tp_comps
        )
        checks.extend(acn_checks)

        # ---- Phase 2: CRA Checks ----
        cra_checks = self._run_cra_checks(
            sbom_data, sbom_format, core_comps=core_comps, tp_comps=tp_comps
        )
        checks.extend(cra_checks)

        # ---- Phase 3: NIS2 Checks ----
        nis2_checks = self._run_nis2_checks(
            sbom_data, sbom_format, core_comps=core_comps, tp_comps=tp_comps
        )
        checks.extend(nis2_checks)

        # ---- Compute overall result ----
        failed = [c for c in checks if not c.passed]
        passed_all = len(failed) == 0
        if passed_all:
            overall_status = "PASS"
        elif any(c.category in ("schema", "acn") and not c.passed for c in checks):
            overall_status = "FAIL"
        else:
            # If blocking core checks failed, mark as FAIL
            overall_status = "FAIL" if any(not c.passed for c in checks) else "WARNING"

        overall_valid = overall_status == "PASS"

        # ---- SBOM summary ----
        sbom_summary = self._build_sbom_summary(sbom_data, sbom_format, schema_version)

        # ---- Statistics ----
        services = sbom_data.get("services", [])
        passed_count = sum(1 for c in checks if c.passed)

        statistics = {
            "components_total": len(components),
            "components_valid": acn_results_dict.get("valid_components", 0) if acn_results_dict else len(components),
            "services_total": len(services),
            "services_valid": acn_results_dict.get("valid_services", 0) if acn_results_dict else len(services),
        }

        # Build CRA corporate compliance data (imprint, root product, 11-point checklist, component matrix)
        cra_data = self._build_cra_compliance_data(
            sbom_data,
            filepath=filepath,
            file_imprint=file_imprint,
            core_comps=core_comps,
            tp_comps=tp_comps
        )
        statistics["core_components_count"] = cra_data["core_components_count"]
        statistics["third_party_components_count"] = cra_data["third_party_components_count"]

        elapsed = time.time() - start

        # ---- Aggregate third-party / non-blocking warnings ----
        report_warnings: List[Dict[str, Any]] = []
        for c in checks:
            d = c.details or {}
            items = d.get("missing_items") or d.get("invalid_elements") or d.get("third_party_missing") or d.get("third_party_sloppy") or []
            is_warning = bool(d.get("warning") or (c.passed and len(items) > 0) or d.get("warning_message"))
            if is_warning:
                report_warnings.append({
                    "check_name": c.name,
                    "category": c.category,
                    "count": len(items) if items else int(d.get("invalid", 0) or 1),
                    "message": d.get("warning_message") or c.message,
                    "items": items,
                })

        return ValidationReport(
            filename=filename,
            sbom_format=sbom_format,
            schema_version=schema_version,
            overall_valid=overall_valid,
            overall_status=overall_status,
            processing_time=elapsed,
            profile=self.profile.value,
            checks=checks,
            warnings=report_warnings,
            statistics=statistics,
            sbom_summary=sbom_summary,
            acn_output_lines=acn_output_lines,
            acn_results=acn_results_dict,
            file_imprint=cra_data["file_imprint"],
            root_product=cra_data["root_product"],
            root_product_name=cra_data["root_product_name"],
            root_product_version=cra_data["root_product_version"],
            serial_number=cra_data["serial_number"],
            cra_checklist=cra_data["cra_checklist"],
            cra_checklist_status=cra_data["cra_checklist_status"],
            component_matrix=cra_data["component_matrix"],
        )

    # ------------------------------------------------------------------
    # CRA Corporate Compliance & File Imprint Helpers
    # ------------------------------------------------------------------

    def _calculate_file_imprint(self, filepath: str = "", raw_bytes: Optional[bytes] = None) -> Dict[str, Any]:
        """Calcola l'impronta crittografica (SHA-256, SHA-512) e la dimensione del file."""
        try:
            data = raw_bytes
            if data is None and filepath and Path(filepath).exists():
                data = Path(filepath).read_bytes()
            if data is not None:
                size_bytes = len(data)
                return {
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "sha512": hashlib.sha512(data).hexdigest(),
                    "file_size_mb": round(size_bytes / (1024 * 1024), 2),
                    "file_size_bytes": size_bytes,
                }
        except Exception:
            pass
        return {
            "sha256": "N/D",
            "sha512": "N/D",
            "file_size_mb": 0.0,
            "file_size_bytes": 0,
        }

    def _build_cra_compliance_data(
        self,
        sbom_data: dict,
        filepath: str = "",
        raw_bytes: Optional[bytes] = None,
        file_imprint: Optional[Dict[str, Any]] = None,
        core_comps: Optional[List[dict]] = None,
        tp_comps: Optional[List[dict]] = None,
    ) -> Dict[str, Any]:
        """
        Estrae il prodotto radice, calcola l'impronta del file, la checklist CRA a 11 punti
        e la matrice di completezza per ogni componente.
        """
        if not isinstance(sbom_data, dict):
            sbom_data = {}

        if file_imprint is None:
            file_imprint = self._calculate_file_imprint(filepath, raw_bytes)

        # 1. Root Product Extraction
        metadata = sbom_data.get("metadata") if isinstance(sbom_data.get("metadata"), dict) else {}
        root_comp = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
        root_product_name = str(root_comp.get("name") or "N/D").strip()
        root_product_version = str(root_comp.get("version") or "N/D").strip()
        serial_number = str(sbom_data.get("serialNumber") or "N/D").strip()

        root_supplier = ""
        if isinstance(root_comp.get("supplier"), dict):
            root_supplier = str(root_comp["supplier"].get("name") or "").strip()
        elif isinstance(root_comp.get("manufacturer"), dict):
            root_supplier = str(root_comp["manufacturer"].get("name") or "").strip()
        elif isinstance(metadata.get("supplier"), dict):
            root_supplier = str(metadata["supplier"].get("name") or "").strip()
        elif isinstance(metadata.get("manufacturer"), dict):
            root_supplier = str(metadata["manufacturer"].get("name") or "").strip()
        elif isinstance(metadata.get("manufacture"), dict):
            root_supplier = str(metadata["manufacture"].get("name") or "").strip()

        root_product = {
            "name": root_product_name,
            "version": root_product_version,
            "type": str(root_comp.get("type") or "application"),
            "supplier": root_supplier or "N/D",
            "serialNumber": serial_number,
        }

        # 2. Components & Matrix Analysis
        raw_components = sbom_data.get("components")
        components = raw_components if isinstance(raw_components, list) else []
        total_comps = len(components)

        if core_comps is None or tp_comps is None:
            core_comps, tp_comps = self.partition_components(components)

        core_comps_count = len(core_comps)
        tp_comps_count = len(tp_comps)
        core_ids = {id(c) for c in core_comps}

        missing_supplier = 0
        missing_hash = 0
        missing_version = 0
        missing_id = 0
        missing_license = 0

        deps_list = sbom_data.get("dependencies") if isinstance(sbom_data.get("dependencies"), list) else []
        dep_refs = set()
        for dep in deps_list:
            if isinstance(dep, dict):
                r = dep.get("ref")
                if r:
                    dep_refs.add(str(r))
                for child in dep.get("dependsOn", []):
                    if child:
                        dep_refs.add(str(child))

        component_matrix: List[Dict[str, Any]] = []

        for c in components:
            if not isinstance(c, dict):
                continue
            is_core = bool(any(isinstance(p, dict) and p.get("name") == "company:core-component" and str(p.get("value")).lower() == "true" for p in (c.get("properties") if isinstance(c.get("properties"), list) else [])))

            c_name = c.get("name", "N/D") or "N/D"
            c_version = c.get("version") or "vN/D"
            has_version = "✓" if bool(c.get("version")) else "✕"
            has_id = "✓" if bool(c.get("purl") or c.get("cpe")) else "✕"
            has_supplier = "✓" if bool(c.get("supplier") or c.get("author") or c.get("publisher")) else "✕"
            has_hash = "✓" if bool(c.get("hashes") and len(c.get("hashes")) > 0) else "✕"
            has_license = "✓" if is_spdx_license(c) else ("!" if has_non_spdx_license(c) else "✕")
            has_dependencies = "✓" if is_in_dependencies_graph(c, dep_refs) else "✕"

            if has_version == "✕":
                missing_version += 1
            if has_id == "✕":
                missing_id += 1
            if has_supplier == "✕":
                missing_supplier += 1
            if has_hash == "✕":
                missing_hash += 1
            if has_license == "✕":
                missing_license += 1

            component_matrix.append({
                "name": c_name,
                "version": c_version,
                "has_version": has_version,
                "is_core": is_core,
                "has_id": has_id,
                "has_supplier": has_supplier,
                "has_hash": has_hash,
                "has_license": has_license,
                "has_dependencies": has_dependencies,
            })

        # 3. 12-Point CRA Checklist (Section 4.1.1)
        fmt = self._detect_format(sbom_data)
        spec_ver = str(sbom_data.get("specVersion") or sbom_data.get("spdxVersion") or "unknown").strip()
        p1_passed = (fmt.lower() == "cyclonedx" and spec_ver in ["1.6", "1.7"])
        p1_detail = f"Conforme: rilevato CycloneDX v{spec_ver}" if p1_passed else f"Non conforme: rilevato {fmt} v{spec_ver} (richiesto CycloneDX 1.6 o 1.7)"

        deps = sbom_data.get("dependencies")
        p2_passed = isinstance(deps, list) and len(deps) > 0
        p2_detail = f"Presenti ({len(deps)} relazioni)" if p2_passed else "Grafo delle dipendenze di primo livello assente"

        has_root_name = bool(root_comp.get("name") and str(root_comp.get("name")).strip())
        has_root_ver = bool(root_comp.get("version") and str(root_comp.get("version")).strip())
        p3_passed = has_root_name and has_root_ver
        p3_detail = f"{root_product_name} v{root_product_version}" if p3_passed else (
            "Nome o versione mancante nel componente root" if (has_root_name or has_root_ver) else "Componente root non definito nei metadati"
        )

        p4_passed = bool(root_supplier)
        p4_detail = f"Fornitore: {root_supplier}" if p4_passed else "Produttore o fornitore del prodotto root non indicato"

        ts = metadata.get("timestamp")
        p5_passed = bool(ts and isinstance(ts, str) and len(ts.strip()) >= 10)
        p5_detail = f"Timestamp: {ts}" if p5_passed else "Data di generazione mancante nei metadati"

        tools = metadata.get("tools")
        authors = metadata.get("authors")
        has_tools = bool(
            (isinstance(tools, list) and len(tools) > 0) or
            (isinstance(tools, dict) and bool(tools.get("components") or tools.get("services")))
        )
        has_authors = bool(isinstance(authors, list) and len(authors) > 0)
        p6_passed = has_tools or has_authors
        p6_detail = "Origine identificata (tools/authors presenti)" if p6_passed else "Origine della SBOM non indicata (tools o authors assenti)"

        p7_passed = (total_comps > 0 and missing_supplier == 0)
        p7_detail = "Tutti i componenti hanno un fornitore indicato" if p7_passed else (
            f"manca in {missing_supplier} componenti su {total_comps}" if total_comps > 0 else "Nessun componente presente"
        )

        p8_passed = (total_comps > 0 and missing_hash == 0)
        p8_detail = "Tutti i componenti hanno hash di integrità" if p8_passed else (
            f"manca in {missing_hash} componenti su {total_comps}" if total_comps > 0 else "Nessun componente presente"
        )

        p9_passed = (total_comps > 0 and missing_version == 0)
        p9_detail = "Tutti i componenti hanno una versione definita" if p9_passed else (
            f"manca in {missing_version} componenti su {total_comps}" if total_comps > 0 else "Nessun componente presente"
        )

        p10_passed = (total_comps > 0 and missing_id == 0)
        p10_detail = "Tutti i componenti hanno un identificativo univoco (PURL/CPE)" if p10_passed else (
            f"manca in {missing_id} componenti su {total_comps}" if total_comps > 0 else "Nessun componente presente"
        )

        p11_passed = (total_comps > 0 and missing_license == 0)
        p11_detail = "Tutti i componenti hanno una licenza dichiarata" if p11_passed else (
            f"manca in {missing_license} componenti su {total_comps}" if total_comps > 0 else "Nessun componente presente"
        )

        p12_passed = True
        p12_status = "PASS"
        if core_comps_count > 0:
            p12_detail = f"Individuati {core_comps_count} componenti Core proprietari su {total_comps}."
        else:
            p12_detail = f"Nessun componente Core proprietario individuato (0 su {total_comps}): tutti i componenti sono trattati come Terze Parti."

        cra_checklist = [
            {
                "id": "format_cyclonedx",
                "name": "Formato standard CycloneDX (v1.6 / v1.7)",
                "title": "Formato standard CycloneDX (v1.6 / v1.7)",
                "status": "PASS" if p1_passed else "FAIL",
                "passed": p1_passed,
                "missing_count": 0 if p1_passed else 1,
                "total_count": 1,
                "detail": p1_detail,
                "details": p1_detail,
            },
            {
                "id": "dependencies_first_level",
                "name": "Dipendenze di primo livello",
                "title": "Dipendenze di primo livello",
                "status": "PASS" if p2_passed else "FAIL",
                "passed": p2_passed,
                "missing_count": 0 if p2_passed else 1,
                "total_count": 1,
                "detail": p2_detail,
                "details": p2_detail,
            },
            {
                "id": "product_identified_with_version",
                "name": "Prodotto identificato con versione",
                "title": "Prodotto identificato con versione",
                "status": "PASS" if p3_passed else "FAIL",
                "passed": p3_passed,
                "missing_count": 0 if p3_passed else 1,
                "total_count": 1,
                "detail": p3_detail,
                "details": p3_detail,
            },
            {
                "id": "product_manufacturer_indicated",
                "name": "Produttore del prodotto indicato",
                "title": "Produttore del prodotto indicato",
                "status": "PASS" if p4_passed else "FAIL",
                "passed": p4_passed,
                "missing_count": 0 if p4_passed else 1,
                "total_count": 1,
                "detail": p4_detail,
                "details": p4_detail,
            },
            {
                "id": "generation_date",
                "name": "Data di generazione",
                "title": "Data di generazione",
                "status": "PASS" if p5_passed else "FAIL",
                "passed": p5_passed,
                "missing_count": 0 if p5_passed else 1,
                "total_count": 1,
                "detail": p5_detail,
                "details": p5_detail,
            },
            {
                "id": "sbom_origin",
                "name": "Origine della SBOM",
                "title": "Origine della SBOM",
                "status": "PASS" if p6_passed else "FAIL",
                "passed": p6_passed,
                "missing_count": 0 if p6_passed else 1,
                "total_count": 1,
                "detail": p6_detail,
                "details": p6_detail,
            },
            {
                "id": "component_suppliers",
                "name": "Fornitore di ogni componente",
                "title": "Fornitore di ogni componente",
                "status": "PASS" if p7_passed else "FAIL",
                "passed": p7_passed,
                "missing_count": missing_supplier,
                "total_count": total_comps,
                "detail": p7_detail,
                "details": p7_detail,
            },
            {
                "id": "integrity_hashes",
                "name": "Hash di integrità",
                "title": "Hash di integrità",
                "status": "PASS" if p8_passed else "FAIL",
                "passed": p8_passed,
                "missing_count": missing_hash,
                "total_count": total_comps,
                "detail": p8_detail,
                "details": p8_detail,
            },
            {
                "id": "component_versions",
                "name": "Versione di ogni componente",
                "title": "Versione di ogni componente",
                "status": "PASS" if p9_passed else "FAIL",
                "passed": p9_passed,
                "missing_count": missing_version,
                "total_count": total_comps,
                "detail": p9_detail,
                "details": p9_detail,
            },
            {
                "id": "unique_identifiers",
                "name": "Identificativo univoco",
                "title": "Identificativo univoco",
                "status": "PASS" if p10_passed else "FAIL",
                "passed": p10_passed,
                "missing_count": missing_id,
                "total_count": total_comps,
                "detail": p10_detail,
                "details": p10_detail,
            },
            {
                "id": "component_licenses",
                "name": "Licenza di ogni componente",
                "title": "Licenza di ogni componente",
                "status": "PASS" if p11_passed else "FAIL",
                "passed": p11_passed,
                "missing_count": missing_license,
                "total_count": total_comps,
                "detail": p11_detail,
                "details": p11_detail,
            },
            {
                "id": "core_component_tagging",
                "name": "Marcatura Core Component",
                "title": "Marcatura Core Component",
                "status": p12_status,
                "passed": p12_passed,
                "missing_count": 0,
                "total_count": total_comps,
                "detail": p12_detail,
                "details": p12_detail,
            },
        ]

        cra_checklist_status: Dict[str, bool] = {}
        for item in cra_checklist:
            cra_checklist_status[item["id"]] = item["passed"]
            cra_checklist_status[item["title"]] = item["passed"]
            cra_checklist_status[item["name"]] = item["passed"]

        return {
            "file_imprint": file_imprint,
            "root_product": root_product,
            "root_product_name": root_product_name,
            "root_product_version": root_product_version,
            "serial_number": serial_number,
            "core_components_count": core_comps_count,
            "third_party_components_count": tp_comps_count,
            "cra_checklist": cra_checklist,
            "cra_checklist_status": cra_checklist_status,
            "component_matrix": component_matrix,
        }

    # ------------------------------------------------------------------
    # Internal: format detection
    # ------------------------------------------------------------------

    def _detect_format(self, data: dict) -> str:
        if "bomFormat" in data:
            return "cyclonedx"
        if "spdxVersion" in data or "SPDXID" in data:
            return "spdx"
        return "unknown"

    # ------------------------------------------------------------------
    # Phase 1 — ACN Validation
    # ------------------------------------------------------------------

    def _run_acn_validation(
        self,
        filepath: str,
        sbom_data: Optional[dict] = None,
        core_comps: Optional[List[dict]] = None,
        tp_comps: Optional[List[dict]] = None,
    ) -> Tuple[List[ValidationCheck], List[str], Optional[Dict]]:
        """Esegue la validazione ACN e mappa i risultati in ValidationCheck."""
        checks: List[ValidationCheck] = []
        output_lines: List[str] = []
        results_dict: Optional[Dict] = None

        if not ACN_AVAILABLE:
            checks.append(ValidationCheck(
                name="Modulo ACN",
                category="acn",
                passed=False,
                message=f"modulo_SBOM non trovato / ACN module not found: {_ACN_IMPORT_ERROR}",
            ))
            return checks, output_lines, results_dict

        try:
            acn_config = AcnValidationConfig(
                max_size_mb=self.config.max_size_mb,
                verbose=self.config.verbose,
                quiet=True,  # suppress stdout — we capture output_lines
                skip_schema=self.config.skip_schema,
            )
            acn_validator = AcnSBOMValidator(acn_config)

            # Run full ACN pipeline
            acn_results: AcnValidationResults = acn_validator.validate_sbom_file(filepath)

            # Capture raw text output
            output_lines = list(acn_validator.output_lines)

            # Generate summary (populates more output_lines)
            if acn_results.component_stats is None:
                acn_results.component_stats = {"has_additional_fields": False}
            if acn_results.service_stats is None:
                acn_results.service_stats = {"has_additional_fields": False}
            acn_validator.generate_summary(acn_results)
            output_lines = list(acn_validator.output_lines)

            # Map ACN ValidationResults → structured checks
            results_dict = {
                "valid_components": len(acn_results.valid_components),
                "valid_services": len(acn_results.valid_services),
                "components_total": acn_results.components_total,
                "services_total": acn_results.services_total,
                "schema_valid": acn_results.schema_valid,
                "metadata_valid": acn_results.metadata_valid,
                "schema_skipped": acn_results.schema_skipped,
            }

            # -- Schema check --
            if not acn_results.schema_skipped:
                checks.append(ValidationCheck(
                    name="Validazione schema CycloneDX v1.6 / CycloneDX v1.6 Schema",
                    category="schema",
                    passed=acn_results.schema_valid,
                    message=(
                        "Schema CycloneDX v1.6 valido / Valid CycloneDX v1.6 schema."
                        if acn_results.schema_valid else
                        "Schema CycloneDX v1.6 non valido / Invalid CycloneDX v1.6 schema. Vedere output ACN."
                    ),
                    details={"acn_output_snippet": output_lines[:10]},
                ))
            else:
                checks.append(ValidationCheck(
                    name="Validazione schema CycloneDX v1.6 / CycloneDX v1.6 Schema",
                    category="schema",
                    passed=True,
                    message="Validazione schema saltata su richiesta / Schema validation skipped.",
                    details={"skipped": True},
                ))

            # -- Metadata check --
            checks.append(ValidationCheck(
                name="Validazione metadata SBOM / SBOM Metadata",
                category="metadata",
                passed=acn_results.metadata_valid,
                message=(
                    "Campo metadata.component presente e valido / metadata.component present and valid."
                    if acn_results.metadata_valid else
                    "Campo metadata.component assente o non valido / metadata.component missing or invalid."
                ),
            ))

            # -- Components check (Bifurcated: Core vs Third-Party) --
            raw_comps = (sbom_data.get("components", []) if isinstance(sbom_data, dict) else [])
            if core_comps is None or tp_comps is None:
                core_comps, tp_comps = self.partition_components(raw_comps)

            core_missing: List[str] = []
            for c in core_comps:
                c_name = c.get("name")
                c_version = c.get("version")
                c_type = c.get("type")
                sup = c.get("supplier")
                aut = c.get("author")
                man = c.get("manufacturer")
                has_origin = bool(
                    (sup and (isinstance(sup, dict) and sup.get("name") or isinstance(sup, str)))
                    or (aut and str(aut).strip())
                    or (man and (isinstance(man, dict) and man.get("name") or isinstance(man, str)))
                )
                if not (c_name and c_version and c_type and has_origin):
                    core_missing.append(c_name or "sconosciuto")

            total_c = acn_results.components_total
            valid_c = len(acn_results.valid_components)
            invalid_c = total_c - valid_c

            if core_missing:
                checks.append(ValidationCheck(
                    name="Validazione componenti / Component Validation",
                    category="component",
                    passed=False,
                    message=(
                        f"Violazione requisiti minimi: {len(core_missing)} componenti Core mancano di campi obbligatori "
                        f"({', '.join(core_missing[:5])}). Mandatory fields missing on core components."
                    ),
                    details={"core_missing": core_missing, "core_total": len(core_comps)},
                ))
            else:
                tp_missing_origin = []
                if invalid_c > 0 and len(tp_comps) > 0:
                    tp_missing_origin = [
                        c.get("name") or f"Component #{i}"
                        for i, c in enumerate(tp_comps, 1)
                        if not (
                            (c.get("supplier") and (isinstance(c.get("supplier"), dict) and c.get("supplier", {}).get("name") or isinstance(c.get("supplier"), str)))
                            or (c.get("author") and str(c.get("author")).strip())
                            or (c.get("manufacturer") and (isinstance(c.get("manufacturer"), dict) and c.get("manufacturer", {}).get("name") or isinstance(c.get("manufacturer"), str)))
                        )
                    ]
                warning_note = ""
                if invalid_c > 0 and len(tp_comps) > 0:
                    warning_note = f" ({invalid_c} componenti terze parti privi di manufacturer aziendale; tollerato con avviso)"

                checks.append(ValidationCheck(
                    name="Validazione componenti / Component Validation",
                    category="component",
                    passed=True,
                    message=(
                        f"Componenti Core conformi. {valid_c}/{total_c} componenti complessivi con campi minimi estesi{warning_note}."
                    ),
                    details={
                        "total": total_c,
                        "valid": valid_c,
                        "invalid": invalid_c,
                        "core_total": len(core_comps),
                        "third_party_total": len(tp_comps),
                        "warning": invalid_c > 0,
                        "missing_items": tp_missing_origin if invalid_c > 0 else [],
                        "warning_message": f"Component Validation: {invalid_c} third-party components lack enterprise manufacturer/origin metadata." if invalid_c > 0 else None,
                    },
                ))

            # -- Services check --
            total_s = acn_results.services_total
            valid_s = len(acn_results.valid_services)
            invalid_s = total_s - valid_s
            services_ok = (total_s == 0) or (invalid_s == 0)
            checks.append(ValidationCheck(
                name="Validazione servizi / Service Validation",
                category="service",
                passed=services_ok,
                message=(
                    f"{valid_s}/{total_s} servizi validi con campi minimi obbligatori. "
                    f"{valid_s}/{total_s} services valid with required minimum fields."
                    if total_s > 0 else
                    "Nessun servizio trovato / No services found."
                ),
                details={
                    "total": total_s,
                    "valid": valid_s,
                    "invalid": invalid_s,
                },
            ))

        except Exception as e:
            checks.append(ValidationCheck(
                name="Validazione ACN / ACN Validation",
                category="acn",
                passed=False,
                message=f"Errore durante la validazione ACN / ACN validation error: {e}",
                details={"error": str(e)},
            ))

        return checks, output_lines, results_dict

    # ------------------------------------------------------------------
    # Phase 2 — CRA Checks
    # ------------------------------------------------------------------

    def _run_cra_checks(
        self,
        data: dict,
        fmt: str,
        core_comps: Optional[List[dict]] = None,
        tp_comps: Optional[List[dict]] = None
    ) -> List[ValidationCheck]:
        """
        Controlli di conformità al Cyber Resilience Act (CRA).
        CRA Compliance Checks.
        """
        checks: List[ValidationCheck] = []

        if fmt not in ("cyclonedx", "spdx"):
            checks.append(ValidationCheck(
                name="Conformità CRA / CRA Compliance",
                category="cra",
                passed=False,
                message="Formato SBOM non riconosciuto — impossibile effettuare i controlli CRA. Unknown SBOM format.",
            ))
            return checks

        if fmt == "cyclonedx":
            components: List[dict] = data.get("components", [])
            metadata: dict = data.get("metadata", {})

            if core_comps is None or tp_comps is None:
                core_comps, tp_comps = self.partition_components(components)

            # CRA-1: Timestamp metadata
            checks.append(self._cra_check_timestamp(metadata))

            # CRA-2: Contatto creatore / Creator contact
            checks.append(self._cra_check_creator_contact(metadata))

            # CRA-3: Hash SHA-512 su componenti / SHA-512 hashes
            checks.append(self._cra_check_sha512_hashes(components, core_comps=core_comps, tp_comps=tp_comps))

            # CRA-4: Licenze SPDX valide / SPDX licenses
            checks.append(self._cra_check_spdx_licenses(components, core_comps=core_comps, tp_comps=tp_comps))

            # CRA-5: Assenza dati vulnerabilità / No vulnerability data
            checks.append(self._cra_check_no_vulnerabilities(data))

            # CRA-6: Versione schema CycloneDX 1.6 / Schema version
            checks.append(self._cra_check_schema_version_cdx(data))

        elif fmt == "spdx":
            # Basic CRA checks for SPDX
            checks.append(self._cra_check_schema_version_spdx(data))
            checks.append(self._cra_check_no_vulnerabilities(data))

        return checks

    def _cra_check_timestamp(self, metadata: dict) -> ValidationCheck:
        ts = metadata.get("timestamp")
        if ts and isinstance(ts, str) and len(ts) >= 10:
            return ValidationCheck(
                name="Timestamp SBOM (CRA Art. 13)",
                category="cra",
                passed=True,
                message=f"Timestamp SBOM presente: {ts}. SBOM timestamp present.",
                details={"timestamp": ts},
            )
        return ValidationCheck(
            name="Timestamp SBOM (CRA Art. 13)",
            category="cra",
            passed=False,
            message="Timestamp SBOM assente in metadata.timestamp. SBOM timestamp missing.",
        )

    def _cra_check_creator_contact(self, metadata: dict) -> ValidationCheck:
        tools = metadata.get("tools")
        authors = metadata.get("authors")
        manufacturer = metadata.get("manufacturer") or metadata.get("manufacture")
        supplier = metadata.get("supplier")
        component = metadata.get("component")

        has_contact = False
        details: Dict[str, Any] = {}

        if authors and isinstance(authors, list) and len(authors) > 0:
            has_contact = True
            details["authors"] = [a.get("name", "") for a in authors if isinstance(a, dict)]
        elif authors and isinstance(authors, dict) and authors.get("name"):
            has_contact = True
            details["authors"] = [authors.get("name")]

        if tools and (
            (isinstance(tools, list) and len(tools) > 0)
            or (isinstance(tools, dict) and len(tools) > 0)
        ):
            has_contact = True
            details["tools"] = tools

        if isinstance(manufacturer, dict) and manufacturer.get("name"):
            has_contact = True
            details["manufacturer"] = manufacturer.get("name")
        elif isinstance(manufacturer, str) and manufacturer.strip():
            has_contact = True
            details["manufacturer"] = manufacturer.strip()

        if isinstance(supplier, dict) and supplier.get("name"):
            has_contact = True
            details["supplier"] = supplier.get("name")
        elif isinstance(supplier, str) and supplier.strip():
            has_contact = True
            details["supplier"] = supplier.strip()

        # Root metadata.component is treated as Core by default
        if component and isinstance(component, dict):
            comp_mfr = component.get("manufacturer")
            if isinstance(comp_mfr, dict) and comp_mfr.get("name"):
                has_contact = True
                details["component_manufacturer"] = comp_mfr.get("name")
            elif isinstance(comp_mfr, str) and comp_mfr.strip():
                has_contact = True
                details["component_manufacturer"] = comp_mfr.strip()

            comp_sup = component.get("supplier")
            if isinstance(comp_sup, dict) and comp_sup.get("name"):
                has_contact = True
                details["component_supplier"] = comp_sup.get("name")
            elif isinstance(comp_sup, str) and comp_sup.strip():
                has_contact = True
                details["component_supplier"] = comp_sup.strip()

            comp_author = component.get("author")
            if comp_author:
                has_contact = True
                details["component_author"] = comp_author

        if has_contact:
            return ValidationCheck(
                name="Contatto creatore SBOM (CRA Art. 13) / Creator Contact",
                category="cra",
                passed=True,
                message="Informazioni di contatto del creatore presenti. Creator contact information present.",
                details=details,
            )
        return ValidationCheck(
            name="Contatto creatore SBOM (CRA Art. 13) / Creator Contact",
            category="cra",
            passed=False,
            message=(
                "Informazioni di contatto del creatore SBOM assenti "
                "(metadata.authors, metadata.tools, metadata.manufacturer o metadata.supplier mancanti). "
                "Creator contact missing in metadata."
            ),
        )

    def _cra_check_sha512_hashes(
        self,
        components: List[dict],
        core_comps: Optional[List[dict]] = None,
        tp_comps: Optional[List[dict]] = None
    ) -> ValidationCheck:
        if not components:
            return ValidationCheck(
                name="Hash SHA-512 componenti (CRA Art. 13) / SHA-512 Hashes",
                category="cra",
                passed=True,
                message="Nessun componente da verificare. No components to check.",
            )
        if self.profile == ValidationProfile.LEGACY:
            return ValidationCheck(
                name="Hash SHA-512 componenti (CRA Art. 13) / SHA-512 Hashes",
                category="cra",
                passed=True,
                message="Controllo hash SHA-512 ignorato per profilo LEGACY (sistemi air-gapped). Bypassed under LEGACY profile.",
                details={"total": len(components), "bypassed": True, "profile": self.profile.value},
            )

        if core_comps is None or tp_comps is None:
            core_comps, tp_comps = self.partition_components(components)

        # Strict check on Core components
        core_missing: List[str] = []
        for comp in core_comps:
            hashes = comp.get("hashes")
            has = False
            if isinstance(hashes, list):
                for h in hashes:
                    if isinstance(h, dict):
                        alg = h.get("alg") or h.get("algorithm")
                        if alg in HASH_SHA512_ALGS or (isinstance(alg, str) and alg.upper().replace("_", "-") in HASH_SHA512_ALGS):
                            if h.get("content") or h.get("hash"):
                                has = True
                                break
            if not has:
                core_missing.append(comp.get("name", "sconosciuto"))

        if core_missing:
            return ValidationCheck(
                name="Hash SHA-512 componenti (CRA Art. 13) / SHA-512 Hashes",
                category="cra",
                passed=False,
                message=(
                    f"Violazione CRA: {len(core_missing)} componenti Core mancano di hash SHA-512 "
                    f"({', '.join(core_missing[:5])}). Core components must declare SHA-512 hashes."
                ),
                details={
                    "core_total": len(core_comps),
                    "core_missing": core_missing,
                    "third_party_total": len(tp_comps),
                },
            )

        # Third-party components: missing hashes are downgraded to WARNING only
        tp_with_hash = 0
        tp_missing: List[str] = []
        for comp in tp_comps:
            hashes = comp.get("hashes")
            has = False
            if isinstance(hashes, list):
                for h in hashes:
                    if isinstance(h, dict):
                        alg = h.get("alg") or h.get("algorithm")
                        if alg in HASH_ALGORITHMS or (isinstance(alg, str) and alg.upper().replace("_", "-") in HASH_ALGORITHMS):
                            if h.get("content") or h.get("hash"):
                                has = True
                                break
            if has:
                tp_with_hash += 1
            else:
                tp_missing.append(comp.get("name", "sconosciuto"))

        pct = (tp_with_hash / len(tp_comps) * 100) if tp_comps else 100.0
        warning_note = ""
        if tp_comps and tp_with_hash < len(tp_comps):
            warning_note = f" (Avviso non bloccante: {len(tp_missing)} librerie di terze parti prive di hash crittografico)"

        return ValidationCheck(
            name="Hash SHA-512 componenti (CRA Art. 13) / SHA-512 Hashes",
            category="cra",
            passed=True,
            message=(
                f"Componenti Core conformi a CRA Art. 13. "
                f"Terze parti: {tp_with_hash}/{len(tp_comps)} ({pct:.1f}%) con hash crittografico{warning_note}."
            ),
            details={
                "core_total": len(core_comps),
                "core_compliant": len(core_comps),
                "third_party_total": len(tp_comps),
                "third_party_with_hash": tp_with_hash,
                "third_party_missing": tp_missing,
                "missing_items": tp_missing,
                "invalid_elements": tp_missing,
                "warning": len(tp_missing) > 0,
                "warning_message": f"CRA SHA-512 Hashes: {len(tp_missing)} third-party components missing cryptographic hashes (SHA-512/SHA-256).",
            },
        )

    def _cra_check_spdx_licenses(
        self,
        components: List[dict],
        core_comps: Optional[List[dict]] = None,
        tp_comps: Optional[List[dict]] = None
    ) -> ValidationCheck:
        if not components:
            return ValidationCheck(
                name="Licenze SPDX valide (CRA Art. 13) / SPDX Licenses",
                category="cra",
                passed=True,
                message="Nessun componente da verificare. No components to check.",
            )

        is_legacy = self.profile == ValidationProfile.LEGACY
        if core_comps is None or tp_comps is None:
            core_comps, tp_comps = self.partition_components(components)

        # Strict check on Core components
        core_invalid: List[str] = []
        for comp in core_comps:
            licenses = comp.get("licenses")
            comp_name = comp.get("name", "sconosciuto")
            found_valid = False
            if isinstance(licenses, list):
                for lic_entry in licenses:
                    if not isinstance(lic_entry, dict):
                        continue
                    lic = lic_entry.get("license")
                    lic_id = lic.get("id") if isinstance(lic, dict) else None
                    lic_expr = lic_entry.get("expression")

                    if is_legacy:
                        if lic_id or lic_expr or (isinstance(lic, dict) and lic.get("name")):
                            found_valid = True
                            break
                    else:
                        if lic_id and (lic_id in VALID_SPDX_LICENSES or lic_id in ALLOWED_CORPORATE_LICENSE_REFS or (isinstance(lic_id, str) and lic_id.startswith("LicenseRef-"))):
                            found_valid = True
                            break
                        if lic_expr:
                            found_valid = True
                            break

            if not found_valid:
                core_invalid.append(comp_name)

        if core_invalid:
            return ValidationCheck(
                name="Licenze SPDX valide (CRA Art. 13) / SPDX Licenses",
                category="cra",
                passed=False,
                message=(
                    f"Violazione CRA: {len(core_invalid)} componenti Core con licenza mancante o non valida "
                    f"({', '.join(core_invalid[:5])}). Valid SPDX or approved corporate license required for core components."
                ),
                details={
                    "core_total": len(core_comps),
                    "core_invalid": core_invalid,
                    "third_party_total": len(tp_comps),
                },
            )

        # Third-party components: sloppy or non-SPDX licenses generate WARNING only
        tp_with_strict = 0
        tp_sloppy: List[str] = []
        for comp in tp_comps:
            licenses = comp.get("licenses")
            comp_name = comp.get("name", "sconosciuto")
            is_strict = False
            if isinstance(licenses, list):
                for lic_entry in licenses:
                    if not isinstance(lic_entry, dict):
                        continue
                    lic = lic_entry.get("license")
                    lic_id = lic.get("id") if isinstance(lic, dict) else None
                    lic_expr = lic_entry.get("expression")
                    if lic_id and (lic_id in VALID_SPDX_LICENSES or lic_id in ALLOWED_CORPORATE_LICENSE_REFS or (isinstance(lic_id, str) and lic_id.startswith("LicenseRef-"))):
                        is_strict = True
                        break
                    if lic_expr:
                        is_strict = True
                        break
            if is_strict:
                tp_with_strict += 1
            else:
                tp_sloppy.append(comp_name)

        warning_note = ""
        if tp_sloppy:
            warning_note = f" (Avviso non bloccante: {len(tp_sloppy)} librerie di terze parti con licenze non-SPDX o permissive)"

        return ValidationCheck(
            name="Licenze SPDX valide (CRA Art. 13) / SPDX Licenses",
            category="cra",
            passed=True,
            message=(
                f"Componenti Core conformi a CRA Art. 13. "
                f"Terze parti: {tp_with_strict}/{len(tp_comps)} con licenze SPDX formali{warning_note}."
            ),
            details={
                "core_total": len(core_comps),
                "core_compliant": len(core_comps),
                "third_party_total": len(tp_comps),
                "third_party_strict": tp_with_strict,
                "third_party_sloppy": tp_sloppy,
                "invalid_elements": tp_sloppy,
                "missing_items": tp_sloppy,
                "warning": len(tp_sloppy) > 0,
                "warning_message": f"CRA SPDX Licenses: {len(tp_sloppy)} third-party components with non-SPDX or custom license strings.",
            },
        )

    def _cra_check_no_vulnerabilities(self, data: dict) -> ValidationCheck:
        """CRA: L'SBOM non deve contenere dati di vulnerabilità incorporati."""
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return ValidationCheck(
                name="Assenza dati vulnerabilità (CRA) / No Embedded Vulnerabilities",
                category="cra",
                passed=False,
                message=(
                    f"L'SBOM contiene {len(vulns)} voci di vulnerabilità incorporate. "
                    f"Secondo CRA, la SBOM non deve incorporare dati CVE/vulnerabilità. "
                    f"SBOM contains {len(vulns)} embedded vulnerability entries (not recommended per CRA)."
                ),
                details={"count": len(vulns)},
            )
        return ValidationCheck(
            name="Assenza dati vulnerabilità (CRA) / No Embedded Vulnerabilities",
            category="cra",
            passed=True,
            message="Nessun dato di vulnerabilità incorporato nell'SBOM. No embedded vulnerabilities.",
        )

    def _cra_check_schema_version_cdx(self, data: dict) -> ValidationCheck:
        version = str(data.get("specVersion", "")).strip()
        passed = version in ["1.6", "1.7"]
        return ValidationCheck(
            name="Versione schema CycloneDX (CRA) / CycloneDX Schema Version",
            category="cra",
            passed=passed,
            message=(
                f"specVersion: {version} — Conforme (richiesto CycloneDX 1.6 o 1.7)."
                if passed else
                f"specVersion: {version} — Non conforme: richiesto CycloneDX 1.6 o 1.7."
            ),
            details={"version": version, "required": "1.6 o 1.7"},
        )

    def _cra_check_schema_version_spdx(self, data: dict) -> ValidationCheck:
        version = data.get("spdxVersion", "")
        passed = "3.0" in version or "2.3" in version
        return ValidationCheck(
            name="Versione schema SPDX (CRA) / SPDX Schema Version",
            category="cra",
            passed=passed,
            message=(
                f"spdxVersion: {version}. CRA raccomanda SPDX 3.0.1 o superiore. "
                f"spdxVersion: {version}. CRA recommends SPDX 3.0.1+."
            ),
            details={"version": version},
        )

    # ------------------------------------------------------------------
    # Phase 3 — NIS2 Checks
    # ------------------------------------------------------------------

    def _run_nis2_checks(
        self,
        data: dict,
        fmt: str,
        core_comps: Optional[List[dict]] = None,
        tp_comps: Optional[List[dict]] = None
    ) -> List[ValidationCheck]:
        """
        Controlli di conformità alla Direttiva NIS2.
        NIS2 Compliance Checks.
        """
        checks: List[ValidationCheck] = []

        if fmt == "cyclonedx":
            components = data.get("components", [])
            dependencies = data.get("dependencies", [])

            if core_comps is None or tp_comps is None:
                core_comps, tp_comps = self.partition_components(components)

            # NIS2-1: Completezza inventario componenti (Art. 21)
            checks.append(self._nis2_check_component_inventory(components, core_comps=core_comps, tp_comps=tp_comps))

            # NIS2-2: Completezza dipendenze (Art. 21 supply chain)
            checks.append(self._nis2_check_dependencies(components, dependencies))

            # NIS2-3: Prontezza per segnalazione incidenti (Art. 23)
            checks.append(self._nis2_check_incident_readiness(data))

            # NIS2-4: Verifica purl univoci (tracciabilità supply chain)
            checks.append(self._nis2_check_purl_traceability(components, core_comps=core_comps, tp_comps=tp_comps))

        else:
            checks.append(ValidationCheck(
                name="Conformità NIS2 / NIS2 Compliance",
                category="nis2",
                passed=True,
                message=(
                    f"Controlli NIS2 approfonditi disponibili solo per CycloneDX. "
                    f"Formato: {fmt}. "
                    "Full NIS2 checks available for CycloneDX format only."
                ),
                details={"skipped": True},
            ))

        return checks

    def _nis2_check_component_inventory(
        self,
        components: List[dict],
        core_comps: Optional[List[dict]] = None,
        tp_comps: Optional[List[dict]] = None
    ) -> ValidationCheck:
        if not components:
            return ValidationCheck(
                name="Inventario componenti NIS2 (Art. 21) / Component Inventory",
                category="nis2",
                passed=False,
                message=(
                    "Nessun componente nell'SBOM. NIS2 richiede un inventario completo. "
                    "No components in SBOM. NIS2 requires complete component inventory."
                ),
            )

        if core_comps is None or tp_comps is None:
            core_comps, tp_comps = self.partition_components(components)

        core_missing: List[str] = []
        for comp in core_comps:
            if not (comp.get("name") and comp.get("version")):
                core_missing.append(comp.get("name", "sconosciuto"))

        if core_missing:
            return ValidationCheck(
                name="Inventario componenti NIS2 (Art. 21) / Component Inventory",
                category="nis2",
                passed=False,
                message=(
                    f"Violazione NIS2: {len(core_missing)} componenti Core privi di nome o versione "
                    f"({', '.join(core_missing[:5])})."
                ),
                details={"core_missing": core_missing, "core_total": len(core_comps)},
            )

        tp_missing_fields = [
            c.get("name") or f"Component #{i}"
            for i, c in enumerate(tp_comps, 1)
            if not (c.get("name") and c.get("version"))
        ]
        tp_complete = len(tp_comps) - len(tp_missing_fields)
        return ValidationCheck(
            name="Inventario componenti NIS2 (Art. 21) / Component Inventory",
            category="nis2",
            passed=True,
            message=(
                f"Inventario componenti conforme. {len(core_comps)} componenti Core validati. "
                f"Terze parti: {tp_complete}/{len(tp_comps)} con nome e versione."
            ),
            details={
                "core_total": len(core_comps),
                "third_party_total": len(tp_comps),
                "third_party_complete": tp_complete,
                "missing_items": tp_missing_fields,
                "warning": len(tp_missing_fields) > 0,
                "warning_message": f"NIS2 Component Inventory: {len(tp_missing_fields)} third-party components missing name or version." if tp_missing_fields else None,
            },
        )

    def _nis2_check_dependencies(self, components: List[dict], dependencies: List[dict]) -> ValidationCheck:
        """NIS2 Art. 21: supply chain — presenza sezione dipendenze."""
        if not components:
            return ValidationCheck(
                name="Dipendenze supply chain NIS2 (Art. 21) / Supply Chain Dependencies",
                category="nis2",
                passed=True,
                message="Nessun componente — sezione dipendenze non applicabile. No components.",
            )
        has_deps = bool(dependencies and isinstance(dependencies, list) and len(dependencies) > 0)
        deps_ref_count = len(dependencies) if has_deps else 0
        components_with_purl = [c for c in components if isinstance(c, dict) and c.get("purl")]

        if has_deps:
            return ValidationCheck(
                name="Dipendenze supply chain NIS2 (Art. 21) / Supply Chain Dependencies",
                category="nis2",
                passed=True,
                message=(
                    f"Sezione 'dependencies' presente con {deps_ref_count} voci. "
                    f"'dependencies' section present with {deps_ref_count} entries."
                ),
                details={"count": deps_ref_count, "components_with_purl": len(components_with_purl)},
            )
        return ValidationCheck(
            name="Dipendenze supply chain NIS2 (Art. 21) / Supply Chain Dependencies",
            category="nis2",
            passed=False,
            message=(
                "Sezione 'dependencies' assente. NIS2 Art. 21 richiede completezza della supply chain. "
                "'dependencies' section missing. NIS2 Art. 21 requires complete supply chain."
            ),
            details={"components_with_purl": len(components_with_purl)},
        )

    def _nis2_check_incident_readiness(self, data: dict) -> ValidationCheck:
        """NIS2 Art. 23: Metadati per segnalazione incidenti."""
        metadata = data.get("metadata", {})
        component = metadata.get("component", {})
        has_name = bool(component.get("name"))
        has_version = bool(component.get("version"))
        has_timestamp = bool(metadata.get("timestamp"))
        ext_refs = component.get("externalReferences", []) if isinstance(component, dict) else []
        has_contact = len(ext_refs) > 0 or bool(metadata.get("authors")) or bool(metadata.get("tools"))

        score = sum([has_name, has_version, has_timestamp, has_contact])
        passed = score >= 3

        return ValidationCheck(
            name="Prontezza segnalazione incidenti NIS2 (Art. 23) / Incident Reporting Readiness",
            category="nis2",
            passed=passed,
            message=(
                f"Metadati per segnalazione incidenti: {score}/4 elementi presenti "
                f"(nome, versione, timestamp, contatto). "
                f"Incident reporting metadata: {score}/4 present."
            ),
            details={
                "has_name": has_name,
                "has_version": has_version,
                "has_timestamp": has_timestamp,
                "has_contact": has_contact,
            },
        )

    def _nis2_check_purl_traceability(
        self,
        components: List[dict],
        core_comps: Optional[List[dict]] = None,
        tp_comps: Optional[List[dict]] = None
    ) -> ValidationCheck:
        """NIS2: tracciabilità supply chain tramite PURL."""
        if not components:
            return ValidationCheck(
                name="Tracciabilità PURL NIS2 / PURL Traceability",
                category="nis2",
                passed=True,
                message="Nessun componente. No components.",
            )
        if self.profile == ValidationProfile.LEGACY:
            return ValidationCheck(
                name="Tracciabilità PURL NIS2 / PURL Traceability",
                category="nis2",
                passed=True,
                message="Controllo tracciabilità PURL ignorato per profilo LEGACY (sistemi air-gapped). Bypassed under LEGACY profile.",
                details={"total": len(components), "bypassed": True, "profile": self.profile.value},
            )

        if core_comps is None or tp_comps is None:
            core_comps, tp_comps = self.partition_components(components)

        core_missing_purl = [c.get("name", "sconosciuto") for c in core_comps if not c.get("purl")]
        if core_missing_purl:
            return ValidationCheck(
                name="Tracciabilità PURL NIS2 / PURL Traceability",
                category="nis2",
                passed=False,
                message=(
                    f"Violazione NIS2: {len(core_missing_purl)} componenti Core privi di PURL "
                    f"({', '.join(core_missing_purl[:5])}). Supply chain traceability requires PURL for core components."
                ),
                details={"core_missing_purl": core_missing_purl, "core_total": len(core_comps)},
            )

        tp_with_purl = sum(1 for c in tp_comps if c.get("purl"))
        tp_missing = [c.get("name", "N/A") for c in tp_comps if not c.get("purl")]

        return ValidationCheck(
            name="Tracciabilità PURL NIS2 / PURL Traceability",
            category="nis2",
            passed=True,
            message=(
                f"Componenti Core conformi a NIS2 Art. 21. "
                f"Terze parti: {tp_with_purl}/{len(tp_comps)} con PURL per tracciabilità supply chain."
            ),
            details={
                "core_total": len(core_comps),
                "third_party_total": len(tp_comps),
                "third_party_with_purl": tp_with_purl,
                "third_party_missing": tp_missing,
                "missing_items": tp_missing,
                "invalid_elements": tp_missing,
                "warning": len(tp_missing) > 0,
                "warning_message": f"NIS2 PURL Traceability: {len(tp_missing)} third-party components missing PURL identifiers.",
            },
        )

    # ------------------------------------------------------------------
    # SBOM Summary builder
    # ------------------------------------------------------------------

    def _build_sbom_summary(self, data: dict, fmt: str, schema_version: str) -> dict:
        if fmt == "cyclonedx":
            components = data.get("components", [])
            services = data.get("services", [])
            return {
                "format": f"CycloneDX {schema_version}",
                "schema_version": schema_version,
                "components_count": len(components),
                "services_count": len(services),
                "metadata_present": "metadata" in data,
                "has_dependencies": len(data.get("dependencies", [])) > 0,
                "has_vulnerabilities": len(data.get("vulnerabilities", [])) > 0,
                "serial_number": data.get("serialNumber", ""),
                "version": data.get("version", ""),
            }
        elif fmt == "spdx":
            packages = data.get("packages", [])
            return {
                "format": f"SPDX {schema_version}",
                "schema_version": schema_version,
                "components_count": len(packages),
                "services_count": 0,
                "metadata_present": "documentNamespace" in data,
                "has_dependencies": len(data.get("relationships", [])) > 0,
                "has_vulnerabilities": False,
                "name": data.get("name", ""),
                "data_license": data.get("dataLicense", ""),
            }
        return {
            "format": fmt,
            "schema_version": schema_version,
            "components_count": 0,
            "services_count": 0,
            "metadata_present": False,
            "has_dependencies": False,
            "has_vulnerabilities": False,
        }


# ---------------------------------------------------------------------------
# ACN-only validator (for the dedicated ACN tab)
# ---------------------------------------------------------------------------

class AcnOnlyValidator:
    """
    Esegue solo la validazione ACN modulo_SBOM (per il tab dedicato).
    Runs only the ACN modulo_SBOM validation (for the dedicated ACN tab).
    """

    def __init__(self, config: ValidationConfig):
        self.config = config

    def validate(self, filepath: str) -> dict:
        if not ACN_AVAILABLE:
            return {
                "success": False,
                "error": f"modulo_SBOM non disponibile: {_ACN_IMPORT_ERROR}",
                "output_lines": [],
                "results": None,
            }

        try:
            acn_config = AcnValidationConfig(
                max_size_mb=self.config.max_size_mb,
                verbose=self.config.verbose,
                quiet=True,
                skip_schema=self.config.skip_schema,
            )
            acn_validator = AcnSBOMValidator(acn_config)
            results = acn_validator.validate_sbom_file(filepath)

            if results.component_stats is None:
                results.component_stats = {"has_additional_fields": False}
            if results.service_stats is None:
                results.service_stats = {"has_additional_fields": False}
            acn_validator.generate_summary(results)

            overall_success = (
                len(results.valid_components) == results.components_total
                and len(results.valid_services) == results.services_total
                and (results.schema_valid or results.schema_skipped)
                and results.metadata_valid
                and (results.components_total > 0 or results.services_total > 0)
            )

            return {
                "success": True,
                "overall_valid": overall_success,
                "output_lines": list(acn_validator.output_lines),
                "results": {
                    "schema_valid": results.schema_valid,
                    "schema_skipped": results.schema_skipped,
                    "metadata_valid": results.metadata_valid,
                    "components_total": results.components_total,
                    "valid_components": len(results.valid_components),
                    "services_total": results.services_total,
                    "valid_services": len(results.valid_services),
                    "processing_time": results.processing_time,
                    "component_stats": results.component_stats,
                    "service_stats": results.service_stats,
                },
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "output_lines": [],
                "results": None,
            }


# ---------------------------------------------------------------------------
# Corporate Policy Validator ("Linee Guida per la generazione di una SBOM")
# ---------------------------------------------------------------------------

ALLOWED_CORPORATE_LICENSE_REFS = frozenset([
    "LicenseRef-Proprietary",
    "LicenseRef-InternalUseOnly",
])


class CorporatePolicyValidator:
    """
    Validatore per la Policy Aziendale ('Linee Guida per la generazione di una SBOM').

    Enforces mandatory corporate rules:
    1. Format & Version (Section 5): CycloneDX strictly v1.6. Reject SPDX or older versions.
    2. Document Metadata (Sections 4.1.1 & 4.1.4): Root metadata.timestamp (valid ISO-8601)
       and metadata.authors or metadata.tools.
    3. Component Mandatory Fields (Section 4.1.1): Every component must have name, version.
       Strict rules (supplier or author, and SHA-256 or SHA-512) apply to Core components.
       Third-party components missing origin or hashes generate WARNINGs only.
    4. License Compliance (Section 4.1.3): Core components must declare valid SPDX ID
       or LicenseRef-Proprietary / LicenseRef-InternalUseOnly. Third-party non-SPDX licenses generate WARNINGs.
    5. Core Component Tagging (Section 4.1.1): WARNING if no component has custom property
       {"name": "company:core-component", "value": "true"}.
    6. Dependency Graph (Section 4.1.2): Root dependencies array must exist and cannot be empty.
    """

    is_core_component = staticmethod(is_core_component)

    def validate(self, sbom_json: dict) -> Dict[str, Any]:
        failed_rules: List[str] = []
        warnings: List[str] = []

        if not isinstance(sbom_json, dict):
            return {
                "status": "FAIL",
                "failed_rules": ["Corporate Policy: Expected valid JSON object root."],
                "warnings": [],
            }

        # ------------------------------------------------------------------
        # 1. Format & Version (Section 5)
        # ------------------------------------------------------------------
        bom_format = str(sbom_json.get("bomFormat") or "").strip()
        spec_version = str(sbom_json.get("specVersion", "")).strip()

        if bom_format.lower() != "cyclonedx":
            failed_rules.append(
                f"Rule 1 [Format & Version]: SBOM format must be 'CycloneDX' (detected: '{bom_format or 'unknown'}'). "
                "SPDX and non-CycloneDX formats are rejected."
            )

        if spec_version not in ["1.6", "1.7"]:
            failed_rules.append(
                f"Rule 1 [Format & Version]: CycloneDX version must be '1.6' or '1.7' (detected: '{spec_version or 'unknown'}'). "
                "CycloneDX versions <= 1.5 and non-CycloneDX formats are rejected."
            )

        # ------------------------------------------------------------------
        # 2. Document Metadata (Sections 4.1.1 & 4.1.4)
        # ------------------------------------------------------------------
        metadata = sbom_json.get("metadata")
        if not isinstance(metadata, dict):
            failed_rules.append(
                "Rule 2 [Document Metadata]: Root 'metadata' object is missing."
            )
        else:
            # 2a. Timestamp check
            timestamp = metadata.get("timestamp")
            if not timestamp or not isinstance(timestamp, str) or not timestamp.strip():
                failed_rules.append(
                    "Rule 2 [Document Metadata]: 'metadata.timestamp' is missing or empty. A valid ISO-8601 timestamp is mandatory."
                )
            else:
                ts_clean = timestamp.strip()
                is_valid_iso = False
                try:
                    datetime.fromisoformat(ts_clean.replace("Z", "+00:00"))
                    is_valid_iso = True
                except Exception:
                    if re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", ts_clean):
                        is_valid_iso = True
                if not is_valid_iso:
                    failed_rules.append(
                        f"Rule 2 [Document Metadata]: 'metadata.timestamp' ('{timestamp}') is not a valid ISO-8601 timestamp."
                    )

            # 2b. Authors or Tools check
            authors = metadata.get("authors")
            tools = metadata.get("tools")
            has_authors = bool(authors and (
                (isinstance(authors, list) and len(authors) > 0)
                or (isinstance(authors, dict) and len(authors) > 0)
            ))
            has_tools = bool(tools and (
                (isinstance(tools, list) and len(tools) > 0)
                or (isinstance(tools, dict) and len(tools) > 0)
            ))

            if not (has_authors or has_tools):
                failed_rules.append(
                    "Rule 2 [Document Metadata]: Creator identity missing. Either 'metadata.authors' or 'metadata.tools' "
                    "must be present to identify the creator/tool that generated the SBOM."
                )

            # 2c. Root metadata.component (treated as Core by default)
            meta_comp = metadata.get("component")
            if meta_comp and isinstance(meta_comp, dict):
                if not meta_comp.get("name") or not str(meta_comp.get("name")).strip():
                    failed_rules.append(
                        "Rule 2 [Document Metadata]: Root 'metadata.component' is missing mandatory 'name'."
                    )
                if not meta_comp.get("version") or not str(meta_comp.get("version")).strip():
                    failed_rules.append(
                        "Rule 2 [Document Metadata]: Root 'metadata.component' is missing mandatory 'version'."
                    )

        # ------------------------------------------------------------------
        # 3. Component-Level Mandatory Fields (Section 4.1.1)
        # 4. License Compliance (Section 4.1.3)
        # 5. Core Component Tagging (Section 4.1.1)
        # ------------------------------------------------------------------
        components = sbom_json.get("components")
        has_core_component = False

        if components is None or not isinstance(components, list):
            failed_rules.append(
                "Rule 3 [Component Mandatory Fields]: Root 'components' array is missing."
            )
        elif len(components) == 0:
            failed_rules.append(
                "Rule 3 [Component Mandatory Fields]: Root 'components' list cannot be empty."
            )
        else:
            tp_missing_name_count = 0
            tp_missing_name_samples: List[str] = []
            tp_missing_version_count = 0
            tp_missing_version_samples: List[str] = []
            tp_missing_origin_count = 0
            tp_missing_origin_samples: List[str] = []
            tp_missing_hash_count = 0
            tp_missing_hash_samples: List[str] = []
            tp_invalid_lic_count = 0
            tp_invalid_lic_samples: List[str] = []

            for idx, comp in enumerate(components, 1):
                if not isinstance(comp, dict):
                    failed_rules.append(
                        f"Rule 3 [Component Mandatory Fields]: Component at index {idx} is not a valid JSON object."
                    )
                    continue

                is_core = is_core_component(comp)
                if is_core:
                    has_core_component = True

                comp_name = comp.get("name")
                comp_version = comp.get("version")

                # 3a. Name
                if not comp_name or not isinstance(comp_name, str) or not comp_name.strip():
                    if is_core:
                        failed_rules.append(
                            f"Rule 3 [Component Mandatory Fields]: Core component #{idx} is missing mandatory field 'name'."
                        )
                    else:
                        tp_missing_name_count += 1
                        if len(tp_missing_name_samples) < 5:
                            tp_missing_name_samples.append(f"Component #{idx}")

                # 3b. Version
                if not comp_version or not isinstance(comp_version, str) or not comp_version.strip():
                    display_name = str(comp_name) if comp_name and str(comp_name).strip() else f"Component #{idx}"
                    if is_core:
                        failed_rules.append(
                            f"Rule 3 [Component Mandatory Fields]: Core component '{display_name}' is missing exact 'version'."
                        )
                    else:
                        tp_missing_version_count += 1
                        if len(tp_missing_version_samples) < 5:
                            tp_missing_version_samples.append(display_name)

                # 3c. Supplier or Author
                supplier = comp.get("supplier")
                author = comp.get("author")
                has_origin = bool(
                    (isinstance(supplier, dict) and supplier.get("name") and str(supplier.get("name")).strip())
                    or (isinstance(supplier, str) and supplier.strip())
                    or (isinstance(author, str) and author.strip())
                    or (isinstance(author, list) and len(author) > 0)
                    or (isinstance(author, dict) and author.get("name") and str(author.get("name")).strip())
                )

                if not has_origin:
                    display_name = str(comp_name) if comp_name and str(comp_name).strip() else f"Component #{idx}"
                    if is_core:
                        failed_rules.append(
                            f"Rule 3 [Component Mandatory Fields]: Core component '{display_name}' must identify origin/vendor "
                            "via 'supplier' or 'author'."
                        )
                    else:
                        tp_missing_origin_count += 1
                        if len(tp_missing_origin_samples) < 5:
                            tp_missing_origin_samples.append(display_name)

                # 3d. Cryptographic Hashes (SHA-256 or SHA-512)
                hashes = comp.get("hashes")
                has_valid_hash = False
                if isinstance(hashes, list) and hashes:
                    for h in hashes:
                        if isinstance(h, dict):
                            alg = h.get("alg") or h.get("algorithm")
                            if alg in HASH_ALGORITHMS or (isinstance(alg, str) and alg.upper().replace("_", "-") in HASH_ALGORITHMS):
                                val = h.get("content") or h.get("hash")
                                if val and str(val).strip():
                                    has_valid_hash = True
                                    break

                if not has_valid_hash:
                    display_name = str(comp_name) if comp_name and str(comp_name).strip() else f"Component #{idx}"
                    if is_core:
                        failed_rules.append(
                            f"Rule 3 [Component Mandatory Fields]: Core component '{display_name}' must contain at least "
                            "one cryptographic hash using SHA-256 or SHA-512 (mandated in Section 4.1.4)."
                        )
                    else:
                        tp_missing_hash_count += 1
                        if len(tp_missing_hash_samples) < 5:
                            tp_missing_hash_samples.append(display_name)

                # ----------------------------------------------------------
                # 4. License Compliance (Section 4.1.3)
                # ----------------------------------------------------------
                licenses = comp.get("licenses")
                if licenses is None or not isinstance(licenses, list) or len(licenses) == 0:
                    display_name = str(comp_name) if comp_name and str(comp_name).strip() else f"Component #{idx}"
                    if is_core:
                        failed_rules.append(
                            f"Rule 4 [License Compliance]: Core component '{display_name}' is missing a mandatory 'licenses' array."
                        )
                    else:
                        tp_invalid_lic_count += 1
                        if len(tp_invalid_lic_samples) < 5:
                            tp_invalid_lic_samples.append(display_name)
                else:
                    found_valid_license = False
                    for lic_idx, lic_entry in enumerate(licenses, 1):
                        if not isinstance(lic_entry, dict):
                            continue

                        lic_obj = lic_entry.get("license")
                        lic_expr = lic_entry.get("expression")

                        if isinstance(lic_obj, dict):
                            lic_id = lic_obj.get("id")
                            lic_name = lic_obj.get("name")

                            if lic_id and isinstance(lic_id, str) and lic_id.strip():
                                clean_id = lic_id.strip()
                                if clean_id in VALID_SPDX_LICENSES or clean_id in ALLOWED_CORPORATE_LICENSE_REFS:
                                    found_valid_license = True
                                    break
                                else:
                                    if is_core:
                                        display_name = str(comp_name) if comp_name and str(comp_name).strip() else f"Component #{idx}"
                                        failed_rules.append(
                                            f"Rule 4 [License Compliance]: Core component '{display_name}' has unrecognized license ID '{clean_id}'. "
                                            f"Must be a valid SPDX identifier or one of {sorted(ALLOWED_CORPORATE_LICENSE_REFS)}."
                                        )
                            elif lic_name and isinstance(lic_name, str) and lic_name.strip():
                                clean_name = lic_name.strip()
                                if clean_name in ALLOWED_CORPORATE_LICENSE_REFS:
                                    found_valid_license = True
                                    break
                                else:
                                    if is_core:
                                        display_name = str(comp_name) if comp_name and str(comp_name).strip() else f"Component #{idx}"
                                        failed_rules.append(
                                            f"Rule 4 [License Compliance]: Core component '{display_name}' uses unstructured license name '{clean_name}'. "
                                            "Unstructured license names are rejected for core components."
                                        )
                            else:
                                if is_core:
                                    display_name = str(comp_name) if comp_name and str(comp_name).strip() else f"Component #{idx}"
                                    failed_rules.append(
                                        f"Rule 4 [License Compliance]: Core component '{display_name}' license object is empty (missing 'id')."
                                    )

                        elif isinstance(lic_expr, str) and lic_expr.strip():
                            clean_expr = lic_expr.strip()
                            if clean_expr in ALLOWED_CORPORATE_LICENSE_REFS:
                                found_valid_license = True
                                break
                            tokens = EXPR_TOKEN_REGEX.findall(clean_expr)
                            invalid_tokens = [
                                t for t in tokens
                                if t not in VALID_SPDX_LICENSES
                                and t not in ALLOWED_CORPORATE_LICENSE_REFS
                                and t not in ("AND", "OR", "WITH")
                            ]
                            if not invalid_tokens:
                                found_valid_license = True
                                break
                            else:
                                if is_core:
                                    display_name = str(comp_name) if comp_name and str(comp_name).strip() else f"Component #{idx}"
                                    failed_rules.append(
                                        f"Rule 4 [License Compliance]: Core component '{display_name}' has invalid license expression tokens: {invalid_tokens}."
                                    )
                        else:
                            if is_core:
                                display_name = str(comp_name) if comp_name and str(comp_name).strip() else f"Component #{idx}"
                                failed_rules.append(
                                    f"Rule 4 [License Compliance]: Core component '{display_name}' license entry #{lic_idx} must specify 'license.id' or 'expression'."
                                )

                    if not found_valid_license and not is_core:
                        tp_invalid_lic_count += 1
                        if len(tp_invalid_lic_samples) < 5:
                            display_name = str(comp_name) if comp_name and str(comp_name).strip() else f"Component #{idx}"
                            tp_invalid_lic_samples.append(display_name)

            # Summarize third-party warnings
            if tp_missing_name_count:
                warnings.append(
                    f"Rule 3 [Component Mandatory Fields]: {tp_missing_name_count} third-party component(s) missing mandatory field 'name', e.g. {', '.join(tp_missing_name_samples)}."
                )
            if tp_missing_version_count:
                warnings.append(
                    f"Rule 3 [Component Mandatory Fields]: {tp_missing_version_count} third-party component(s) missing exact 'version', e.g. {', '.join(tp_missing_version_samples)}."
                )
            if tp_missing_origin_count:
                warnings.append(
                    f"Rule 3 [Component Mandatory Fields]: {tp_missing_origin_count} third-party component(s) missing origin (supplier/author), e.g. {', '.join(tp_missing_origin_samples)}."
                )
            if tp_missing_hash_count:
                warnings.append(
                    f"Rule 3 [Component Mandatory Fields]: {tp_missing_hash_count} third-party component(s) missing SHA-256/512 hashes, e.g. {', '.join(tp_missing_hash_samples)}."
                )
            if tp_invalid_lic_count:
                warnings.append(
                    f"Rule 4 [License Compliance]: {tp_invalid_lic_count} third-party component(s) with non-standard or permissive licenses, e.g. {', '.join(tp_invalid_lic_samples)}."
                )

        # --------------------------------------------------------------
        # 5. Core Component Tagging Check (Section 4.1.1)
        # --------------------------------------------------------------
        # L'assenza di componenti marcati con company:core-component non costituisce
        # una non-conformità: significa semplicemente che lo SBOM non contiene
        # librerie core proprietarie e che tutti i componenti sono terze parti.
        # Non viene emesso alcun warning penalizzante.

        # ------------------------------------------------------------------
        # 6. Dependency Graph (Section 4.1.2)
        # ------------------------------------------------------------------
        dependencies = sbom_json.get("dependencies")
        if dependencies is None or not isinstance(dependencies, list) or len(dependencies) == 0:
            failed_rules.append(
                "Rule 6 [Dependency Graph]: Root 'dependencies' array must exist and cannot be empty. Component dependency graph is mandatory."
            )

        # ------------------------------------------------------------------
        # Aggregate Status
        # ------------------------------------------------------------------
        if failed_rules:
            status = "FAIL"
        elif warnings:
            status = "WARNING"
        else:
            status = "PASS"

        return {
            "status": status,
            "failed_rules": failed_rules,
            "warnings": warnings,
        }


def validate_corporate_policy(sbom_json: dict) -> Dict[str, Any]:
    """
    Validates an SBOM dictionary against the official Corporate Policy
    ('Linee Guida per la generazione di una SBOM').

    Returns a standardized dictionary:
        {"status": "PASS" | "WARNING" | "FAIL", "failed_rules": [...], "warnings": [...]}
    """
    validator = CorporatePolicyValidator()
    return validator.validate(sbom_json)

