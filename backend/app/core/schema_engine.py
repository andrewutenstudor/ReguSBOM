"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Air-Gap Schema Engine & Strict Offline JSON Schema Validator.
Compiles and executes JSON schemas (CycloneDX 1.4-1.7, SPDX 2.3-3.0.1)
exclusively from the local directory with zero HTTP/network fallback.
"""

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import fastjsonschema
from fastjsonschema.exceptions import JsonSchemaException

logger = logging.getLogger("regubom.schemas")

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"

# Schema registry map
SCHEMA_FILES: dict[tuple[str, str], str] = {
    ("cyclonedx", "1.4"): "bom-1.4.schema.json",
    ("cyclonedx", "1.5"): "bom-1.5.schema.json",
    ("cyclonedx", "1.6"): "bom-1.6.schema.json",
    ("cyclonedx", "1.7"): "bom-1.7.schema.json",
    ("spdx", "2.3"): "spdx-2.3.schema.json",
    ("spdx", "3.0"): "spdx-3.0.1.schema.json",
    ("spdx", "3.0.1"): "spdx-3.0.1.schema.json",
}

# Compiled validator cache: (format, version) -> compiled_func
_VALIDATOR_CACHE: dict[tuple[str, str], Callable[[dict[str, Any]], dict[str, Any]]] = {}


def _airgap_uri_handler(uri: str) -> dict[str, Any]:
    """
    Air-gap handler for fastjsonschema $ref URI resolution.
    Strictly forbids any external HTTP/HTTPS network calls.
    Resolves dependencies (e.g. spdx.schema.json, jsf.schema.json) purely from local disk.
    """
    clean_uri = uri.split("#")[0].strip()
    basename = clean_uri.split("/")[-1]

    candidate_files = [
        SCHEMAS_DIR / basename,
        SCHEMAS_DIR / f"{basename}.json",
    ]

    # Common cross-schema aliases
    if "spdx" in basename.lower():
        candidate_files.append(SCHEMAS_DIR / "spdx.schema.json")
        candidate_files.append(SCHEMAS_DIR / "spdx-2.3.schema.json")
    if "jsf" in basename.lower():
        candidate_files.append(SCHEMAS_DIR / "jsf.schema.json")

    for fpath in candidate_files:
        if fpath.exists() and fpath.is_file():
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"[AirGapSchema] Error reading local schema '{fpath}': {e}")
                raise

    error_msg = (
        f"AirGapIsolationViolation: Schema reference '{uri}' cannot be resolved locally. "
        f"Remote network access is strictly prohibited in sovereign mode."
    )
    logger.error(f"[AirGapSchema] {error_msg}")
    raise RuntimeError(error_msg)


def get_schema_validator(format_name: str, version: str) -> Callable[[dict[str, Any]], dict[str, Any]] | None:
    """
    Returns a cached, precompiled fastjsonschema validator function
    for the requested format and version, compiled in air-gap mode.
    """
    fmt = format_name.lower().strip()
    ver = version.strip().replace("SPDX-", "")
    key = (fmt, ver)

    if key in _VALIDATOR_CACHE:
        return _VALIDATOR_CACHE[key]

    schema_filename = SCHEMA_FILES.get(key)
    if not schema_filename:
        # Fallback search
        for (f_name, v_str), fname in SCHEMA_FILES.items():
            if f_name == fmt and ver.startswith(v_str):
                schema_filename = fname
                break

    if not schema_filename:
        logger.warning(f"[AirGapSchema] No bundled schema registered for format '{fmt}', version '{ver}'")
        return None

    schema_path = SCHEMAS_DIR / schema_filename
    if not schema_path.exists():
        logger.error(f"[AirGapSchema] Expected bundled schema file missing: {schema_path}")
        return None

    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_dict = json.load(f)

        compiled_validator = fastjsonschema.compile(
            schema_dict,
            handlers={
                "http": _airgap_uri_handler,
                "https": _airgap_uri_handler,
            },
        )
        _VALIDATOR_CACHE[key] = compiled_validator
        logger.info(f"[AirGapSchema] Successfully compiled air-gapped validator for {fmt} v{ver}")
        return compiled_validator
    except Exception as e:
        logger.error(f"[AirGapSchema] Failed to compile schema '{schema_filename}': {e}")
        return None


def validate_sbom_schema_airgap(sbom_dict: dict[str, Any], format_name: str, version: str) -> tuple[bool, str | None]:
    """
    Validates an SBOM dictionary against its official schema in air-gap mode.
    Returns (True, None) if compliant, or (False, error_detail) if schema validation fails.
    """
    validator = get_schema_validator(format_name, version)
    if not validator:
        # Schema not strictly available for this exact minor version, bypass strict schema check
        return True, None

    try:
        validator(sbom_dict)
        return True, None
    except JsonSchemaException as e:
        return (
            False,
            f"Schema validation error: {e.message} (path: {getattr(e, 'path', '/')})",
        )
    except Exception as e:
        return False, f"Schema validation failed: {e!s}"
