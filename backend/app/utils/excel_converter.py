"""
Excel-to-CycloneDX conversion utility.

Converts legacy software inventory spreadsheets (.xlsx, .xls) into
fully compliant CycloneDX v1.6 JSON SBOM documents.
"""

import io
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

import pandas as pd

# Supported SPDX licenses for clean identifier resolution
VALID_SPDX_LICENSES = frozenset(
    [
        "MIT",
        "Apache-2.0",
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.0",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "MPL-2.0",
        "CDDL-1.0",
        "EPL-1.0",
        "EPL-2.0",
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "CC0-1.0",
        "Unlicense",
        "EUPL-1.2",
        "EUPL-1.1",
        "NOASSERTION",
        "NONE",
    ]
)


def _clean_str(val: Any) -> str:
    """Helper to sanitize string values from DataFrame cells."""
    if pd.isna(val) or val is None:
        return ""
    s = str(val).strip()
    return "" if s.lower() == "nan" else s


def _normalize_col_name(col: Any) -> str:
    """Normalize column header for flexible lookup."""
    return str(col).strip().lower().replace("_", " ").replace("-", " ")


def convert_excel_to_cyclonedx(
    excel_input: bytes | BinaryIO | str | Path,
    filename: str | None = None,
) -> str:
    """
    Parse an Excel file (expecting columns: Component Name, Version, Supplier, License)
    and construct a valid CycloneDX v1.6 JSON string.

    Args:
        excel_input: Raw bytes, file-like object, or path to the .xlsx/.xls file.
        filename: Optional original file name to derive root component metadata.

    Returns:
        A serialized JSON string compliant with CycloneDX v1.6 schema.

    Raises:
        ValueError: If required columns cannot be found or the spreadsheet is unreadable.
    """
    # Load DataFrame from bytes or file path
    if isinstance(excel_input, bytes):
        file_obj = io.BytesIO(excel_input)
        df = pd.read_excel(file_obj)
    elif isinstance(excel_input, (str, Path)):
        df = pd.read_excel(excel_input)
    else:
        df = pd.read_excel(excel_input)

    # Determine original base filename for root component naming
    clean_filename = "Legacy-Excel-Inventory"
    if filename:
        clean_filename = Path(filename).stem or clean_filename

    # Map expected columns flexibly
    # Expecting: Component Name, Version, Supplier, License
    col_map: dict[str, str] = {}
    for col in df.columns:
        norm = _normalize_col_name(col)
        if norm in ("component name", "component", "name"):
            col_map["name"] = str(col)
        elif norm in ("version", "ver", "component version"):
            col_map["version"] = str(col)
        elif norm in ("supplier", "vendor", "manufacturer", "author"):
            col_map["supplier"] = str(col)
        elif norm in ("license", "licence", "spdx license", "licenses"):
            col_map["license"] = str(col)

    if "name" not in col_map:
        raise ValueError(
            f"Excel spreadsheet missing required column 'Component Name'. "
            f"Found columns: {list(df.columns)}. Expected: Component Name, Version, Supplier, License."
        )

    components: list[dict[str, Any]] = []
    component_bom_refs: list[str] = []
    root_bom_ref = f"pkg:generic/{clean_filename.lower().replace(' ', '-')}@1.0.0"

    for idx, row in df.iterrows():
        name = _clean_str(row.get(col_map["name"]))
        if not name:
            continue

        version = _clean_str(row.get(col_map.get("version", ""))) or "1.0.0"
        supplier = _clean_str(row.get(col_map.get("supplier", "")))
        license_str = _clean_str(row.get(col_map.get("license", "")))

        # Format purl and bom-ref
        safe_name = name.replace(" ", "-").lower()
        bom_ref = f"pkg:generic/{safe_name}@{version}"
        component_bom_refs.append(bom_ref)

        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
            "purl": bom_ref,
        }

        # Add supplier and manufacturer for standard CycloneDX and ACN compatibility
        if supplier:
            comp["supplier"] = {"name": supplier}
            comp["manufacturer"] = {"name": supplier}

        # Add license (normalize to SPDX id if recognized, otherwise license name)
        if license_str:
            if license_str in VALID_SPDX_LICENSES or license_str.startswith("LicenseRef-"):
                comp["licenses"] = [{"license": {"id": license_str}}]
            else:
                comp["licenses"] = [{"license": {"name": license_str}}]

        components.append(comp)

    # Build CycloneDX v1.6 document
    cyclonedx_doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "SBOM Validator Excel Bridge",
                        "version": "1.0.0",
                        "description": "Automated Excel-to-CycloneDX Ingestion Bridge",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_bom_ref,
                "name": clean_filename,
                "version": "1.0.0",
                "description": "Converted from legacy Excel inventory",
                "supplier": {"name": "Internal Organization / Legacy Ingestion Bridge"},
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": root_bom_ref,
                "dependsOn": component_bom_refs,
            }
        ],
    }

    return json.dumps(cyclonedx_doc, indent=2, ensure_ascii=False)


# Provide alias for convenience
excel_to_cyclonedx = convert_excel_to_cyclonedx
