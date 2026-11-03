"""
analyzer.py — Desirable Metadata Analyzer & Gap Identification.

Parses CycloneDX and SPDX SBOMs to inspect component metadata completeness,
flagging missing desirable fields (supplier, version, licenses, hashes, purl, cpe)
and producing a structured payload for interactive frontend exploration.
"""

from typing import Any

from app.core.validator import (
    has_non_spdx_license,
    is_core_component,
    is_in_dependencies_graph,
    is_spdx_license,
)

DESIRABLE_METADATA_FIELDS = [
    "supplier",
    "version",
    "licenses",
    "hashes",
    "purl",
    "cpe",
]

FIELD_LABELS = {
    "supplier": "Fornitore (Supplier/Author)",
    "hashes": "Hash (SHA-256/SHA-512)",
    "licenses": "Licenza (SPDX/UID)",
    "version": "Versione",
    "purl": "PURL",
    "cpe": "CPE",
}


def _extract_supplier_display(comp: dict) -> str:
    """Extracts a human-readable supplier or author string."""
    supplier = comp.get("supplier")
    if isinstance(supplier, dict):
        name = supplier.get("name")
        if name and str(name).strip():
            return str(name).strip()
    elif isinstance(supplier, str) and supplier.strip():
        return supplier.strip()

    manufacturer = comp.get("manufacturer")
    if isinstance(manufacturer, dict):
        name = manufacturer.get("name")
        if name and str(name).strip():
            return str(name).strip()
    elif isinstance(manufacturer, str) and manufacturer.strip():
        return manufacturer.strip()

    author = comp.get("author")
    if isinstance(author, dict):
        name = author.get("name")
        if name and str(name).strip():
            return str(name).strip()
    elif isinstance(author, str) and author.strip():
        return author.strip()

    authors = comp.get("authors")
    if isinstance(authors, list) and len(authors) > 0:
        first = authors[0]
        if isinstance(first, dict) and first.get("name"):
            return str(first.get("name")).strip()
        elif isinstance(first, str) and first.strip():
            return first.strip()

    return "—"


def _extract_licenses_display(comp: dict) -> list[str]:
    """Extracts a clean list of license identifiers or expressions."""
    licenses = comp.get("licenses")
    if not isinstance(licenses, list) or not licenses:
        return []

    result: list[str] = []
    for lic in licenses:
        if not isinstance(lic, dict):
            continue
        # Direct expression: {"expression": "MIT OR Apache-2.0"}
        expr = lic.get("expression")
        if expr and isinstance(expr, str) and expr.strip():
            result.append(expr.strip())
            continue

        license_obj = lic.get("license")
        if isinstance(license_obj, dict):
            lic_id = license_obj.get("id")
            lic_name = license_obj.get("name")
            if lic_id and str(lic_id).strip():
                result.append(str(lic_id).strip())
            elif lic_name and str(lic_name).strip():
                result.append(str(lic_name).strip())
        elif isinstance(license_obj, str) and license_obj.strip():
            result.append(license_obj.strip())

    return result


def _extract_tools_display(metadata: dict) -> list[str]:
    """Extracts tool names from metadata.tools."""
    tools = metadata.get("tools")
    if not tools:
        return []

    names: list[str] = []
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict):
                n = t.get("name")
                v = t.get("version")
                if n:
                    names.append(f"{n} {v}".strip() if v else str(n).strip())
            elif isinstance(t, str):
                names.append(t.strip())
    elif isinstance(tools, dict):
        # CycloneDX 1.5/1.6 format: tools.components or tools.services
        components = tools.get("components")
        if isinstance(components, list):
            for c in components:
                if isinstance(c, dict) and c.get("name"):
                    n = c.get("name")
                    v = c.get("version")
                    names.append(f"{n} {v}".strip() if v else str(n).strip())
        services = tools.get("services")
        if isinstance(services, list):
            for s in services:
                if isinstance(s, dict) and s.get("name"):
                    names.append(str(s.get("name")).strip())

    return names


def _extract_authors_display(metadata: dict) -> list[str]:
    """Extracts author names from metadata.authors."""
    authors = metadata.get("authors")
    if not isinstance(authors, list):
        return []
    result: list[str] = []
    for a in authors:
        if isinstance(a, dict):
            n = a.get("name")
            email = a.get("email")
            if n:
                result.append(f"{n} <{email}>" if email else str(n).strip())
        elif isinstance(a, str) and a.strip():
            result.append(a.strip())
    return result


def analyze_component(comp: dict, index: int = 0, dep_refs: set | None = None) -> dict[str, Any]:
    """
    Analyzes a single component strictly evaluating corporate policy mandates:
    - Name
    - Version
    - Supplier (supplier or author)
    - License (SPDX ID or LicenseRef- string)
    - Hash (specifically SHA-256 or SHA-512)
    - Core Property (properties with company:core-component == 'true')
    """
    name = str(comp.get("name") or f"unnamed-component-{index}").strip()
    raw_version = comp.get("version")
    version = str(raw_version).strip() if (raw_version and str(raw_version).strip()) else "vN/D"
    comp_type = str(comp.get("type") or "library").strip()

    # 1. Supplier ("Nome del Fornitore" - must check supplier, author or publisher)
    supplier_display = _extract_supplier_display(comp)
    has_supplier = bool(comp.get("supplier") or comp.get("author") or comp.get("publisher"))
    has_supplier_symbol = "✓" if has_supplier else "✕"

    # 2. Version ("Versione del Componente")
    has_version = bool(comp.get("version"))
    has_version_symbol = "✓" if has_version else "✕"

    # 3. License ("Licenza/SPDXID/UID")
    license_list = _extract_licenses_display(comp)
    has_lic_valid = is_spdx_license(comp)
    has_lic_any = has_non_spdx_license(comp)
    if has_lic_valid:
        has_license_symbol = "✓"
    elif has_lic_any:
        has_license_symbol = "!"
    else:
        has_license_symbol = "✕"

    # 4. Hash ("Hash / Checksum")
    hashes_list = comp.get("hashes")
    has_valid_hash = bool(hashes_list and isinstance(hashes_list, list) and len(hashes_list) > 0)
    valid_hashes_count = len(hashes_list) if isinstance(hashes_list, list) else 0
    has_hash_symbol = "✓" if has_valid_hash else "✕"

    # 5. Core Property (properties array with company:core-component == 'true')
    is_core = is_core_component(comp, is_metadata=False)

    # 6. PURL & CPE ("Identificativo univoco")
    purl_val = comp.get("purl")
    has_purl = isinstance(purl_val, str) and purl_val.strip().startswith("pkg:")
    purl = purl_val.strip() if isinstance(purl_val, str) and purl_val.strip() else None

    cpe_val = comp.get("cpe")
    has_cpe = isinstance(cpe_val, str) and (
        cpe_val.strip().startswith("cpe:2.3:") or cpe_val.strip().startswith("cpe:/")
    )
    cpe = cpe_val.strip() if isinstance(cpe_val, str) and cpe_val.strip() else None

    has_id_bool = bool((purl and str(purl).strip()) or (cpe and str(cpe).strip()))
    has_id_symbol = "✓" if has_id_bool else "✕"

    # Calculate missing desirable fields
    missing_desirable: list[str] = []
    if not has_supplier:
        missing_desirable.append("supplier")
    if not has_version:
        missing_desirable.append("version")
    if has_license_symbol == "✕":
        missing_desirable.append("licenses")
    if not has_valid_hash:
        missing_desirable.append("hashes")
    if not has_purl:
        missing_desirable.append("purl")
    if not has_cpe:
        missing_desirable.append("cpe")

    completeness_score = round(
        ((len(DESIRABLE_METADATA_FIELDS) - len(missing_desirable)) / len(DESIRABLE_METADATA_FIELDS)) * 100,
        1,
    )

    c_bom_ref = comp.get("bom-ref") or comp.get("ref")
    in_dep_graph = bool(
        dep_refs
        and (
            (c_bom_ref and str(c_bom_ref) in dep_refs)
            or (purl and str(purl) in dep_refs)
            or (name and str(name) in dep_refs)
        )
    )
    has_dependencies_symbol = "✓" if in_dep_graph else "✕"

    return {
        "index": index,
        "name": name,
        "version": version or "vN/D",
        "type": comp_type,
        "supplier": supplier_display,
        "licenses": license_list,
        "hashes_count": valid_hashes_count,
        "purl": purl,
        "cpe": cpe,
        "is_core": is_core,
        "has_id": has_id_symbol,
        "has_id_symbol": has_id_symbol,
        "has_supplier": has_supplier_symbol,
        "has_supplier_symbol": has_supplier_symbol,
        "has_version": has_version,
        "has_version_symbol": has_version_symbol,
        "has_dependencies": has_dependencies_symbol,
        "has_dependencies_symbol": has_dependencies_symbol,
        "has_licenses": (has_license_symbol != "✕"),
        "has_license": has_license_symbol,
        "has_license_symbol": has_license_symbol,
        "has_hashes": has_valid_hash,
        "has_hash": has_hash_symbol,
        "has_hash_symbol": has_hash_symbol,
        "has_purl": has_purl,
        "has_cpe": has_cpe,
        "missing_desirable": missing_desirable,
        "completeness_score": completeness_score,
        "bom_ref": comp.get("bom-ref") or comp.get("ref"),
        "description": comp.get("description"),
    }


def analyze_sbom(sbom_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Parses an SBOM dictionary and returns an enriched payload mapping out
    root metadata, mapped components with desirable gap indicators, and aggregate statistics.
    """
    if not isinstance(sbom_dict, dict):
        sbom_dict = {}

    bom_format = sbom_dict.get(
        "bomFormat",
        "CycloneDX" if "bomFormat" in sbom_dict else "SPDX" if "spdxVersion" in sbom_dict else "Unknown",
    )
    spec_version = str(sbom_dict.get("specVersion") or sbom_dict.get("spdxVersion") or "1.6").strip()
    serial_number = sbom_dict.get("serialNumber") or sbom_dict.get("serial_number") or "—"
    doc_version = sbom_dict.get("version", 1)

    metadata = sbom_dict.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    timestamp = metadata.get("timestamp") or "—"
    tools_list = _extract_tools_display(metadata)
    authors_list = _extract_authors_display(metadata)

    root_comp = metadata.get("component")
    if not isinstance(root_comp, dict):
        root_comp = {}

    root_name = root_comp.get("name") or "Prodotto Principale"
    root_version = root_comp.get("version") or "—"
    root_type = root_comp.get("type") or "application"
    root_supplier = _extract_supplier_display(root_comp)

    root_metadata = {
        "bom_format": bom_format,
        "spec_version": spec_version,
        "serial_number": serial_number,
        "document_version": doc_version,
        "timestamp": timestamp,
        "tools": tools_list,
        "authors": authors_list,
        "root_product": {
            "name": root_name,
            "version": root_version,
            "type": root_type,
            "supplier": root_supplier,
            "purl": root_comp.get("purl"),
            "cpe": root_comp.get("cpe"),
            "description": root_comp.get("description"),
        },
    }

    raw_components = sbom_dict.get("components")
    if not isinstance(raw_components, list):
        raw_components = []

    deps_list = sbom_dict.get("dependencies") if isinstance(sbom_dict.get("dependencies"), list) else []
    dep_refs = set()
    for dep in deps_list:
        if isinstance(dep, dict):
            r = dep.get("ref")
            if r:
                dep_refs.add(str(r))
            for child in dep.get("dependsOn", []):
                if child:
                    dep_refs.add(str(child))

    components: list[dict[str, Any]] = []
    field_gap_counts = {field: 0 for field in DESIRABLE_METADATA_FIELDS}
    core_count = 0
    third_party_count = 0
    complete_count = 0
    incomplete_count = 0

    for idx, comp in enumerate(raw_components):
        if not isinstance(comp, dict):
            continue
        analyzed = analyze_component(comp, idx, dep_refs=dep_refs)
        components.append(analyzed)

        if analyzed["is_core"]:
            core_count += 1
        else:
            third_party_count += 1

        missing = analyzed["missing_desirable"]
        if len(missing) == 0:
            complete_count += 1
        else:
            incomplete_count += 1
            for m in missing:
                field_gap_counts[m] += 1

    total_components = len(components)
    completeness_percentage = round((complete_count / total_components * 100), 1) if total_components > 0 else 100.0

    field_coverage_percentages = {
        field: round(((total_components - gap_cnt) / total_components * 100), 1) if total_components > 0 else 100.0
        for field, gap_cnt in field_gap_counts.items()
    }

    statistics = {
        "total_components": total_components,
        "complete_components": complete_count,
        "incomplete_components": incomplete_count,
        "completeness_percentage": completeness_percentage,
        "core_components_count": core_count,
        "third_party_components_count": third_party_count,
        "field_gap_counts": field_gap_counts,
        "field_coverage_percentages": field_coverage_percentages,
        "desirable_fields": DESIRABLE_METADATA_FIELDS,
        "field_labels": FIELD_LABELS,
    }

    component_matrix = [
        {
            "name": comp.get("name", "N/D"),
            "version": comp.get("version") or "vN/D",
            "has_version": "✓" if bool(comp.get("version")) else "✕",
            "is_core": bool(
                any(
                    isinstance(p, dict)
                    and p.get("name") == "company:core-component"
                    and str(p.get("value")).lower() == "true"
                    for p in (comp.get("properties") if isinstance(comp.get("properties"), list) else [])
                )
            ),
            "has_id": "✓" if bool(comp.get("purl") or comp.get("cpe")) else "✕",
            "has_supplier": "✓" if bool(comp.get("supplier") or comp.get("author") or comp.get("publisher")) else "✕",
            "has_hash": "✓" if bool(comp.get("hashes") and len(comp.get("hashes")) > 0) else "✕",
            "has_license": "✓" if is_spdx_license(comp) else ("!" if has_non_spdx_license(comp) else "✕"),
            "has_dependencies": "✓" if is_in_dependencies_graph(comp, dep_refs) else "✕",
        }
        for comp in raw_components
        if isinstance(comp, dict)
    ]

    return {
        "root_metadata": root_metadata,
        "statistics": statistics,
        "components": components,
        "component_matrix": component_matrix,
    }
