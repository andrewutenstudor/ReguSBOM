"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Differential & Drift Engine.
Computes deep semantic differences between two SBOM documents:
- Added, removed, and modified components
- Attribute drift: license changes, supplier changes, cryptographic hash drops
- Dependency graph delta: added vs removed edges
- Executive compliance and security posture delta
Supports CycloneDX (1.4-1.7) and SPDX (2.3-3.0.1).
"""
import logging
from typing import Dict, Any, List, Set, Tuple, Optional

logger = logging.getLogger("regubom.diff")


def _extract_component_dict(comp: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes a raw CycloneDX or SPDX component into a canonical structure."""
    name = str(comp.get("name") or comp.get("packageName") or "N/D").strip()
    version = str(comp.get("version") or comp.get("versionInfo") or comp.get("packageVersion") or "N/D").strip()

    # PURL and CPE extraction
    purl = comp.get("purl")
    if not purl and isinstance(comp.get("externalRefs"), list):
        for ref in comp.get("externalRefs"):
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
    purl_str = str(purl).strip() if purl else None

    cpe = comp.get("cpe")
    cpe_str = str(cpe).strip() if cpe else None

    # Supplier extraction
    supplier_raw = comp.get("supplier") or comp.get("packageSupplier")
    supplier_display = "N/D"
    if isinstance(supplier_raw, dict):
        supplier_display = str(supplier_raw.get("name") or supplier_raw.get("url") or "N/D").strip()
    elif isinstance(supplier_raw, str):
        supplier_display = supplier_raw.replace("Organization:", "").replace("Person:", "").strip()

    # License extraction
    licenses_found: List[str] = []
    if "licenses" in comp and isinstance(comp["licenses"], list):
        for lic_entry in comp["licenses"]:
            if isinstance(lic_entry, dict):
                lic_obj = lic_entry.get("license", {})
                if isinstance(lic_obj, dict):
                    lid = lic_obj.get("id") or lic_obj.get("name")
                    if lid:
                        licenses_found.append(str(lid).strip())
                elif "expression" in lic_entry:
                    licenses_found.append(str(lic_entry["expression"]).strip())
            elif isinstance(lic_entry, str):
                licenses_found.append(lic_entry.strip())
    elif "licenseConcluded" in comp:
        licenses_found.append(str(comp["licenseConcluded"]).strip())
    elif "licenseDeclared" in comp:
        licenses_found.append(str(comp["licenseDeclared"]).strip())

    license_display = ", ".join(licenses_found) if licenses_found else "N/D"

    # Hashes extraction
    hashes_map: Dict[str, str] = {}
    if "hashes" in comp and isinstance(comp["hashes"], list):
        for h in comp["hashes"]:
            if isinstance(h, dict) and h.get("alg") and h.get("content"):
                hashes_map[str(h["alg"]).upper()] = str(h["content"]).strip()
    elif "checksums" in comp and isinstance(comp["checksums"], list):
        for c in comp["checksums"]:
            if isinstance(c, dict) and c.get("algorithm") and c.get("checksumValue"):
                hashes_map[str(c["algorithm"]).upper()] = str(c["checksumValue"]).strip()

    has_strong_hash = bool(
        "SHA-256" in hashes_map or "SHA256" in hashes_map or
        "SHA-512" in hashes_map or "SHA512" in hashes_map
    )

    bom_ref = str(comp.get("bom-ref") or comp.get("SPDXID") or purl_str or f"{name}@{version}").strip()

    return {
        "name": name,
        "version": version,
        "purl": purl_str,
        "cpe": cpe_str,
        "supplier": supplier_display,
        "licenses": licenses_found,
        "license_display": license_display,
        "hashes": hashes_map,
        "has_strong_hash": has_strong_hash,
        "bom_ref": bom_ref,
        "type": str(comp.get("type") or comp.get("primaryPackagePurpose") or "library").strip(),
        "is_proprietary": bool(
            any(
                str(p.get("name", "")).startswith("regubom:proprietary") or
                str(p.get("name", "")).startswith("company:core-component")
                for p in comp.get("properties", [])
                if isinstance(p, dict)
            )
        ) if isinstance(comp.get("properties"), list) else False
    }


def _extract_all_components(sbom_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extracts all components from CycloneDX or SPDX."""
    raw_list: List[Dict[str, Any]] = []

    # CycloneDX
    if "components" in sbom_dict and isinstance(sbom_dict["components"], list):
        def _recurse_cdx(comps):
            for c in comps:
                if isinstance(c, dict):
                    raw_list.append(c)
                    sub = c.get("components")
                    if isinstance(sub, list):
                        _recurse_cdx(sub)
        _recurse_cdx(sbom_dict["components"])

    # SPDX packages
    elif "packages" in sbom_dict and isinstance(sbom_dict["packages"], list):
        for p in sbom_dict["packages"]:
            if isinstance(p, dict):
                raw_list.append(p)

    return [_extract_component_dict(c) for c in raw_list]


def _extract_dependency_edges(sbom_dict: Dict[str, Any]) -> Set[Tuple[str, str]]:
    """Extracts dependency graph directed edges: set of (source_ref, target_ref)."""
    edges: Set[Tuple[str, str]] = set()

    # CycloneDX dependencies
    if "dependencies" in sbom_dict and isinstance(sbom_dict["dependencies"], list):
        for dep in sbom_dict["dependencies"]:
            if isinstance(dep, dict):
                src = str(dep.get("ref", "")).strip()
                depends_on = dep.get("dependsOn", [])
                if src and isinstance(depends_on, list):
                    for dst in depends_on:
                        dst_str = str(dst).strip()
                        if dst_str:
                            edges.add((src, dst_str))

    # SPDX relationships
    elif "relationships" in sbom_dict and isinstance(sbom_dict["relationships"], list):
        for rel in sbom_dict["relationships"]:
            if isinstance(rel, dict):
                src = str(rel.get("spdxElementId", "")).strip()
                dst = str(rel.get("relatedSpdxElement", "")).strip()
                rel_type = str(rel.get("relationshipType", "")).upper()
                if src and dst and rel_type in ("DEPENDS_ON", "CONTAINS", "DESCRIBES"):
                    edges.add((src, dst))

    return edges


def compare_sboms(base_sbom_dict: Dict[str, Any], target_sbom_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes a comprehensive semantic differential between base and target SBOMs.
    Returns:
    - added_components
    - removed_components
    - modified_components (with version drift, license drift, supplier drift, hash drops)
    - dependency graph delta (added_edges, removed_edges)
    - summary & compliance posture delta
    """
    base_components = _extract_all_components(base_sbom_dict)
    target_components = _extract_all_components(target_sbom_dict)

    # Build index by component name for version/attribute drift tracking
    base_by_name: Dict[str, List[Dict[str, Any]]] = {}
    for c in base_components:
        base_by_name.setdefault(c["name"].lower(), []).append(c)

    target_by_name: Dict[str, List[Dict[str, Any]]] = {}
    for c in target_components:
        target_by_name.setdefault(c["name"].lower(), []).append(c)

    # Exact identity index by (name.lower(), version)
    base_by_identity: Dict[Tuple[str, str], Dict[str, Any]] = {
        (c["name"].lower(), c["version"]): c for c in base_components
    }
    target_by_identity: Dict[Tuple[str, str], Dict[str, Any]] = {
        (c["name"].lower(), c["version"]): c for c in target_components
    }

    added_components: List[Dict[str, Any]] = []
    removed_components: List[Dict[str, Any]] = []
    modified_components: List[Dict[str, Any]] = []

    matched_target_identities: Set[Tuple[str, str]] = set()
    matched_base_identities: Set[Tuple[str, str]] = set()

    # 1. Detect Library Name Matches (Check for Version & Attribute Drift)
    all_names = set(base_by_name.keys()).union(set(target_by_name.keys()))

    license_drift_count = 0
    hash_drop_count = 0
    supplier_drift_count = 0
    version_drift_count = 0

    for name_lower in all_names:
        base_matches = base_by_name.get(name_lower, [])
        target_matches = target_by_name.get(name_lower, [])

        # Scenario A: Library in both base and target
        if base_matches and target_matches:
            # Pair primary match
            b_comp = base_matches[0]
            t_comp = target_matches[0]

            matched_base_identities.add((b_comp["name"].lower(), b_comp["version"]))
            matched_target_identities.add((t_comp["name"].lower(), t_comp["version"]))

            # Check for changes
            version_changed = b_comp["version"] != t_comp["version"]
            license_changed = b_comp["license_display"] != t_comp["license_display"]
            supplier_changed = (
                b_comp["supplier"] != "N/D" and
                t_comp["supplier"] != "N/D" and
                b_comp["supplier"].lower() != t_comp["supplier"].lower()
            )
            # Hash drop: base had strong hash, target dropped it!
            hash_dropped = b_comp["has_strong_hash"] and not t_comp["has_strong_hash"]
            hash_added = not b_comp["has_strong_hash"] and t_comp["has_strong_hash"]

            has_drift = (
                version_changed or
                license_changed or
                supplier_changed or
                hash_dropped or
                hash_added
            )

            if has_drift:
                if version_changed:
                    version_drift_count += 1
                if license_changed:
                    license_drift_count += 1
                if hash_dropped:
                    hash_drop_count += 1
                if supplier_changed:
                    supplier_drift_count += 1

                modified_components.append({
                    "name": t_comp["name"],
                    "drift_type": "MODIFIED",
                    "base": {
                        "version": b_comp["version"],
                        "license": b_comp["license_display"],
                        "supplier": b_comp["supplier"],
                        "has_strong_hash": b_comp["has_strong_hash"],
                        "purl": b_comp["purl"],
                    },
                    "target": {
                        "version": t_comp["version"],
                        "license": t_comp["license_display"],
                        "supplier": t_comp["supplier"],
                        "has_strong_hash": t_comp["has_strong_hash"],
                        "purl": t_comp["purl"],
                    },
                    "drift": {
                        "version_changed": version_changed,
                        "license_changed": license_changed,
                        "supplier_changed": supplier_changed,
                        "hash_dropped": hash_dropped,
                        "hash_added": hash_added,
                    }
                })

        # Scenario B: Library only in target -> ADDED
        elif target_matches and not base_matches:
            for t_comp in target_matches:
                matched_target_identities.add((t_comp["name"].lower(), t_comp["version"]))
                added_components.append({
                    "name": t_comp["name"],
                    "version": t_comp["version"],
                    "license": t_comp["license_display"],
                    "supplier": t_comp["supplier"],
                    "purl": t_comp["purl"],
                    "has_strong_hash": t_comp["has_strong_hash"],
                    "drift_type": "ADDED",
                })

        # Scenario C: Library only in base -> REMOVED
        elif base_matches and not target_matches:
            for b_comp in base_matches:
                matched_base_identities.add((b_comp["name"].lower(), b_comp["version"]))
                removed_components.append({
                    "name": b_comp["name"],
                    "version": b_comp["version"],
                    "license": b_comp["license_display"],
                    "supplier": b_comp["supplier"],
                    "purl": b_comp["purl"],
                    "has_strong_hash": b_comp["has_strong_hash"],
                    "drift_type": "REMOVED",
                })

    # Catch any remaining unmatched items
    for ident, comp in target_by_identity.items():
        if ident not in matched_target_identities:
            added_components.append({
                "name": comp["name"],
                "version": comp["version"],
                "license": comp["license_display"],
                "supplier": comp["supplier"],
                "purl": comp["purl"],
                "has_strong_hash": comp["has_strong_hash"],
                "drift_type": "ADDED",
            })

    for ident, comp in base_by_identity.items():
        if ident not in matched_base_identities:
            removed_components.append({
                "name": comp["name"],
                "version": comp["version"],
                "license": comp["license_display"],
                "supplier": comp["supplier"],
                "purl": comp["purl"],
                "has_strong_hash": comp["has_strong_hash"],
                "drift_type": "REMOVED",
            })

    # 2. Dependency Graph Delta
    base_edges = _extract_dependency_edges(base_sbom_dict)
    target_edges = _extract_dependency_edges(target_sbom_dict)

    added_edges_raw = target_edges - base_edges
    removed_edges_raw = base_edges - target_edges

    added_edges = [{"source": src, "target": dst} for src, dst in added_edges_raw]
    removed_edges = [{"source": src, "target": dst} for src, dst in removed_edges_raw]

    # 3. Compliance & Risk Posture Delta
    base_missing_hashes = sum(1 for c in base_components if not c["has_strong_hash"])
    target_missing_hashes = sum(1 for c in target_components if not c["has_strong_hash"])
    hash_security_delta = target_missing_hashes - base_missing_hashes

    # Overall posture: if hash drops or degraded -> DEGRADED
    if hash_drop_count > 0 or hash_security_delta > 5:
        posture_verdict = "DEGRADED"
        posture_message = f"Rilevato degrado di sicurezza: {hash_drop_count} hash crittografici eliminati nel target."
    elif hash_security_delta < 0 and hash_drop_count == 0:
        posture_verdict = "IMPROVED"
        posture_message = f"Postura di sicurezza migliorata: copertura hash aumentata su {-hash_security_delta} componenti."
    else:
        posture_verdict = "STABLE"
        posture_message = "Postura di conformità e integrità stabile tra i rilasci."

    return {
        "summary": {
            "base_total_components": len(base_components),
            "target_total_components": len(target_components),
            "net_component_delta": len(target_components) - len(base_components),
            "added_count": len(added_components),
            "removed_count": len(removed_components),
            "modified_count": len(modified_components),
            "unchanged_count": max(0, len(base_components) - len(removed_components) - len(modified_components)),
            "license_drift_count": license_drift_count,
            "hash_drop_count": hash_drop_count,
            "supplier_drift_count": supplier_drift_count,
            "version_drift_count": version_drift_count,
            "edges_added_count": len(added_edges),
            "edges_removed_count": len(removed_edges),
            "posture_verdict": posture_verdict,
            "posture_message": posture_message,
        },
        "added_components": added_components,
        "removed_components": removed_components,
        "modified_components": modified_components,
        "dependency_graph_delta": {
            "added_edges": added_edges,
            "removed_edges": removed_edges,
            "total_base_edges": len(base_edges),
            "total_target_edges": len(target_edges),
        }
    }
