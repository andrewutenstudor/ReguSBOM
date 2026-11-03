"""
SBOM Auto-Mender Utility / Middleware.

Automatically resolves common SBOM schema issues and formatting flaws:
1. Injects current UTC timestamp if metadata.timestamp is missing or empty.
2. Maps common invalid/loose license strings (e.g., 'Apache 2', 'GPL 3') to valid SPDX identifiers ('Apache-2.0', 'GPL-3.0-only').
"""

import re
import copy
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
try:
    import orjson
except ImportError:
    orjson = None

logger = logging.getLogger(__name__)

# Common non-standard license strings mapped to official SPDX License Identifiers
COMMON_LICENSE_MAP: Dict[str, str] = {
    # Apache variants
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache v2": "Apache-2.0",
    "apache v2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    "apache software license, version 2.0": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "asl 2": "Apache-2.0",
    "apache 1.1": "Apache-1.1",
    "apache 1.0": "Apache-1.0",

    # GPL 3 variants
    "gpl 3": "GPL-3.0-only",
    "gpl 3.0": "GPL-3.0-only",
    "gpl-3": "GPL-3.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gplv3": "GPL-3.0-only",
    "gpl v3": "GPL-3.0-only",
    "gnu gpl 3": "GPL-3.0-only",
    "gnu gpl v3": "GPL-3.0-only",
    "gnu general public license 3": "GPL-3.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "gnu general public license, version 3": "GPL-3.0-only",
    "gnu general public license version 3": "GPL-3.0-only",
    "gpl-3.0-only": "GPL-3.0-only",
    "gpl-3.0-or-later": "GPL-3.0-or-later",
    "gpl 3+": "GPL-3.0-or-later",
    "gpl-3+": "GPL-3.0-or-later",
    "gplv3+": "GPL-3.0-or-later",

    # GPL 2 variants
    "gpl 2": "GPL-2.0-only",
    "gpl 2.0": "GPL-2.0-only",
    "gpl-2": "GPL-2.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gplv2": "GPL-2.0-only",
    "gpl v2": "GPL-2.0-only",
    "gnu gpl 2": "GPL-2.0-only",
    "gnu gpl v2": "GPL-2.0-only",
    "gnu general public license 2": "GPL-2.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license, version 2": "GPL-2.0-only",
    "gnu general public license version 2": "GPL-2.0-only",
    "gpl-2.0-only": "GPL-2.0-only",
    "gpl-2.0-or-later": "GPL-2.0-or-later",
    "gpl 2+": "GPL-2.0-or-later",
    "gpl-2+": "GPL-2.0-or-later",
    "gplv2+": "GPL-2.0-or-later",

    # LGPL variants
    "lgpl 3": "LGPL-3.0-only",
    "lgpl 3.0": "LGPL-3.0-only",
    "lgpl-3": "LGPL-3.0-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgplv3": "LGPL-3.0-only",
    "lgpl v3": "LGPL-3.0-only",
    "gnu lgpl 3": "LGPL-3.0-only",
    "gnu lgpl v3": "LGPL-3.0-only",
    "lgpl 2.1": "LGPL-2.1-only",
    "lgpl 2.1+": "LGPL-2.1-or-later",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgpl v2.1": "LGPL-2.1-only",
    "gnu lgpl 2.1": "LGPL-2.1-only",
    "lgpl 2": "LGPL-2.0-only",
    "lgpl 2.0": "LGPL-2.0-only",

    # MIT variants
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",

    # BSD variants
    "bsd": "BSD-3-Clause",
    "bsd 3": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3 clause": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "revised bsd license": "BSD-3-Clause",
    "bsd 2": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd 2 clause": "BSD-2-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "freebsd license": "BSD-2-Clause",

    # Other common licenses
    "isc": "ISC",
    "isc license": "ISC",
    "mpl 2.0": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "mpl 2": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "mozilla public license, version 2.0": "MPL-2.0",
    "cddl 1.0": "CDDL-1.0",
    "cddl-1.0": "CDDL-1.0",
    "epl 1.0": "EPL-1.0",
    "epl-1.0": "EPL-1.0",
    "epl 2.0": "EPL-2.0",
    "epl-2.0": "EPL-2.0",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0 1.0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
}


def _normalize_license_str(val: str) -> str:
    """Normalize a license string for dictionary lookup."""
    return re.sub(r"\s+", " ", str(val).strip()).lower()


def map_license_identifier(val: Optional[str]) -> Optional[str]:
    """
    Return a standardized SPDX identifier for known common license strings,
    or None if no mapping is found.
    """
    if not val or not isinstance(val, str):
        return None
    cleaned = _normalize_license_str(val)
    return COMMON_LICENSE_MAP.get(cleaned)


def _mend_license_entry(lic_entry: Any) -> None:
    """
    Mend an individual CycloneDX license choice entry.
    Ensures that if an invalid string is mapped to an SPDX identifier,
    it is assigned to 'id' and any conflicting 'name' is cleared so strict
    oneOf schema checks pass.
    """
    if not isinstance(lic_entry, dict):
        return

    # Case 1: {"license": {"id": "...", "name": "..."}}
    if "license" in lic_entry and isinstance(lic_entry["license"], dict):
        lic_obj = lic_entry["license"]
        orig_id = lic_obj.get("id")
        orig_name = lic_obj.get("name")

        mapped_id = map_license_identifier(orig_id) if orig_id else None
        mapped_name = map_license_identifier(orig_name) if orig_name else None
        target_spdx = mapped_id or mapped_name

        if target_spdx:
            lic_obj["id"] = target_spdx
            # CycloneDX v1.6 license schema enforces oneOf: either 'id' or 'name', never both!
            lic_obj.pop("name", None)

    # Case 2: {"expression": "..."}
    elif "expression" in lic_entry and isinstance(lic_entry["expression"], str):
        mapped_expr = map_license_identifier(lic_entry["expression"])
        if mapped_expr:
            lic_entry["expression"] = mapped_expr


def _mend_component(comp: Dict[str, Any]) -> None:
    """Mend license fields in a single component and recurse into subcomponents."""
    if not isinstance(comp, dict):
        return

    licenses = comp.get("licenses")
    if isinstance(licenses, list):
        for idx, lic_item in enumerate(licenses):
            if isinstance(lic_item, dict):
                _mend_license_entry(lic_item)
            elif isinstance(lic_item, str):
                # Loose format: list of string licenses -> convert to valid CycloneDX structure
                mapped = map_license_identifier(lic_item)
                if mapped:
                    licenses[idx] = {"license": {"id": mapped}}
                else:
                    licenses[idx] = {"license": {"name": lic_item}}

    # Recurse into nested components
    nested = comp.get("components")
    if isinstance(nested, list):
        for sub in nested:
            _mend_component(sub)


def mend_sbom(raw_json: Dict[str, Any], in_place: bool = True) -> Dict[str, Any]:
    """
    Auto-mend an SBOM dictionary to fix common schema and compliance flaws.

    1. Checks if metadata.timestamp is missing or blank; if so, injects the current UTC timestamp.
    2. Scans component licenses for common invalid strings (e.g., 'Apache 2', 'GPL 3')
       and replaces them with valid SPDX identifiers ('Apache-2.0', 'GPL-3.0-only').
    3. Handles CycloneDX components, nested components, metadata.component, services,
       as well as SPDX packages.

    :param raw_json: The SBOM dictionary.
    :param in_place: If True, mutates the dictionary in-place to avoid high memory & CPU clone costs.
                     If False, fast-clones using orjson (or copy.deepcopy fallback).
    Returns the mended dictionary.
    """
    if not isinstance(raw_json, dict):
        return raw_json

    if in_place:
        sbom = raw_json
    else:
        if orjson is not None:
            try:
                sbom = orjson.loads(orjson.dumps(raw_json))
            except Exception:
                sbom = copy.deepcopy(raw_json)
        else:
            sbom = copy.deepcopy(raw_json)

    # 1. Metadata timestamp auto-injection
    metadata = sbom.get("metadata")
    if metadata is None or not isinstance(metadata, dict):
        metadata = {}
        sbom["metadata"] = metadata

    current_timestamp = metadata.get("timestamp")
    if not current_timestamp or not str(current_timestamp).strip():
        injected_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        metadata["timestamp"] = injected_ts
        logger.info(f"[Auto-Mend] Injected missing metadata.timestamp: {injected_ts}")

    # Mend metadata.component if present
    if isinstance(metadata.get("component"), dict):
        _mend_component(metadata["component"])

    # 2. Scan and mend CycloneDX components
    components = sbom.get("components")
    if isinstance(components, list):
        for comp in components:
            _mend_component(comp)

    # Scan and mend CycloneDX services
    services = sbom.get("services")
    if isinstance(services, list):
        for s in services:
            if isinstance(s, dict):
                _mend_component(s)

    # 3. Scan and mend SPDX packages if SPDX format is supplied
    packages = sbom.get("packages")
    if isinstance(packages, list):
        for pkg in packages:
            if isinstance(pkg, dict):
                for lic_field in ("licenseConcluded", "licenseDeclared"):
                    val = pkg.get(lic_field)
                    if val and isinstance(val, str):
                        mapped = map_license_identifier(val)
                        if mapped:
                            pkg[lic_field] = mapped

    return sbom
