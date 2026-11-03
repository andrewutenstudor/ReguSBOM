"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
ENISA Technical Advisory (October 2026) Compliance Engine.

Integrates:
- ENISA Technical Advisory on SBOM (October 2026)
- BSI TR-03183-2 v2.1.0 ("Cyber Resilience Requirements for SBOM")
- CISA 2026 Minimum Elements for Software Bill of Materials
- EU Cyber Resilience Act (CRA) Art. 13 & Annex II Technical Documentation
"""

import logging
import re
from datetime import UTC, datetime
from typing import Any

from app.core.schema_engine import validate_sbom_schema_airgap

logger = logging.getLogger("regubom.enisa")

# Supported Regulatory SBOM Standards
SUPPORTED_STANDARDS = {
    "cyclonedx": {"1.6", "1.7"},
    "spdx": {"2.3", "SPDX-2.3", "3.0.1", "SPDX-3.0.1"},
}

LIFECYCLE_PHASES = {
    "design",
    "source",
    "build",
    "analysed",
    "analyzed",
    "deployed",
    "runtime",
    "pre-build",
    "post-build",
    "operations",
    "discovery",
    "decommission",
}

# Standard RFC 5322 simplified email regex
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
# Standard URL regex
URL_REGEX = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
# PURL regex (RFC draft / spec)
PURL_REGEX = re.compile(r"^pkg:[a-zA-Z0-9._-]+/[a-zA-Z0-9._@%/-]+", re.IGNORECASE)
# CPE 2.3 / 2.2 regex
CPE_REGEX = re.compile(
    r"^cpe:(?:2\.3:[aho](?::[a-zA-Z0-9._~%-]+){10}|/[aho]:[a-zA-Z0-9._~%-]+)",
    re.IGNORECASE,
)

# Official SPDX 3.25+ License Identifiers (Core Canonical Set)
SPDX_LICENSE_IDS = frozenset(
    [
        "0bsd",
        "aal",
        "abstyles",
        "adsl",
        "afl-1.1",
        "afl-1.2",
        "afl-2.0",
        "afl-2.1",
        "afl-3.0",
        "agpl-1.0-only",
        "agpl-1.0-or-later",
        "agpl-3.0-only",
        "agpl-3.0-or-later",
        "aladdin",
        "aml",
        "ampas",
        "antlr-pd",
        "antlr-pd-fallback",
        "apache-1.0",
        "apache-1.1",
        "apache-2.0",
        "apafml",
        "apl-1.0",
        "app-s2p",
        "apsl-1.0",
        "apsl-1.1",
        "apsl-1.2",
        "apsl-2.0",
        "arphic-1999",
        "artistic-1.0",
        "artistic-1.0-cl8",
        "artistic-1.0-perl",
        "artistic-2.0",
        "baekmuk",
        "barr",
        "beerware",
        "bittorrent-1.0",
        "bittorrent-1.1",
        "borceux",
        "bsd-1-clause",
        "bsd-2-clause",
        "bsd-2-clause-freebsd",
        "bsd-2-clause-netbsd",
        "bsd-2-clause-patent",
        "bsd-2-clause-views",
        "bsd-3-clause",
        "bsd-3-clause-attribution",
        "bsd-3-clause-clear",
        "bsd-3-clause-lbnl",
        "bsd-3-clause-modification",
        "bsd-3-clause-no-military-license",
        "bsd-3-clause-no-nuclear-license",
        "bsd-3-clause-no-nuclear-license-2014",
        "bsd-3-clause-no-nuclear-warranty",
        "bsd-3-clause-open-mpi",
        "bsd-4-clause",
        "bsd-4-clause-shortened",
        "bsd-4-clause-uc",
        "bsd-protection",
        "bsl-1.0",
        "bzip2-1.0.5",
        "bzip2-1.0.6",
        "cal-1.0",
        "cal-1.0-combined-work-exception",
        "caldera",
        "catosl-1.1",
        "cc-by-1.0",
        "cc-by-2.0",
        "cc-by-2.5",
        "cc-by-3.0",
        "cc-by-4.0",
        "cc-by-nc-1.0",
        "cc-by-nc-2.0",
        "cc-by-nc-2.5",
        "cc-by-nc-3.0",
        "cc-by-nc-4.0",
        "cc-by-nc-nd-1.0",
        "cc-by-nc-nd-2.0",
        "cc-by-nc-nd-2.5",
        "cc-by-nc-nd-3.0",
        "cc-by-nc-nd-4.0",
        "cc-by-nc-sa-1.0",
        "cc-by-nc-sa-2.0",
        "cc-by-nc-sa-2.5",
        "cc-by-nc-sa-3.0",
        "cc-by-nc-sa-4.0",
        "cc-by-nd-1.0",
        "cc-by-nd-2.0",
        "cc-by-nd-2.5",
        "cc-by-nd-3.0",
        "cc-by-nd-4.0",
        "cc-by-sa-1.0",
        "cc-by-sa-2.0",
        "cc-by-sa-2.5",
        "cc-by-sa-3.0",
        "cc-by-sa-4.0",
        "cc-pddc",
        "cc0-1.0",
        "cddl-1.0",
        "cddl-1.1",
        "cdla-permissive-1.0",
        "cdla-permissive-2.0",
        "cdla-sharing-1.0",
        "cecill-1.0",
        "cecill-1.1",
        "cecill-2.0",
        "cecill-2.1",
        "cecill-b",
        "cecill-c",
        "cern-ohl-1.1",
        "cern-ohl-1.2",
        "cern-ohl-p-2.0",
        "cern-ohl-s-2.0",
        "cern-ohl-w-2.0",
        "cfitsiio",
        "checkmk",
        "clartistic",
        "clips",
        "cmu-mach",
        "cnri-jython",
        "cnri-python",
        "cnri-python-gpl-compatible",
        "condor-1.1",
        "copyleft-next-0.3.0",
        "copyleft-next-0.3.1",
        "cpal-1.0",
        "cpl-1.0",
        "cptycl",
        "crossword",
        "crystalstacker",
        "cua-opl-1.0",
        "cube",
        "curl",
        "d-fsl-1.0",
        "diffmark",
        "doc",
        "dotseqn",
        "dsdp",
        "dtoa",
        "dvipdfm",
        "ecl-1.0",
        "ecl-2.0",
        "efl-1.0",
        "efl-2.0",
        "egenix",
        "entessa",
        "epics",
        "epl-1.0",
        "epl-2.0",
        "erlpl-1.1",
        "etalfir-1.0",
        "eudatagrid",
        "eupl-1.0",
        "eupl-1.1",
        "eupl-1.2",
        "eurosym",
        "fair",
        "fbm",
        "fdl-1.1-only",
        "fdl-1.1-or-later",
        "fdl-1.2-only",
        "fdl-1.2-or-later",
        "fdl-1.3-only",
        "fdl-1.3-or-later",
        "freebsd-doc",
        "freeimage",
        "fsfap",
        "fsful",
        "fsfullr",
        "ftl",
        "gcr-docs",
        "gd",
        "giftware",
        "gl2ps",
        "glide",
        "glulxe",
        "gnuplot",
        "gpl-1.0-only",
        "gpl-1.0-or-later",
        "gpl-2.0-only",
        "gpl-2.0-or-later",
        "gpl-3.0-only",
        "gpl-3.0-or-later",
        "gsoap-1.3b",
        "haskellreport",
        "hippocratic-2.1",
        "hp-1986",
        "hpnd",
        "hpnd-sell-variant",
        "htmltidy",
        "ibm-pibs",
        "icu",
        "iec-code-components-eula",
        "ijg",
        "ijg-short",
        "imagemagick",
        "imatix",
        "imlib2",
        "info-zip",
        "inner-net-2.0",
        "intel",
        "intel-acpi",
        "interbase-1.0",
        "ipa",
        "ipl-1.0",
        "isc",
        "jam",
        "jasper-2.0",
        "jpl-image",
        "jpnic",
        "json",
        "kfgpl",
        "lal-1.2",
        "lal-1.3",
        "latex2e",
        "leptonica",
        "lgpl-2.0-only",
        "lgpl-2.0-or-later",
        "lgpl-2.1-only",
        "lgpl-2.1-or-later",
        "lgpl-3.0-only",
        "lgpl-3.0-or-later",
        "lgtm",
        "libpng",
        "libpng-2.0",
        "libselinux-1.0",
        "libtiff",
        "libutil-david-gibson",
        "liliq-p-1.1",
        "liliq-r-1.1",
        "liliq-rplus-1.1",
        "linux-man-pages-1-para",
        "linux-man-pages-copyleft",
        "linux-man-pages-copyleft-2-para",
        "linux-man-pages-copyleft-var",
        "linux-openib",
        "loop",
        "lpl-1.0",
        "lpl-1.02",
        "lppl-1.0",
        "lppl-1.1",
        "lppl-1.2",
        "lppl-1.3a",
        "lppl-1.3c",
        "lzma-sdk-9.22",
        "makeindex",
        "mips",
        "mit",
        "mit-0",
        "mit-advertising",
        "mit-cmu",
        "mit-enna",
        "mit-feh",
        "mit-modern-variant",
        "mit-open-group",
        "mit-wu",
        "mitnfa",
        "motosoto",
        "mpi-permissive",
        "mpich2",
        "mpl-1.0",
        "mpl-1.1",
        "mpl-2.0",
        "mpl-2.0-no-copyleft-exception",
        "mplus",
        "mup",
        "naist-2003",
        "nasa-1.3",
        "naumen",
        "nbpl-1.0",
        "ncgl-uk-2.0",
        "ncsa",
        "net-snmp",
        "netcdf",
        "newsletr",
        "ngpl",
        "nicta-1.0",
        "nist-pd",
        "nist-pd-fallback",
        "nist-software",
        "nlod-1.0",
        "nlod-2.0",
        "nlpl",
        "nokia",
        "nosl",
        "noweb",
        "npl-1.0",
        "npl-1.1",
        "nposl-3.0",
        "nrl",
        "ntp",
        "ntp-0",
        "nunit",
        "o-uda-1.0",
        "occt-pl",
        "oclc-2.0",
        "odbl-1.0",
        "odc-by-1.0",
        "offis",
        "ofl-1.0",
        "ofl-1.0-no-rfn",
        "ofl-1.0-rfn",
        "ofl-1.1",
        "ofl-1.1-no-rfn",
        "ofl-1.1-rfn",
        "ogc-1.0",
        "ogdl-taiwan-1.0",
        "ogl-canada-2.0",
        "ogl-uk-1.0",
        "ogl-uk-2.0",
        "ogl-uk-3.0",
        "ogtsl",
        "oldap-1.1",
        "oldap-1.2",
        "oldap-1.3",
        "oldap-1.4",
        "oldap-2.0",
        "oldap-2.0.1",
        "oldap-2.1",
        "oldap-2.2",
        "oldap-2.2.1",
        "oldap-2.2.2",
        "oldap-2.3",
        "oldap-2.4",
        "oldap-2.5",
        "oldap-2.6",
        "oldap-2.7",
        "oldap-2.8",
        "olfl-1.3",
        "oml",
        "openssl",
        "opl-1.0",
        "opl-uk-3.0",
        "oset-pl-2.1",
        "osl-1.0",
        "osl-1.1",
        "osl-2.0",
        "osl-2.1",
        "osl-3.0",
        "parity-6.0.0",
        "parity-7.0.0",
        "pddl-1.0",
        "php-3.0",
        "php-3.01",
        "plexus",
        "polyform-noncommercial-1.0.0",
        "polyform-small-business-1.0.0",
        "postgresql",
        "psf-2.0",
        "psfrag",
        "psutils",
        "python-2.0",
        "python-2.0.1",
        "python-ldap",
        "qhull",
        "qpl-1.0",
        "radvd",
        "rdisc",
        "rpsl-1.0",
        "rsa-md",
        "rscpl",
        "ruby",
        "saftp",
        "sax-pd",
        "saxpath",
        "scea",
        "schemereport",
        "sendmail",
        "sendmail-8.23",
        "sgi-b-1.0",
        "sgi-b-1.1",
        "sgi-b-2.0",
        "sgp4",
        "shl-0.5",
        "shl-0.51",
        "simpl-2.0",
        "sisscl",
        "sisscl-1.2",
        "sleepycat",
        "smlnj",
        "smppl",
        "snia",
        "snprintf",
        "sorcmc",
        "spencer-86",
        "spencer-94",
        "spencer-99",
        "spl-1.0",
        "ssh-keyscan",
        "ssh-openssh",
        "ssleay",
        "sspl-1.0",
        "standardml-nj",
        "sugarcrm-1.1.3",
        "sunpro",
        "swl",
        "symlinks",
        "tapr-ohl-1.0",
        "tcl",
        "tcp-wrappers",
        "termchem",
        "thirdeye",
        "threatgrid",
        "tldr-pages",
        "torque-1.1",
        "tosl",
        "tpdl",
        "tpl-1.0",
        "ttwl",
        "tu-berlin-1.0",
        "tu-berlin-2.0",
        "ucar",
        "ucl-1.0",
        "unicode-dfs-2015",
        "unicode-dfs-2016",
        "unicode-inc-2024",
        "unicode-tou",
        "unixcrypt",
        "unlicense",
        "upl-1.0",
        "vim",
        "vostrom",
        "vsl-1.0",
        "w3c",
        "w3c-19980720",
        "w3c-20150513",
        "w3m",
        "watcom-1.0",
        "widget-workshop",
        "wsuipa",
        "wtfpl",
        "wxwindows",
        "x11",
        "x11-distribute-modifications-variant",
        "x11-swapped",
        "xfree86-1.1",
        "xinetd",
        "xlock",
        "xnet",
        "xpp",
        "xskat",
        "ypl-1.0",
        "ypl-1.1",
        "zed",
        "zeepl-1.0",
        "zend-2.0",
        "zimbra-1.3",
        "zimbra-1.4",
        "zlib",
        "zlib-acknowledgement",
        "zpl-1.1",
        "zpl-2.0",
        "zpl-2.1",
    ]
)


def is_valid_spdx_expression(expr: str) -> bool:
    """
    Validates whether a license expression or ID conforms to SPDX specification.
    Supports complex expressions like 'MIT OR Apache-2.0', 'GPL-3.0-only WITH Classpath-exception-2.0',
    or user-defined 'LicenseRef-Proprietary'.
    """
    if not expr or not isinstance(expr, str):
        return False
    clean = expr.strip()
    if not clean:
        return False

    # Check direct single license match (case-insensitive)
    lower = clean.lower()
    if lower in SPDX_LICENSE_IDS:
        return True
    if lower.startswith("licenseref-"):
        return True

    # Tokenize complex expression
    # Operators: AND, OR, WITH, +, parentheses
    tokens = re.split(r"[\s()]+", clean)
    valid_operators = {"AND", "OR", "WITH"}

    has_license_token = False
    for token in tokens:
        if not token:
            continue
        token_clean = token.strip("+")
        if token_clean in valid_operators:
            continue
        token_lower = token_clean.lower()
        if token_lower in SPDX_LICENSE_IDS or token_lower.startswith("licenseref-"):
            has_license_token = True
        else:
            return False

    return has_license_token


def is_email_or_url(contact: str | None) -> bool:
    """Validates if contact string is an RFC 5322 email or valid URL."""
    if not contact or not isinstance(contact, str):
        return False
    c = contact.strip()
    if EMAIL_REGEX.match(c):
        return True
    if URL_REGEX.match(c):
        return True
    # If wrapped in brackets e.g. "Jane Doe <jane@example.com>"
    sub_email = re.findall(r"<([^>]+)>", c)
    if sub_email and EMAIL_REGEX.match(sub_email[0].strip()):
        return True
    return False


def is_valid_utc_timestamp(ts: str | None) -> bool:
    """Validates if timestamp is a valid RFC 3339 / ISO 8601 UTC timestamp."""
    if not ts or not isinstance(ts, str):
        return False
    clean = ts.strip()
    if not clean:
        return False
    # Check for UTC markers (Z or +00:00)
    has_utc_indicator = clean.endswith("Z") or clean.endswith("+00:00") or clean.endswith("+0000")
    try:
        # Standard ISO 8601 parsing
        dt = datetime.fromisoformat(clean.replace("Z", "+00:00"))
        return has_utc_indicator or (dt.tzinfo is not None and dt.utcoffset() == UTC.utcoffset(dt))
    except Exception:
        # Fallback regex for common RFC 3339 patterns
        return bool(re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$", clean))


class EnisaComplianceAuditor:
    """
    Evaluates SBOMs against ENISA Technical Advisory (October 2026),
    BSI TR-03183-2 v2.1.0, and CISA Minimum Elements.
    """

    def __init__(
        self,
        proprietary_prefix: str = "regubom:proprietary",
        proprietary_supplier: str | None = None,
    ):
        self.proprietary_prefix = (proprietary_prefix or "regubom:proprietary").strip().lower()
        self.proprietary_supplier = (proprietary_supplier or "").strip().lower()

    def audit(self, sbom_dict: dict[str, Any], file_imprint: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Executes comprehensive ENISA/BSI audit on an SBOM dictionary.
        Returns a complete dossier including:
        - Format & Standard verdict
        - Table 1 Document Metadata Audit
        - 12-point Regulatory Checklist
        - Component Completeness Matrix with bifurcated 1st vs 3rd party logic
        - Executive statistics & compliance certificate payload
        """
        if not isinstance(sbom_dict, dict):
            raise ValueError("Invalid SBOM dictionary payload")

        # 1. Format & Standard Identification
        format_info = self._detect_format_and_version(sbom_dict)
        is_cyclonedx = format_info["format"] == "cyclonedx"
        is_spdx = format_info["format"] == "spdx"

        # 1.5 Air-Gap Strict JSON Schema Validation (Zero-Telemetry)
        schema_valid, schema_err = validate_sbom_schema_airgap(sbom_dict, format_info["format"], format_info["version"])

        # 2. Document Metadata Audit (Table 1: Creator, Timestamp, Lifecycle, Tools, Signatures)
        doc_metadata = self._audit_document_metadata(sbom_dict, format_info)

        # 3. Component Extraction & Graph Resolution
        components_raw, dependency_graph = self._extract_components_and_graph(sbom_dict, format_info)

        # 4. Component Completeness Matrix Evaluation (BSI/CISA + Bifurcated 1st vs 3rd party)
        matrix_rows, matrix_stats = self._evaluate_components(components_raw, dependency_graph)

        # 5. Build 12-Point Regulatory Checklist
        checklist = self._build_12_point_checklist(
            format_info,
            doc_metadata,
            matrix_rows,
            matrix_stats,
            schema_valid=schema_valid,
            schema_err=schema_err,
        )

        # 6. Overall Compliance Verdict
        # Rules:
        # - Any FAIL on mandatory points (format, timestamp, root product, proprietary component gaps) -> FAIL
        # - Missing supplier/hashes on 3rd party OSS -> WARNING
        # - All passed -> PASS
        has_critical_failure = any(item["status"] == "FAIL" for item in checklist)
        has_warnings = (
            any(item["status"] == "WARNING" for item in checklist) or matrix_stats["proprietary_with_gaps"] > 0
        )

        if has_critical_failure or matrix_stats["proprietary_with_gaps"] > 0:
            overall_status = "FAIL"
            overall_valid = False
        elif has_warnings or matrix_stats["third_party_with_gaps"] > 0:
            overall_status = "WARNING"
            overall_valid = True
        else:
            overall_status = "PASS"
            overall_valid = True

        # 7. File Imprint Fallback
        imprint = file_imprint or {
            "sha256": "N/D",
            "sha512": "N/D",
            "file_size_mb": 0.0,
            "file_size_bytes": 0,
        }

        # 8. Certificate Payload for CRA Art. 13 Export
        certificate_data = {
            "regubom_gateway_version": "2.0.0",
            "standard_profile": "ENISA-Technical-Advisory-2026 / BSI TR-03183-2 v2.1.0",
            "audit_timestamp": datetime.now(UTC).isoformat(),
            "overall_status": overall_status,
            "overall_valid": overall_valid,
            "format": format_info["display"],
            "document_metadata": doc_metadata,
            "statistics": matrix_stats,
            "file_imprint": imprint,
        }

        return {
            "overall_status": overall_status,
            "overall_valid": overall_valid,
            "format_info": format_info,
            "document_metadata": doc_metadata,
            "root_product": doc_metadata.get("root_product", {}),
            "file_imprint": imprint,
            "cra_checklist": checklist,
            "component_matrix": matrix_rows,
            "statistics": matrix_stats,
            "certificate_data": certificate_data,
        }

    # -------------------------------------------------------------------------
    # Format & Spec Detection
    # -------------------------------------------------------------------------
    def _detect_format_and_version(self, data: dict[str, Any]) -> dict[str, Any]:
        """Identifies standard format, schema version, and regulatory acceptance."""
        bom_format = str(data.get("bomFormat", "")).strip()
        spec_version = str(data.get("specVersion", "")).strip()

        spdx_version = str(data.get("spdxVersion", "")).strip()
        is_spdx_3 = (
            "@context" in data
            or data.get("type") == "SpdxDocument"
            or "spdxVersion" in data
            and "3." in str(data.get("spdxVersion"))
        )

        if bom_format.lower() == "cyclonedx":
            is_supported = spec_version in SUPPORTED_STANDARDS["cyclonedx"]
            return {
                "format": "cyclonedx",
                "version": spec_version or "unknown",
                "display": f"CycloneDX v{spec_version}" if spec_version else "CycloneDX (Unknown)",
                "standard": "ECMA-424",
                "is_supported": is_supported,
                "regulatory_verdict": "CONFORME" if is_supported else "NON_CONFORME",
            }
        elif spdx_version or is_spdx_3:
            raw_v = "3.0.1" if is_spdx_3 and not spdx_version else spdx_version
            clean_v = raw_v.replace("SPDX-", "")
            is_supported = clean_v in ("2.3", "3.0.1") or raw_v in SUPPORTED_STANDARDS["spdx"]
            return {
                "format": "spdx",
                "version": clean_v or "unknown",
                "display": f"SPDX v{clean_v}" if clean_v else "SPDX (Unknown)",
                "standard": "ISO/IEC 5962:2021",
                "is_supported": is_supported,
                "regulatory_verdict": "CONFORME" if is_supported else "NON_CONFORME",
            }

        return {
            "format": "unknown",
            "version": "unknown",
            "display": "Unknown Format",
            "standard": "Unrecognized",
            "is_supported": False,
            "regulatory_verdict": "NON_CONFORME",
        }

    # -------------------------------------------------------------------------
    # Table 1: Document Metadata Audit
    # -------------------------------------------------------------------------
    def _audit_document_metadata(self, data: dict[str, Any], format_info: dict[str, Any]) -> dict[str, Any]:
        """Audits Table 1 elements: Author, Timestamp, Lifecycle, Tools, Signatures."""
        metadata = data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {}
        is_cdx = format_info["format"] == "cyclonedx"
        is_spdx = format_info["format"] == "spdx"

        # 1. Author / Creator (RFC 5322 email or valid URL)
        authors_found: list[str] = []
        author_valid = False

        if is_cdx:
            # Check metadata.authors
            authors = metadata.get("authors")
            if isinstance(authors, list):
                for a in authors:
                    if isinstance(a, dict):
                        email = a.get("email")
                        name = a.get("name")
                        phone = a.get("phone")
                        contact_str = f"{name} <{email}>" if email and name else (email or name or "")
                        if contact_str:
                            authors_found.append(contact_str)
                        if is_email_or_url(email) or is_email_or_url(contact_str):
                            author_valid = True
            # Check metadata.manufacture / supplier
            for entity_key in ("manufacture", "supplier"):
                ent = metadata.get(entity_key)
                if isinstance(ent, dict):
                    name = ent.get("name", "")
                    url_list = ent.get("url", [])
                    contact = ent.get("contact", [])
                    if isinstance(url_list, list):
                        for u in url_list:
                            if is_email_or_url(u):
                                author_valid = True
                                authors_found.append(f"{name} ({u})")
                    elif isinstance(url_list, str) and is_email_or_url(url_list):
                        author_valid = True
                        authors_found.append(f"{name} ({url_list})")
                    if isinstance(contact, list):
                        for c in contact:
                            if isinstance(c, dict) and is_email_or_url(c.get("email")):
                                author_valid = True
                                authors_found.append(c.get("email"))

        elif is_spdx:
            creation_info = data.get("creationInfo", {})
            creators = creation_info.get("creators", [])
            if isinstance(creators, list):
                for c in creators:
                    if isinstance(c, str):
                        authors_found.append(c)
                        if is_email_or_url(c):
                            author_valid = True

        # 2. Timestamp (Valid UTC RFC 3339)
        raw_timestamp = metadata.get("timestamp") if is_cdx else data.get("creationInfo", {}).get("created")
        timestamp_valid = is_valid_utc_timestamp(str(raw_timestamp)) if raw_timestamp else False

        # 3. Generation Context & Lifecycle Type
        lifecycle_phase = None
        has_lifecycle = False

        if is_cdx:
            lifecycles = metadata.get("lifecycles")
            if isinstance(lifecycles, list) and lifecycles:
                for lc in lifecycles:
                    if isinstance(lc, dict) and "phase" in lc:
                        phase_val = str(lc["phase"]).strip()
                        if phase_val.lower() in LIFECYCLE_PHASES:
                            has_lifecycle = True
                            lifecycle_phase = phase_val.capitalize()
                            break
                    elif isinstance(lc, str) and lc.lower() in LIFECYCLE_PHASES:
                        has_lifecycle = True
                        lifecycle_phase = lc.capitalize()
                        break
            # Fallback to metadata.properties for lifecycle tags
            if not has_lifecycle:
                props = metadata.get("properties", [])
                if isinstance(props, list):
                    for p in props:
                        if isinstance(p, dict) and "lifecycle" in str(p.get("name", "")).lower():
                            has_lifecycle = True
                            lifecycle_phase = str(p.get("value", "")).capitalize()
                            break

        elif is_spdx:
            # SPDX 3.0 lifecycle or comments
            comment = data.get("creationInfo", {}).get("comment", "")
            for phase in LIFECYCLE_PHASES:
                if phase in comment.lower():
                    has_lifecycle = True
                    lifecycle_phase = phase.capitalize()
                    break

        if not lifecycle_phase:
            lifecycle_phase = "Build (Inferred)" if has_lifecycle else "Unspecified"

        # 4. Tool / Engine Identity
        tools_found: list[str] = []
        tools_valid = False

        if is_cdx:
            tools = metadata.get("tools")
            if isinstance(tools, list):
                for t in tools:
                    if isinstance(t, dict):
                        vendor = t.get("vendor", "")
                        name = t.get("name", "")
                        ver = t.get("version", "")
                        full_name = f"{vendor} {name}".strip() if vendor else name
                        if full_name:
                            tools_found.append(f"{full_name} v{ver}" if ver else full_name)
                            if ver:
                                tools_valid = True
            elif isinstance(tools, dict):
                # CycloneDX 1.6+ tools.components or tools.services
                comp_tools = tools.get("components", [])
                if isinstance(comp_tools, list):
                    for ct in comp_tools:
                        if isinstance(ct, dict):
                            t_name = ct.get("name", "")
                            t_ver = ct.get("version", "")
                            if t_name:
                                tools_found.append(f"{t_name} v{t_ver}" if t_ver else t_name)
                                if t_ver:
                                    tools_valid = True
        elif is_spdx:
            creators = data.get("creationInfo", {}).get("creators", [])
            if isinstance(creators, list):
                for c in creators:
                    if isinstance(c, str) and c.startswith("Tool:"):
                        tools_found.append(c.replace("Tool:", "").strip())
                        tools_valid = True

        # 5. Cryptographic Signature / Attestation Verification
        has_signature = False
        signature_details: list[str] = []

        if is_cdx:
            # Root signature object
            if "signature" in data and isinstance(data["signature"], dict):
                has_signature = True
                sig_alg = data["signature"].get("algorithm") or data["signature"].get("keyId") or "Standard Signature"
                signature_details.append(f"Embedded CycloneDX Signature ({sig_alg})")
            # In-toto / Cosign / Attestations in externalReferences
            ext_refs = data.get("externalReferences", []) or metadata.get("externalReferences", [])
            if isinstance(ext_refs, list):
                for ref in ext_refs:
                    if isinstance(ref, dict):
                        ref_type = str(ref.get("type", "")).lower()
                        ref_comment = str(ref.get("comment", "")).lower()
                        if (
                            ref_type in ("attestation", "signature", "release-notes")
                            or "cosign" in ref_comment
                            or "in-toto" in ref_comment
                        ):
                            has_signature = True
                            signature_details.append(f"Attestation Reference: {ref.get('url', ref_type)}")
            # Signature properties
            props = metadata.get("properties", [])
            if isinstance(props, list):
                for p in props:
                    if isinstance(p, dict):
                        pname = str(p.get("name", "")).lower()
                        if "signature" in pname or "cosign" in pname or "attestation" in pname:
                            has_signature = True
                            signature_details.append(f"Attestation Property: {p.get('name')}")

        elif is_spdx:
            if "signatures" in data and isinstance(data["signatures"], list) and len(data["signatures"]) > 0:
                has_signature = True
                signature_details.append("SPDX Digital Signature Object")

        # 6. Root Product / Subject Component
        root_product = self._extract_root_product(data, format_info)

        return {
            "author_valid": author_valid,
            "authors": authors_found,
            "timestamp": str(raw_timestamp) if raw_timestamp else "N/D",
            "timestamp_valid": timestamp_valid,
            "has_lifecycle": has_lifecycle,
            "lifecycle_phase": lifecycle_phase,
            "tools_valid": tools_valid,
            "tools": tools_found,
            "has_signature": has_signature,
            "signature_details": signature_details,
            "root_product": root_product,
            "serial_number": str(data.get("serialNumber") or data.get("SPDXID") or "N/D"),
        }

    def _extract_root_product(self, data: dict[str, Any], format_info: dict[str, Any]) -> dict[str, Any]:
        """Extracts the primary product / target component definition."""
        if format_info["format"] == "cyclonedx":
            meta_comp = data.get("metadata", {}).get("component")
            if isinstance(meta_comp, dict):
                return {
                    "name": meta_comp.get("name", "N/D"),
                    "version": meta_comp.get("version", "N/D"),
                    "type": meta_comp.get("type", "application"),
                    "supplier": meta_comp.get("supplier", {}).get("name", "N/D")
                    if isinstance(meta_comp.get("supplier"), dict)
                    else str(meta_comp.get("supplier") or "N/D"),
                    "purl": meta_comp.get("purl"),
                    "cpe": meta_comp.get("cpe"),
                }
        elif format_info["format"] == "spdx":
            doc_name = data.get("name") or "SPDX Document"
            return {
                "name": doc_name,
                "version": "1.0.0",
                "type": "application",
                "supplier": data.get("creationInfo", {}).get("creators", ["N/D"])[0]
                if data.get("creationInfo", {}).get("creators")
                else "N/D",
                "purl": None,
                "cpe": None,
            }

        return {
            "name": "N/D",
            "version": "N/D",
            "type": "application",
            "supplier": "N/D",
            "purl": None,
            "cpe": None,
        }

    # -------------------------------------------------------------------------
    # Component Extraction & Dependency Graph
    # -------------------------------------------------------------------------
    def _extract_components_and_graph(
        self, data: dict[str, Any], format_info: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], set[str]]:
        """Extracts component records and resolves dependency graph references."""
        is_cdx = format_info["format"] == "cyclonedx"
        components: list[dict[str, Any]] = []
        referenced_in_graph: set[str] = set()

        if is_cdx:
            # 1. Dependency Graph references
            deps = data.get("dependencies", [])
            if isinstance(deps, list):
                for dep in deps:
                    if isinstance(dep, dict):
                        ref = dep.get("ref")
                        if ref:
                            referenced_in_graph.add(str(ref).strip())
                        depends_on = dep.get("dependsOn", [])
                        if isinstance(depends_on, list):
                            for d in depends_on:
                                if d:
                                    referenced_in_graph.add(str(d).strip())

            # 2. Extract components (including nested components)
            def _gather_cdx(comp_list: Any):
                if not isinstance(comp_list, list):
                    return
                for comp in comp_list:
                    if isinstance(comp, dict):
                        components.append(comp)
                        sub_comps = comp.get("components")
                        if sub_comps:
                            _gather_cdx(sub_comps)

            _gather_cdx(data.get("components", []))

        elif format_info["format"] == "spdx":
            # SPDX 2.3 packages and relationships
            relationships = data.get("relationships", [])
            if isinstance(relationships, list):
                for rel in relationships:
                    if isinstance(rel, dict):
                        spdx_id = rel.get("spdxElementId")
                        related_id = rel.get("relatedSpdxElement")
                        if spdx_id:
                            referenced_in_graph.add(str(spdx_id).strip())
                        if related_id:
                            referenced_in_graph.add(str(related_id).strip())

            packages = data.get("packages", [])
            if isinstance(packages, list):
                for pkg in packages:
                    if isinstance(pkg, dict):
                        components.append(pkg)

        return components, referenced_in_graph

    # -------------------------------------------------------------------------
    # Component Evaluation & Bifurcated 1st vs 3rd Party Analysis
    # -------------------------------------------------------------------------
    def _evaluate_components(
        self, components_raw: list[dict[str, Any]], dependency_graph: set[str]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """
        Evaluates each component against BSI/CISA criteria:
        Name, Version, Identifiers (PURL/CPE), Supplier, Hash (SHA-256/512),
        Licenses (SPDX expression, raw text, or missing), Graph Relations,
        BSI properties, and Known Unknowns.
        """
        matrix_rows: list[dict[str, Any]] = []

        total_components = len(components_raw)
        proprietary_count = 0
        third_party_count = 0
        proprietary_with_gaps = 0
        third_party_with_gaps = 0

        missing_hashes_count = 0
        non_spdx_licenses_count = 0
        missing_licenses_count = 0
        orphaned_count = 0

        for comp in components_raw:
            name = str(comp.get("name") or comp.get("packageName") or "N/D").strip()
            version = str(comp.get("version") or comp.get("versionInfo") or comp.get("packageVersion") or "").strip()
            has_version = bool(version and version not in ("N/D", "vN/D", "unknown", "NOASSERTION"))

            # 1. Proprietary vs Third-Party Detection
            is_proprietary = self._is_proprietary_component(comp)
            if is_proprietary:
                proprietary_count += 1
            else:
                third_party_count += 1

            # 2. Identifiers (PURL or CPE)
            purl = comp.get("purl") or comp.get("externalRefs", [])
            cpe = comp.get("cpe")
            has_valid_purl = False
            has_valid_cpe = False
            purl_str = None
            cpe_str = None

            if isinstance(purl, str) and PURL_REGEX.match(purl.strip()):
                has_valid_purl = True
                purl_str = purl.strip()
            elif isinstance(comp.get("externalRefs"), list):
                # SPDX externalRefs check
                for ref in comp.get("externalRefs", []):
                    if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                        purl_locator = ref.get("referenceLocator", "")
                        if PURL_REGEX.match(purl_locator.strip()):
                            has_valid_purl = True
                            purl_str = purl_locator.strip()

            if isinstance(cpe, str) and CPE_REGEX.match(cpe.strip()):
                has_valid_cpe = True
                cpe_str = cpe.strip()

            has_id = has_valid_purl or has_valid_cpe

            # 3. Supplier / Producer
            supplier_display, has_supplier = self._evaluate_supplier(comp)

            # 4. Hashes (SHA-256 or SHA-512)
            has_hash, hashes_found = self._evaluate_hashes(comp)
            if not has_hash:
                missing_hashes_count += 1

            # 5. Licenses (SPDX expression, Non-SPDX raw, or Missing)
            license_symbol, license_expr = self._evaluate_license(comp)
            if license_symbol == "!":
                non_spdx_licenses_count += 1
            elif license_symbol == "✕":
                missing_licenses_count += 1

            # 6. Relationships (In Graph vs Orphaned)
            bom_ref = str(comp.get("bom-ref") or comp.get("SPDXID") or "").strip()
            is_in_graph = (bom_ref in dependency_graph) if bom_ref else False
            # Check if component itself has dependencies listed
            if not is_in_graph and "dependencies" in comp:
                is_in_graph = True

            has_dependencies = "✓" if is_in_graph else "✕"
            if not is_in_graph:
                orphaned_count += 1

            # 7. BSI Properties & Structured Metadata
            bsi_props = self._evaluate_bsi_properties(comp)

            # 8. Known Unknowns detection (explicit NOASSERTION vs silent omission)
            known_unknown = self._detect_known_unknowns(comp)

            # 9. Bifurcated Verdict per Component
            # Proprietary: Missing supplier, hash, version, or valid license fails compliance
            # Third-Party OSS: Missing hash or supplier is advisory warning
            has_gaps = (
                not has_version
                or not has_id
                or not has_supplier
                or not has_hash
                or license_symbol != "✓"
                or has_dependencies == "✕"
            )

            if is_proprietary:
                if not has_version or not has_id or not has_supplier or not has_hash or license_symbol == "✕":
                    is_compliant = False
                    proprietary_with_gaps += 1
                else:
                    is_compliant = True
            else:
                # OSS library
                if has_gaps:
                    third_party_with_gaps += 1
                is_compliant = bool(has_version and has_id and license_symbol in ("✓", "!"))

            row = {
                "name": name,
                "version": version or "vN/D",
                "has_version": "✓" if has_version else "✕",
                "is_core": is_proprietary,
                "is_proprietary": is_proprietary,
                "component_type": "Proprietary" if is_proprietary else "Third-Party OSS",
                "has_id": "✓" if has_id else "✕",
                "purl": purl_str,
                "cpe": cpe_str,
                "supplier": supplier_display,
                "has_supplier": "✓" if has_supplier else "✕",
                "has_hash": "✓" if has_hash else "✕",
                "hashes": hashes_found,
                "has_license": license_symbol,
                "license": license_expr,
                "has_dependencies": has_dependencies,
                "bsi_properties": bsi_props,
                "known_unknowns": known_unknown,
                "is_compliant": is_compliant,
            }
            matrix_rows.append(row)

        statistics = {
            "components_total": total_components,
            "proprietary_count": proprietary_count,
            "third_party_count": third_party_count,
            "proprietary_with_gaps": proprietary_with_gaps,
            "third_party_with_gaps": third_party_with_gaps,
            "missing_hashes_count": missing_hashes_count,
            "non_spdx_licenses_count": non_spdx_licenses_count,
            "missing_licenses_count": missing_licenses_count,
            "orphaned_count": orphaned_count,
            "compliance_rate": round(
                ((total_components - (proprietary_with_gaps + third_party_with_gaps)) / max(1, total_components)) * 100,
                1,
            ),
        }

        return matrix_rows, statistics

    def _is_proprietary_component(self, comp: dict[str, Any]) -> bool:
        """Determines if a component is proprietary based on tenant prefix or supplier."""
        # 1. Properties inspection
        props = comp.get("properties", [])
        if isinstance(props, list):
            for p in props:
                if isinstance(p, dict):
                    pname = str(p.get("name", "")).strip().lower()
                    pval = str(p.get("value", "")).strip().lower()
                    # Matches tenant configured prefix (e.g., regubom:proprietary or custom)
                    if pname.startswith(self.proprietary_prefix) and pval in (
                        "true",
                        "1",
                        "yes",
                    ):
                        return True
                    if pname == "regubom:proprietary" and pval == "true":
                        return True

        # 2. Supplier name match
        if self.proprietary_supplier:
            supplier = comp.get("supplier")
            if isinstance(supplier, dict) and self.proprietary_supplier in str(supplier.get("name", "")).lower():
                return True
            if isinstance(supplier, str) and self.proprietary_supplier in supplier.lower():
                return True

        return False

    def _evaluate_supplier(self, comp: dict[str, Any]) -> tuple[str, bool]:
        """Extracts supplier name and checks if valid entity name, email, or URL."""
        supplier = comp.get("supplier") or comp.get("packageSupplier")
        if isinstance(supplier, dict):
            name = str(supplier.get("name", "")).strip()
            url = supplier.get("url")
            if name and name not in ("NOASSERTION", "unknown", "N/D"):
                return name, True
            if isinstance(url, list) and url:
                return str(url[0]), True
            elif isinstance(url, str) and url.strip():
                return url.strip(), True
        elif isinstance(supplier, str) and supplier.strip():
            clean = supplier.strip()
            if clean not in ("NOASSERTION", "unknown", "N/D"):
                # Clean SPDX "Organization: Name"
                clean_name = re.sub(r"^(?:Person|Organization):\s*", "", clean)
                return clean_name, True

        # Fallback to manufacturer or author
        for fallback_key in ("manufacturer", "author"):
            fb = comp.get(fallback_key)
            if isinstance(fb, dict) and fb.get("name"):
                return str(fb.get("name")).strip(), True
            elif isinstance(fb, str) and fb.strip() and fb not in ("NOASSERTION", "unknown"):
                return fb.strip(), True

        return "N/D", False

    def _evaluate_hashes(self, comp: dict[str, Any]) -> tuple[bool, list[str]]:
        """Checks for cryptographic digest presence (SHA-256 or SHA-512)."""
        hashes_list: list[str] = []
        has_strong_hash = False

        # CycloneDX hashes array: [{"alg": "SHA-256", "content": "..."}]
        cdx_hashes = comp.get("hashes", [])
        if isinstance(cdx_hashes, list):
            for h in cdx_hashes:
                if isinstance(h, dict):
                    alg = str(h.get("alg", "")).upper()
                    content = str(h.get("content", "")).strip()
                    if content:
                        hashes_list.append(f"{alg}: {content[:10]}...")
                        if alg in ("SHA-256", "SHA-512", "SHA256", "SHA512"):
                            has_strong_hash = True

        # SPDX checksums: [{"algorithm": "SHA256", "checksumValue": "..."}]
        spdx_checksums = comp.get("checksums", [])
        if isinstance(spdx_checksums, list):
            for c in spdx_checksums:
                if isinstance(c, dict):
                    alg = str(c.get("algorithm", "")).upper()
                    val = str(c.get("checksumValue", "")).strip()
                    if val:
                        hashes_list.append(f"{alg}: {val[:10]}...")
                        if alg in ("SHA256", "SHA512", "SHA-256", "SHA-512"):
                            has_strong_hash = True

        return has_strong_hash, hashes_list

    def _evaluate_license(self, comp: dict[str, Any]) -> tuple[str, str]:
        """
        Distinguishes:
        - Valid SPDX identifier/expression: '✓'
        - Non-SPDX raw text string: '!'
        - Missing or invalid: '✕'
        """
        # CycloneDX licenses
        licenses = comp.get("licenses", [])
        if isinstance(licenses, list) and licenses:
            for lic_entry in licenses:
                if not isinstance(lic_entry, dict):
                    continue
                expr = lic_entry.get("expression")
                if expr and isinstance(expr, str) and expr.strip():
                    if is_valid_spdx_expression(expr):
                        return "✓", expr.strip()
                    return "!", f"{expr.strip()} (Non-SPDX)"

                lic_obj = lic_entry.get("license", {})
                if isinstance(lic_obj, dict):
                    lid = lic_obj.get("id")
                    lname = lic_obj.get("name")
                    if lid and is_valid_spdx_expression(str(lid)):
                        return "✓", str(lid).strip()
                    if lname and str(lname).strip():
                        if is_valid_spdx_expression(str(lname)):
                            return "✓", str(lname).strip()
                        return "!", f"{str(lname).strip()} (Non-SPDX)"

        # SPDX licenseConcluded / licenseDeclared
        for spdx_lic_key in ("licenseConcluded", "licenseDeclared"):
            s_lic = comp.get(spdx_lic_key)
            if s_lic and isinstance(s_lic, str) and s_lic.strip() not in ("NOASSERTION", "NONE"):
                if is_valid_spdx_expression(s_lic):
                    return "✓", s_lic.strip()
                return "!", f"{s_lic.strip()} (Non-SPDX)"

        return "✕", "Mancante (N/D)"

    def _evaluate_bsi_properties(self, comp: dict[str, Any]) -> dict[str, bool]:
        """Checks for BSI TR-03183-2 structured properties (executable, archive, metadata)."""
        comp_type = str(comp.get("type") or comp.get("primaryPackagePurpose") or "").lower()
        is_executable = comp_type in (
            "application",
            "framework",
            "operating-system",
            "executable",
        )
        is_archive = comp_type in ("archive", "container", "file")

        has_structured = False
        props = comp.get("properties", [])
        if isinstance(props, list) and len(props) > 0:
            has_structured = True

        return {
            "has_executable": is_executable,
            "has_archive": is_archive,
            "has_structured_metadata": has_structured,
        }

    def _detect_known_unknowns(self, comp: dict[str, Any]) -> bool:
        """Detects whether missing fields were explicitly acknowledged as unknown."""
        for val in comp.values():
            if val in ("NOASSERTION", "unknown", "none"):
                return True
        return False

    # -------------------------------------------------------------------------
    # 12-Point ENISA / BSI Checklist Generation
    # -------------------------------------------------------------------------
    def _build_12_point_checklist(
        self,
        format_info: dict[str, Any],
        doc_metadata: dict[str, Any],
        matrix_rows: list[dict[str, Any]],
        stats: dict[str, Any],
        schema_valid: bool = True,
        schema_err: str | None = None,
    ) -> list[dict[str, Any]]:
        """Compiles the 12 regulatory audit criteria with status and descriptions."""
        checklist: list[dict[str, Any]] = []

        total_comps = stats["components_total"]

        # Item 1: Standards & Formats (CycloneDX 1.6/1.7 or SPDX 2.3/3.0.1)
        fmt_ok = format_info["is_supported"] and schema_valid
        if not format_info["is_supported"]:
            fmt_detail = (
                f"Formato non supportato: {format_info['display']}. Richiesto CycloneDX 1.6/1.7 o SPDX 2.3/3.0.1."
            )
        elif not schema_valid:
            fmt_detail = (
                f"Formato: {format_info['display']}. Errore validazione schema JSON air-gap locale: {schema_err}"
            )
        else:
            fmt_detail = f"Formato: {format_info['display']} ({format_info['standard']}). Schema JSON validato con successo in modalità locale air-gap (zero-telemetria)."

        checklist.append(
            {
                "id": "ENISA-01-STANDARD",
                "title": "Standard e Formato Ufficiale (CycloneDX 1.6/1.7 o SPDX 2.3/3.0.1)",
                "passed": fmt_ok,
                "status": "PASS" if fmt_ok else "FAIL",
                "total_count": 1,
                "missing_count": 0 if fmt_ok else 1,
                "detail": fmt_detail,
            }
        )

        # Item 2: Document Timestamp
        ts_ok = doc_metadata["timestamp_valid"]
        checklist.append(
            {
                "id": "ENISA-02-TIMESTAMP",
                "title": "Timestamp del Documento (Formato UTC RFC 3339)",
                "passed": ts_ok,
                "status": "PASS" if ts_ok else "FAIL",
                "total_count": 1,
                "missing_count": 0 if ts_ok else 1,
                "detail": f"Timestamp rilevato: {doc_metadata['timestamp']}. "
                + ("Valido UTC ISO-8601/RFC-3339." if ts_ok else "Mancante o non in formato UTC valido."),
            }
        )

        # Item 3: Document Author / Creator
        auth_ok = doc_metadata["author_valid"]
        checklist.append(
            {
                "id": "ENISA-03-CREATOR",
                "title": "Identità dell'Autore / Creatore SBOM (Email RFC 5322 o URL)",
                "passed": auth_ok,
                "status": "PASS" if auth_ok else "WARNING",
                "total_count": 1,
                "missing_count": 0 if auth_ok else 1,
                "detail": f"Contatti censiti: {', '.join(doc_metadata['authors']) if doc_metadata['authors'] else 'Nessuno'}. "
                + (
                    "Email o URL validi riscontrati."
                    if auth_ok
                    else "Avviso: contatto autore non conforme RFC 5322/URL."
                ),
            }
        )

        # Item 4: Tool / Generator Engine Identity
        tool_ok = doc_metadata["tools_valid"]
        checklist.append(
            {
                "id": "ENISA-04-TOOL",
                "title": "Identità del Tool di Generazione (Nome e Versione)",
                "passed": tool_ok,
                "status": "PASS" if tool_ok else "WARNING",
                "total_count": 1,
                "missing_count": 0 if tool_ok else 1,
                "detail": f"Tool censiti: {', '.join(doc_metadata['tools']) if doc_metadata['tools'] else 'N/D'}. "
                + ("Identità completa registrata." if tool_ok else "Avviso: versione del tool non specificata."),
            }
        )

        # Item 5: Generation Context & Lifecycle Phase
        lc_ok = doc_metadata["has_lifecycle"]
        checklist.append(
            {
                "id": "ENISA-05-LIFECYCLE",
                "title": "Fase di Ciclo di Vita (Design, Source, Build, Analysed, Deployed, Runtime)",
                "passed": lc_ok,
                "status": "PASS" if lc_ok else "WARNING",
                "total_count": 1,
                "missing_count": 0 if lc_ok else 1,
                "detail": f"Fase rilevata: {doc_metadata['lifecycle_phase']}. "
                + (
                    "Contesto di generazione esplicitato."
                    if lc_ok
                    else "Avviso: fase di ciclo di vita non dichiarata esplicitamente."
                ),
            }
        )

        # Item 6: Cryptographic Signature & Attestation
        sig_ok = doc_metadata["has_signature"]
        checklist.append(
            {
                "id": "ENISA-06-SIGNATURE",
                "title": "Firma Crittografica o Attestazione (Cosign / in-toto / Embedded)",
                "passed": sig_ok,
                "status": "PASS" if sig_ok else "WARNING",
                "total_count": 1,
                "missing_count": 0 if sig_ok else 1,
                "detail": f"Stato attestazione: {', '.join(doc_metadata['signature_details']) if sig_ok else 'Nessuna firma digitale o attestazione in-toto rilevata.'}",
            }
        )

        # Item 7: Root Product / Target Subject Definition
        rp = doc_metadata["root_product"]
        rp_ok = bool(rp.get("name") and rp.get("name") != "N/D" and rp.get("version") and rp.get("version") != "N/D")
        checklist.append(
            {
                "id": "ENISA-07-ROOT-PRODUCT",
                "title": "Definizione del Prodotto Primario (Subject Name & Version)",
                "passed": rp_ok,
                "status": "PASS" if rp_ok else "FAIL",
                "total_count": 1,
                "missing_count": 0 if rp_ok else 1,
                "detail": f"Prodotto: {rp.get('name')} v{rp.get('version')} ({rp.get('type')}).",
            }
        )

        # Item 8: Component Inventory & Baseline Completeness (Name, Version, ID)
        missing_versions = sum(1 for r in matrix_rows if r["has_version"] == "✕")
        missing_ids = sum(1 for r in matrix_rows if r["has_id"] == "✕")
        inv_ok = (missing_versions == 0 and missing_ids == 0) and total_comps > 0
        checklist.append(
            {
                "id": "ENISA-08-COMPONENTS",
                "title": "Completezza Inventario Componenti (Nome, Versione, PURL/CPE)",
                "passed": inv_ok,
                "status": "PASS" if inv_ok else ("FAIL" if missing_versions > 0 else "WARNING"),
                "total_count": total_comps,
                "missing_count": missing_versions + missing_ids,
                "detail": f"Totale componenti: {total_comps}. Versioni mancanti: {missing_versions}, Identificatori PURL/CPE mancanti: {missing_ids}.",
            }
        )

        # Item 9: Cryptographic Hash Integrity (SHA-256 / SHA-512)
        missing_hashes = stats["missing_hashes_count"]
        # Check if proprietary components miss hashes (critical fail) vs OSS (warning)
        prop_missing_hash = sum(1 for r in matrix_rows if r["is_proprietary"] and r["has_hash"] == "✕")
        hash_ok = missing_hashes == 0
        checklist.append(
            {
                "id": "ENISA-09-HASHES",
                "title": "Integrità Digest Crittografici (SHA-256 o SHA-512)",
                "passed": hash_ok,
                "status": "FAIL" if prop_missing_hash > 0 else ("PASS" if hash_ok else "WARNING"),
                "total_count": total_comps,
                "missing_count": missing_hashes,
                "detail": f"Componenti privi di hash crittografico: {missing_hashes} (di cui {prop_missing_hash} proprietari).",
            }
        )

        # Item 10: License Compliance & SPDX Identifiers
        non_spdx = stats["non_spdx_licenses_count"]
        missing_lic = stats["missing_licenses_count"]
        prop_missing_lic = sum(1 for r in matrix_rows if r["is_proprietary"] and r["has_license"] == "✕")
        lic_ok = missing_lic == 0 and non_spdx == 0
        checklist.append(
            {
                "id": "ENISA-10-LICENSES",
                "title": "Conformità Licenze (Espressioni SPDX 3.25+ Standardizzate)",
                "passed": lic_ok,
                "status": "FAIL" if prop_missing_lic > 0 else ("PASS" if lic_ok else "WARNING"),
                "total_count": total_comps,
                "missing_count": missing_lic + non_spdx,
                "detail": f"Licenze assenti: {missing_lic}. Licenze non standard (testo libero): {non_spdx}.",
            }
        )

        # Item 11: Dependency Graph & Relationships
        orphaned = stats["orphaned_count"]
        dep_ok = orphaned == 0
        checklist.append(
            {
                "id": "ENISA-11-RELATIONS",
                "title": "Grafo delle Dipendenze e Relazioni (Tracciabilità Componenti)",
                "passed": dep_ok,
                "status": "PASS" if dep_ok else "WARNING",
                "total_count": total_comps,
                "missing_count": orphaned,
                "detail": f"Componenti tracciati nel grafo: {total_comps - orphaned}/{total_comps}. Componenti orfani: {orphaned}.",
            }
        )

        # Item 12: Supplier / Producer Identification (Bifurcated 1st vs 3rd Party)
        missing_supp = sum(1 for r in matrix_rows if r["has_supplier"] == "✕")
        prop_missing_supp = sum(1 for r in matrix_rows if r["is_proprietary"] and r["has_supplier"] == "✕")
        supp_ok = missing_supp == 0
        checklist.append(
            {
                "id": "ENISA-12-SUPPLIER",
                "title": "Identificazione Fornitore / Produttore (Requisito Stringente Proprietari)",
                "passed": supp_ok,
                "status": "FAIL" if prop_missing_supp > 0 else ("PASS" if supp_ok else "WARNING"),
                "total_count": total_comps,
                "missing_count": missing_supp,
                "detail": f"Fornitore mancante su {missing_supp} componenti (di cui {prop_missing_supp} proprietari).",
            }
        )

        return checklist


def audit_enisa_compliance(
    sbom_dict: dict[str, Any],
    file_imprint: dict[str, Any] | None = None,
    proprietary_prefix: str = "regubom:proprietary",
    proprietary_supplier: str | None = None,
) -> dict[str, Any]:
    """Convenience functional interface to EnisaComplianceAuditor."""
    auditor = EnisaComplianceAuditor(proprietary_prefix=proprietary_prefix, proprietary_supplier=proprietary_supplier)
    return auditor.audit(sbom_dict, file_imprint=file_imprint)
