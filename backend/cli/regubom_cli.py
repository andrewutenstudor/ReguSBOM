#!/usr/bin/env python3
"""
ReguBOM — Community Edition (Open Source, Apache 2.0)
Standalone Headless CLI Regulatory SBOM Scanner & Compliance Validator.
Compliant with:
- EU Cyber Resilience Act (Regulation EU 2024/2847 Art. 13 & Annex II)
- ENISA Technical Advisory on SBOM (October 2026)
- BSI TR-03183-2 v2.1.0
- CISA 2026 Minimum Elements
"""
import argparse
import hashlib
import json
import os
import sys
import uuid
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any

# Ensure backend root is on PYTHONPATH
CURRENT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = CURRENT_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Configure stdout encoding safely for cross-platform terminals (Windows cp1252 fallback)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from app.core.enisa_engine import audit_enisa_compliance

VERSION = "2.0.0-ce"


def compute_file_imprint(filepath: Path) -> Dict[str, Any]:
    """Calculates cryptographic hashes and file metrics."""
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    total_bytes = 0

    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            sha512.update(chunk)
            total_bytes += len(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
        "file_size_bytes": total_bytes,
        "file_size_mb": round(total_bytes / (1024 * 1024), 2),
    }


def format_status(status_str: str) -> str:
    """Colorizes status string if terminal supports ANSI."""
    if not sys.stdout.isatty():
        return f"[{status_str}]"
    if status_str == "PASS":
        return f"\033[92m[PASS]\033[0m"
    elif status_str == "WARNING":
        return f"\033[93m[WARN]\033[0m"
    return f"\033[91m[FAIL]\033[0m"


def print_cli_report(result: Dict[str, Any], imprint: Dict[str, Any], filename: str):
    """Outputs an executive terminal compliance audit dossier."""
    overall = result.get("overall_status", "UNKNOWN")
    format_info = result.get("format_info", {})
    doc_meta = result.get("document_metadata", {})
    stats = result.get("statistics", {})
    checklist = result.get("cra_checklist", [])

    print("\n" + "=" * 78)
    print(f"  ReguBOM Community Edition CLI Scanner v{VERSION} (Apache 2.0)")
    print(f"  EU CRA Art. 13 & ENISA Oct 2026 Regulatory Verification")
    print("=" * 78)

    print(f"\n📂 TARGET SBOM: {filename}")
    print(f"   SHA-256:     {imprint.get('sha256')}")
    print(f"   SHA-512:     {imprint.get('sha512')}")
    print(f"   Size:        {imprint.get('file_size_mb')} MB ({imprint.get('file_size_bytes')} bytes)")
    print(f"   Format:      {format_info.get('display')} ({format_info.get('standard')})")

    root_prod = doc_meta.get("root_product", {})
    prod_name = root_prod.get("name") or doc_meta.get("root_product_name") or "N/D"
    prod_ver = root_prod.get("version") or doc_meta.get("root_product_version") or "N/D"
    print(f"   Root Product: {prod_name} (v{prod_ver})")
    print(f"   Authors:     {', '.join(doc_meta.get('authors', [])) or 'N/D'}")
    print(f"   Timestamp:   {doc_meta.get('timestamp') or 'N/D'}")

    print("\n" + "-" * 78)
    print("  📋 12-POINT CRA & ENISA 2026 AUDIT CHECKLIST")
    print("-" * 78)

    for item in checklist:
        tag = format_status(item.get("status", "FAIL"))
        title = item.get("title", "")
        detail = item.get("detail", "")
        print(f"  {tag:<16} {title}")
        if detail:
            print(f"                   └─ {detail}")

    print("\n" + "-" * 78)
    print("  📊 COMPONENT COMPLETENESS METRICS")
    print("-" * 78)
    total_comps = stats.get("components_total", 0)
    prop_count = stats.get("proprietary_count", 0)
    oss_count = stats.get("third_party_count", 0)
    print(f"  Total Inventory:        {total_comps} components")
    print(f"  Proprietary (1st-Party): {prop_count}")
    print(f"  Third-Party OSS:        {oss_count}")
    print(f"  Missing Suppliers:      {stats.get('missing_supplier_count', 0)}")
    print(f"  Missing Identifiers:    {stats.get('missing_id_count', 0)}")
    print(f"  Missing Hashes:         {stats.get('missing_hashes_count', 0)}")
    print(f"  Non-SPDX Licenses:      {stats.get('non_spdx_licenses_count', 0)}")
    print(f"  Missing Dependencies:   {stats.get('missing_deps_count', 0)}")

    print("\n" + "=" * 78)
    verdict_badge = format_status(overall)
    print(f"  FINAL VERDICT: {verdict_badge}  — Overall Regulatory Status: {overall}")
    if overall == "PASS":
        print("  ✅ The SBOM complies with all mandatory ENISA 2026 and CRA Art. 13 requirements.")
    elif overall == "WARNING":
        print("  ⚠️ The SBOM is conditionally acceptable; see checklist warnings above.")
    else:
        print("  ❌ Non-compliant; regulatory submission rejected under CRA Art. 13 & Annex II.")
    print("=" * 78 + "\n")


def main():
    # Support both direct syntax ('regubom <file>') and subcommand syntax ('regubom scan <file>')
    raw_args = list(sys.argv[1:])
    if raw_args and raw_args[0] == "scan":
        raw_args = raw_args[1:]

    parser = argparse.ArgumentParser(
        prog="regubom",
        description="ReguBOM Community Edition — Standalone Headless Regulatory SBOM Scanner (Apache 2.0)",
    )
    parser.add_argument("file", help="Path to SBOM file (CycloneDX JSON or SPDX JSON)")
    parser.add_argument("--api-url", default=None, help="Optional ReguBOM API endpoint URL (e.g. http://localhost:8000)")
    parser.add_argument("--format", choices=["cyclonedx", "spdx"], default=None, help="SBOM format (auto-detected if omitted)")
    parser.add_argument("--profile", default="ENISA_2026", help="Regulatory audit profile (default: ENISA_2026)")
    parser.add_argument("--proprietary-prefix", default=None, help="Prefix for proprietary component detection (e.g. regubom:proprietary)")
    parser.add_argument("--proprietary-supplier", default=None, help="Default supplier name for 1st-party components")
    parser.add_argument("-o", "--output", default="text", help="Output format: 'text', 'json', or path to output file (e.g. report.json)")
    parser.add_argument("--fail-on-warnings", action="store_true", help="Exit with code 2 if status is WARNING")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode: suppress banner, print minimal status")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args(raw_args)

    sbom_path = Path(args.file)
    if not sbom_path.is_file():
        print(f"Error: File not found: '{args.file}'", file=sys.stderr)
        sys.exit(1)

    try:
        content_bytes = sbom_path.read_bytes()
        sbom_data = json.loads(content_bytes.decode("utf-8"))
    except Exception as e:
        print(f"Error: Failed to parse JSON document '{args.file}': {e}", file=sys.stderr)
        sys.exit(1)

    imprint = compute_file_imprint(sbom_path)

    # If --api-url is provided, submit to remote/local ReguBOM API gateway
    if args.api_url:
        target_url = args.api_url.rstrip("/") + "/api/validate"
        boundary = "----WebKitFormBoundaryReguBOM" + uuid.uuid4().hex
        parts = []
        
        # File field
        parts.append(f"--{boundary}".encode())
        parts.append(f'Content-Disposition: form-data; name="file"; filename="{sbom_path.name}"'.encode())
        parts.append(b"Content-Type: application/json\r\n")
        parts.append(content_bytes)

        # Optional fields
        if args.profile:
            parts.append(f"--{boundary}".encode())
            parts.append(b'Content-Disposition: form-data; name="profile"\r\n')
            parts.append(args.profile.encode())
        if args.proprietary_prefix:
            parts.append(f"--{boundary}".encode())
            parts.append(b'Content-Disposition: form-data; name="proprietary_prefix"\r\n')
            parts.append(args.proprietary_prefix.encode())
        if args.proprietary_supplier:
            parts.append(f"--{boundary}".encode())
            parts.append(b'Content-Disposition: form-data; name="proprietary_supplier"\r\n')
            parts.append(args.proprietary_supplier.encode())

        parts.append(f"--{boundary}--\r\n".encode())
        body_bytes = b"\r\n".join(parts)

        req = urllib.request.Request(
            target_url,
            data=body_bytes,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "User-Agent": f"ReguBOM-CLI/{VERSION}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp_bytes = resp.read()
                audit_result = json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8", errors="replace")
            print(f"API Error ({e.code}): {err_msg}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Network error connecting to API '{target_url}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Execute local offline ENISA Oct 2026 / BSI / CRA Compliance Audit Engine
        try:
            audit_result = audit_enisa_compliance(
                sbom_data,
                file_imprint=imprint,
                proprietary_prefix=args.proprietary_prefix,
                proprietary_supplier=args.proprietary_supplier,
            )
        except Exception as e:
            print(f"Error during regulatory compliance audit: {e}", file=sys.stderr)
            sys.exit(1)

    overall = audit_result.get("overall_status", "FAIL")

    # Output formatting
    if args.output == "json":
        print(json.dumps(audit_result, indent=2, ensure_ascii=False))
    elif args.output != "text" and args.output.endswith(".json"):
        out_path = Path(args.output)
        out_path.write_text(json.dumps(audit_result, indent=2, ensure_ascii=False), encoding="utf-8")
        if not args.quiet:
            print(f"Report written to '{args.output}'")
    else:
        if not args.quiet:
            print_cli_report(audit_result, imprint, sbom_path.name)
        else:
            print(overall)

    # Exit code determination
    if overall == "PASS":
        sys.exit(0)
    elif overall == "WARNING":
        sys.exit(2 if args.fail_on_warnings else 0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
