"""Report generation utilities for JSON, HTML, and PDF formats."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    import orjson
except ImportError:
    orjson = None

try:
    from weasyprint import HTML as WeasyHTML

    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError, Exception):
    WEASYPRINT_AVAILABLE = False


class ReportGenerator:
    """Generates validation reports in multiple formats with high-performance dossier memory protection."""

    def __init__(self):
        self.template_dir = Path(__file__).parent.parent / "templates"
        self.template_dir.mkdir(exist_ok=True)

        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def prepare_executive_dossier(self, report_data: dict[str, Any], max_table_rows: int = 50) -> dict[str, Any]:
        """
        Hardens HTML and PDF report generation against memory crashes on 57,000+ component SBOMs.
        Computes aggregate metrics across the entire fleet of components, extracts the top 50
        critical non-compliant gaps, and caps the rendered DOM table size.
        """
        raw_matrix: list[dict[str, Any]] = report_data.get("component_matrix", []) or []
        total_components = len(raw_matrix)

        proprietary_count = 0
        missing_supplier = 0
        missing_id = 0
        missing_hash = 0
        missing_license = 0
        missing_deps = 0
        non_compliant_gaps: list[dict[str, Any]] = []

        for comp in raw_matrix:
            is_prop = bool(comp.get("is_core") or comp.get("is_proprietary"))
            if is_prop:
                proprietary_count += 1

            has_sup = comp.get("has_supplier") == "✓"
            has_purl = comp.get("has_id") == "✓"
            has_hsh = comp.get("has_hash") == "✓"
            has_lic = comp.get("has_license") == "✓"
            has_dp = comp.get("has_dependencies") == "✓"

            if not has_sup:
                missing_supplier += 1
            if not has_purl:
                missing_id += 1
            if not has_hsh:
                missing_hash += 1
            if not has_lic:
                missing_license += 1
            if not has_dp:
                missing_deps += 1

            if not (has_sup and has_purl and has_hsh and has_lic and has_dp):
                non_compliant_gaps.append(comp)

        oss_count = total_components - proprietary_count

        if total_components > max_table_rows:
            dossier_matrix = non_compliant_gaps[:max_table_rows] if non_compliant_gaps else raw_matrix[:max_table_rows]
            truncated_inventory = True
        else:
            dossier_matrix = raw_matrix
            truncated_inventory = False

        dossier_data = dict(report_data)
        dossier_data["component_matrix"] = dossier_matrix
        dossier_data["is_dossier"] = True
        dossier_data["total_components"] = total_components
        dossier_data["shown_count"] = len(dossier_matrix)
        dossier_data["truncated_inventory"] = truncated_inventory
        dossier_data["aggregate_metrics"] = {
            "total_components": total_components,
            "proprietary_count": proprietary_count,
            "oss_count": oss_count,
            "missing_supplier": missing_supplier,
            "missing_id": missing_id,
            "missing_hash": missing_hash,
            "missing_license": missing_license,
            "missing_deps": missing_deps,
            "total_non_compliant": len(non_compliant_gaps),
        }
        return dossier_data

    def generate_json(self, report_data: dict) -> dict:
        """Generate JSON report data."""
        return report_data

    def save_json_report(self, report_data: dict, filepath: str) -> None:
        """Save report as JSON file."""
        if orjson is not None:
            try:
                Path(filepath).write_bytes(orjson.dumps(report_data, option=orjson.OPT_INDENT_2))
                return
            except Exception:
                pass
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

    def generate_html(self, report_data: dict) -> str:
        """Generate HTML report content with executive dossier protection."""
        dossier_data = self.prepare_executive_dossier(report_data)
        template = self.env.get_template("report_template.html")
        return template.render(report=dossier_data, generated_at=datetime.utcnow().isoformat())

    def save_html_report(self, report_data: dict, filepath: str) -> None:
        """Save report as HTML file."""
        html_content = self.generate_html(report_data)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

    def generate_pdf(self, report_data: dict) -> bytes:
        """Generate PDF report content using hardened executive dossier rendering."""
        if not WEASYPRINT_AVAILABLE:
            raise ImportError("WeasyPrint is not available for PDF generation")

        html_content = self.generate_html(report_data)
        pdf_bytes = WeasyHTML(string=html_content).write_pdf()
        return pdf_bytes

    def save_pdf_report(self, report_data: dict, filepath: str) -> None:
        """Save report as PDF file."""
        if not WEASYPRINT_AVAILABLE:
            raise ImportError("WeasyPrint is not available for PDF generation")

        html_content = self.generate_html(report_data)
        WeasyHTML(string=html_content).write_pdf(filepath)
