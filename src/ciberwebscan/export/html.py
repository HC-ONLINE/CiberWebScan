"""
HTML exporter with visual report support for CiberWebScan.

Exports data to HTML format with embedded CSS for professional security reports.
Supports both batch (complete report) and streaming (item by item) modes.
"""

from __future__ import annotations

import html
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from ciberwebscan.export.base import BaseExporter, ExportWriteError

if TYPE_CHECKING:
    from ciberwebscan.export.models import AnalysisReport

logger = logging.getLogger(__name__)

# =============================================================================
# CSS Theme
# =============================================================================

_CSS_THEME = """
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --accent: #58a6ff;
    --critical: #f85149;
    --high: #f0883e;
    --medium: #d29922;
    --low: #3fb950;
    --info: #58a6ff;
    --grade-a: #3fb950;
    --grade-b: #d29922;
    --grade-c: #f0883e;
    --grade-f: #f85149;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
}

.container { max-width: 1200px; margin: 0 auto; }

/* Header */
.report-header {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 2rem;
    margin-bottom: 2rem;
}

.report-header h1 {
    font-size: 1.8rem;
    margin-bottom: 0.5rem;
    color: var(--accent);
}

.report-header .meta {
    display: flex;
    flex-wrap: wrap;
    gap: 1.5rem;
    color: var(--text-secondary);
    font-size: 0.9rem;
}

.report-header .meta span { display: flex; align-items: center; gap: 0.4rem; }

/* Score Cards */
.score-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}

.score-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    text-align: center;
}

.score-card .value {
    font-size: 2.5rem;
    font-weight: 700;
    line-height: 1.2;
}

.score-card .label {
    color: var(--text-secondary);
    font-size: 0.85rem;
    margin-top: 0.3rem;
}

/* Sections */
.section {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 1.5rem;
    overflow: hidden;
}

.section-header {
    background: var(--bg-tertiary);
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border);
    font-size: 1.1rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.section-body { padding: 1.5rem; }

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
}

th, td {
    padding: 0.75rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
}

th {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.05em;
}

tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(88, 166, 255, 0.05); }

/* Badges */
.badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.badge-critical { background: rgba(248, 81, 73, 0.15); color: var(--critical); }
.badge-high { background: rgba(240, 136, 62, 0.15); color: var(--high); }
.badge-medium { background: rgba(210, 153, 34, 0.15); color: var(--medium); }
.badge-low { background: rgba(63, 185, 80, 0.15); color: var(--low); }
.badge-info { background: rgba(88, 166, 255, 0.15); color: var(--info); }
.badge-present { background: rgba(63, 185, 80, 0.15); color: var(--low); }
.badge-missing { background: rgba(248, 81, 73, 0.15); color: var(--critical); }

/* Grade */
.grade {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 48px;
    height: 48px;
    border-radius: 50%;
    font-size: 1.5rem;
    font-weight: 700;
}

.grade-a, .grade-a-plus { background: rgba(63, 185, 80, 0.2); color: var(--grade-a); border: 2px solid var(--grade-a); }
.grade-b { background: rgba(210, 153, 34, 0.2); color: var(--grade-b); border: 2px solid var(--grade-b); }
.grade-c { background: rgba(240, 136, 62, 0.2); color: var(--grade-c); border: 2px solid var(--grade-c); }
.grade-f { background: rgba(248, 81, 73, 0.2); color: var(--grade-f); border: 2px solid var(--grade-f); }

/* Tech cards */
.tech-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 0.75rem;
}

.tech-card {
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.75rem 1rem;
}

.tech-card .name { font-weight: 600; }
.tech-card .version { color: var(--text-secondary); font-size: 0.85rem; }
.tech-card .category { color: var(--accent); font-size: 0.8rem; }

/* Code / Evidence */
code, .evidence {
    background: var(--bg-tertiary);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.85rem;
    word-break: break-all;
}

.evidence-block {
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
    margin-top: 0.5rem;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.85rem;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
}

/* Links list */
.links-list {
    list-style: none;
    max-height: 300px;
    overflow-y: auto;
}

.links-list li {
    padding: 0.4rem 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.85rem;
}

.links-list li:last-child { border-bottom: none; }
.links-list a { color: var(--accent); text-decoration: none; }
.links-list a:hover { text-decoration: underline; }

/* Remediation */
.remediation {
    background: rgba(88, 166, 255, 0.08);
    border-left: 3px solid var(--accent);
    padding: 0.75rem 1rem;
    margin-top: 0.5rem;
    border-radius: 0 4px 4px 0;
    font-size: 0.9rem;
}

/* Empty state */
.empty-state {
    color: var(--text-secondary);
    text-align: center;
    padding: 2rem;
    font-style: italic;
}

/* Footer */
.report-footer {
    text-align: center;
    color: var(--text-secondary);
    font-size: 0.8rem;
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
}

/* Responsive */
@media (max-width: 768px) {
    body { padding: 1rem; }
    .score-cards { grid-template-columns: repeat(2, 1fr); }
    .tech-grid { grid-template-columns: 1fr; }
    table { font-size: 0.8rem; }
    th, td { padding: 0.5rem; }
}
"""


# =============================================================================
# HTML Helpers
# =============================================================================


def _escape(text: Any) -> str:
    """Escape HTML special characters."""
    if text is None:
        return ""
    return html.escape(str(text))


def _severity_badge(severity: str) -> str:
    """Generate an HTML badge for a severity level."""
    severity_lower = severity.lower()
    return f'<span class="badge badge-{_escape(severity_lower)}">{_escape(severity_upper(severity_lower))}</span>'


def severity_upper(severity: str) -> str:
    """Capitalize severity string."""
    return severity.upper() if severity else ""


def _grade_class(grade: str | None) -> str:
    """Get CSS class for an SSL grade."""
    if not grade:
        return "grade-f"
    g = grade.lower().replace("+", "-plus")
    return f"grade-{g}"


def _bool_icon(value: bool) -> str:
    """Return a colored yes/no badge for boolean values."""
    if value:
        return '<span class="badge badge-present">YES</span>'
    return '<span class="badge badge-missing">NO</span>'


def _render_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    """Render an HTML table from a list of dicts."""
    if not rows:
        return '<p class="empty-state">No data available</p>'

    headers = "".join(f"<th>{_escape(c)}</th>" for c in columns)
    body_rows = []
    for row in rows:
        cells = []
        for col in columns:
            val = row.get(col, "")
            if isinstance(val, bool):
                cells.append(f"<td>{_bool_icon(val)}</td>")
            elif isinstance(val, list):
                cells.append(f"<td>{_escape(', '.join(str(v) for v in val))}</td>")
            else:
                cells.append(f"<td>{_escape(val)}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")

    return f"""
    <table>
        <thead><tr>{headers}</tr></thead>
        <tbody>{"".join(body_rows)}</tbody>
    </table>
    """


# =============================================================================
# Section Renderers
# =============================================================================


def _render_summary(report: AnalysisReport) -> str:
    """Render the summary score cards."""
    return f"""
    <div class="score-cards">
        <div class="score-card">
            <div class="value" style="color: {"var(--critical)" if report.risk_score >= 70 else "var(--medium)" if report.risk_score >= 40 else "var(--low)"}">
                {report.risk_score}
            </div>
            <div class="label">Risk Score</div>
        </div>
        <div class="score-card">
            <div class="value" style="color: var(--critical)">{report.critical_findings}</div>
            <div class="label">Critical</div>
        </div>
        <div class="score-card">
            <div class="value" style="color: var(--high)">{report.high_findings}</div>
            <div class="label">High</div>
        </div>
        <div class="score-card">
            <div class="value" style="color: var(--medium)">{report.medium_findings}</div>
            <div class="label">Medium</div>
        </div>
        <div class="score-card">
            <div class="value" style="color: var(--low)">{report.low_findings}</div>
            <div class="label">Low</div>
        </div>
        <div class="score-card">
            <div class="value" style="color: var(--info)">{report.info_findings}</div>
            <div class="label">Info</div>
        </div>
    </div>
    """


def _render_ssl(report: AnalysisReport) -> str:
    """Render the SSL/TLS analysis section."""
    if not report.ssl:
        return ""

    ssl = report.ssl
    grade = ssl.grade or "N/A"
    cert = ssl.certificate

    cert_rows = []
    if cert:
        cert_rows = [
            {
                "Field": "Subject",
                "Value": ", ".join(f"{k}={v}" for k, v in cert.subject.items())
                if cert.subject
                else "N/A",
            },
            {
                "Field": "Issuer",
                "Value": ", ".join(f"{k}={v}" for k, v in cert.issuer.items())
                if cert.issuer
                else "N/A",
            },
            {
                "Field": "Valid From",
                "Value": cert.not_before.isoformat() if cert.not_before else "N/A",
            },
            {
                "Field": "Valid Until",
                "Value": cert.not_after.isoformat() if cert.not_after else "N/A",
            },
            {
                "Field": "Days Until Expiry",
                "Value": str(cert.days_until_expiry)
                if cert.days_until_expiry is not None
                else "N/A",
            },
            {"Field": "Expired", "Value": cert.is_expired},
            {"Field": "Self-Signed", "Value": cert.is_self_signed},
            {
                "Field": "Signature Algorithm",
                "Value": cert.signature_algorithm or "N/A",
            },
            {
                "Field": "Public Key",
                "Value": f"{cert.public_key_algorithm} ({cert.public_key_bits} bits)"
                if cert.public_key_algorithm
                else "N/A",
            },
        ]

    findings_rows = [
        {
            "Title": f.title,
            "Severity": severity_upper(f.severity.value),
            "Description": f.description,
        }
        for f in ssl.findings
    ]

    return f"""
    <div class="section">
        <div class="section-header">
            <span class="grade {_grade_class(grade)}">{_escape(grade)}</span>
            SSL/TLS Analysis
        </div>
        <div class="section-body">
            <p><strong>HTTPS:</strong> {_bool_icon(ssl.is_https)}</p>
            <p><strong>Protocol:</strong> {_escape(ssl.protocol_version) or "N/A"}</p>
            <p><strong>Cipher Suite:</strong> <code>{_escape(ssl.cipher_suite) or "N/A"}</code></p>
            <p><strong>Chain Valid:</strong> {_bool_icon(ssl.chain_valid) if ssl.chain_valid is not None else "N/A"}</p>
            <p><strong>OCSP Stapling:</strong> {_bool_icon(ssl.ocsp_stapling) if ssl.ocsp_stapling is not None else "N/A"}</p>
            {"<h3 style='margin-top:1rem;margin-bottom:0.5rem'>Certificate</h3>" + _render_table(cert_rows, ["Field", "Value"]) if cert_rows else ""}
            {"<h3 style='margin-top:1rem;margin-bottom:0.5rem'>Findings</h3>" + _render_table(findings_rows, ["Title", "Severity", "Description"]) if findings_rows else ""}
        </div>
    </div>
    """


def _render_fingerprint(report: AnalysisReport) -> str:
    """Render the technology fingerprint section."""
    if not report.fingerprint:
        return ""

    fp = report.fingerprint
    tech_cards = []
    for tech in fp.technologies:
        version = f" v{_escape(tech.version)}" if tech.version else ""
        category = (
            f'<div class="category">{_escape(tech.category)}</div>'
            if tech.category
            else ""
        )
        confidence = (
            f'<span class="badge badge-info">{_escape(tech.confidence.value)}</span>'
            if tech.confidence
            else ""
        )
        tech_cards.append(
            f'<div class="tech-card">'
            f'<div class="name">{_escape(tech.name)}{version}</div>'
            f"{category}{confidence}"
            f"</div>"
        )

    summary_rows = []
    if fp.server:
        summary_rows.append({"Property": "Server", "Value": fp.server})
    if fp.powered_by:
        summary_rows.append({"Property": "Powered By", "Value": fp.powered_by})
    if fp.framework:
        summary_rows.append({"Property": "Framework", "Value": fp.framework})
    if fp.cms:
        summary_rows.append({"Property": "CMS", "Value": fp.cms})
    if fp.cdn:
        summary_rows.append({"Property": "CDN", "Value": fp.cdn})
    if fp.waf:
        summary_rows.append({"Property": "WAF", "Value": fp.waf})

    return f"""
    <div class="section">
        <div class="section-header">Technology Fingerprint</div>
        <div class="section-body">
            {_render_table(summary_rows, ["Property", "Value"]) if summary_rows else ""}
            <h3 style="margin-top:1rem;margin-bottom:0.5rem">Technologies Detected ({len(fp.technologies)})</h3>
            <div class="tech-grid">{"".join(tech_cards) if tech_cards else '<p class="empty-state">No technologies detected</p>'}</div>
        </div>
    </div>
    """


def _render_headers(report: AnalysisReport) -> str:
    """Render the security headers section."""
    if not report.headers:
        return ""

    headers = report.headers
    rows = [
        {
            "Header": f.header,
            "Present": f.present,
            "Value": f.value or "N/A",
            "Severity": severity_upper(f.severity.value),
            "Recommendation": f.recommendation,
        }
        for f in headers.findings
    ]

    return f"""
    <div class="section">
        <div class="section-header">
            Security Headers
            <span class="badge badge-info" style="margin-left:auto">Score: {headers.score}/100</span>
        </div>
        <div class="section-body">
            {_render_table(rows, ["Header", "Present", "Value", "Severity", "Recommendation"])}
        </div>
    </div>
    """


def _render_cves(report: AnalysisReport) -> str:
    """Render the CVE findings section."""
    if not report.cves:
        return ""

    rows = []
    for cve in report.cves:
        cvss_score = cve.cvss.base_score if cve.cvss else "N/A"
        rows.append(
            {
                "ID": cve.id,
                "Severity": severity_upper(cve.severity.value),
                "CVSS": str(cvss_score),
                "Description": cve.description[:200] + "..."
                if len(cve.description) > 200
                else cve.description,
                "Exploited": cve.is_exploited,
            }
        )

    return f"""
    <div class="section">
        <div class="section-header">
            CVE Findings
            <span class="badge badge-info" style="margin-left:auto">{len(report.cves)} CVEs</span>
        </div>
        <div class="section-body">
            {_render_table(rows, ["ID", "Severity", "CVSS", "Description", "Exploited"])}
        </div>
    </div>
    """


def _render_attack(report: AnalysisReport) -> str:
    """Render the attack simulation section."""
    if not report.attack:
        return ""

    attack = report.attack
    vuln_rows = []
    for v in attack.vulnerabilities:
        vuln_rows.append(
            {
                "Type": v.type,
                "Title": v.title,
                "Severity": severity_upper(v.severity.value),
                "Confidence": severity_upper(v.confidence.value),
                "URL": v.url,
                "Payload": v.payload.payload,
                "CWE": v.cwe_id or "N/A",
            }
        )

    vuln_details = []
    for v in attack.vulnerabilities:
        detail = f"""
        <div style="margin-bottom:1rem;padding:1rem;background:var(--bg-tertiary);border-radius:6px;border-left:3px solid var(--{v.severity.value})">
            <strong>{_escape(v.title)}</strong> {_severity_badge(v.severity.value)}
            <p style="margin-top:0.5rem;color:var(--text-secondary)">{_escape(v.description)}</p>
            <p style="margin-top:0.5rem"><strong>Payload:</strong> <code>{_escape(v.payload.payload)}</code></p>
            <p><strong>Parameter:</strong> {_escape(v.payload.parameter) or "N/A"} | <strong>Method:</strong> {_escape(v.payload.method)}</p>
            {"<div class='evidence-block'>" + _escape(v.evidence) + "</div>" if v.evidence else ""}
            {"<div class='remediation'><strong>Remediation:</strong> " + _escape(v.remediation) + "</div>" if v.remediation else ""}
        </div>
        """
        vuln_details.append(detail)

    return f"""
    <div class="section">
        <div class="section-header">
            Attack Simulation
            <span class="badge badge-info" style="margin-left:auto">{attack.total_findings} vulnerabilities found</span>
        </div>
        <div class="section-body">
            <div class="score-cards" style="margin-bottom:1rem">
                <div class="score-card"><div class="value">{attack.total_payloads_tested}</div><div class="label">Payloads Tested</div></div>
                <div class="score-card"><div class="value" style="color:var(--critical)">{attack.xss_findings}</div><div class="label">XSS</div></div>
                <div class="score-card"><div class="value" style="color:var(--high)">{attack.sqli_findings}</div><div class="label">SQLi</div></div>
                <div class="score-card"><div class="value" style="color:var(--medium)">{attack.traversal_findings}</div><div class="label">Traversal</div></div>
                <div class="score-card"><div class="value" style="color:var(--info)">{attack.enumeration_findings}</div><div class="label">Enumeration</div></div>
                <div class="score-card"><div class="value" style="color:var(--low)">{attack.csrf_findings}</div><div class="label">CSRF</div></div>
                <div class="score-card"><div class="value" style="color:var(--info)">{attack.subdomain_findings}</div><div class="label">Subdomains</div></div>
            </div>
            <h3 style="margin-bottom:0.5rem">Vulnerability Summary</h3>
            {_render_table(vuln_rows, ["Type", "Title", "Severity", "Confidence", "URL", "Payload", "CWE"])}
            <h3 style="margin-top:1.5rem;margin-bottom:0.5rem">Detailed Findings</h3>
            {"".join(vuln_details) if vuln_details else '<p class="empty-state">No vulnerabilities found</p>'}
        </div>
    </div>
    """


def _render_scrape(report: AnalysisReport) -> str:
    """Render the scraping results section."""
    if not report.scrape:
        return ""

    scrape = report.scrape

    links_list = ""
    if scrape.links:
        external_badge = ' <span class="badge badge-info">external</span>'
        items = "".join(
            f'<li><a href="{_escape(link.href)}" target="_blank">{_escape(link.href)}</a> '
            f'<span style="color:var(--text-secondary)">({_escape(link.text)[:50]})</span>'
            f"{external_badge if link.is_external else ''}</li>"
            for link in scrape.links[:100]
        )
        links_list = (
            f'<h3>Links ({len(scrape.links)})</h3><ul class="links-list">{items}</ul>'
        )

    forms_rows = [
        {
            "Action": f.action,
            "Method": f.method,
            "Name": f.name,
            "Fields": str(len(f.fields)),
        }
        for f in scrape.forms
    ]

    scripts_rows = [
        {"Source": s.src or "inline", "Type": s.type, "Inline": s.is_inline}
        for s in scrape.scripts[:50]
    ]

    return f"""
    <div class="section">
        <div class="section-header">Scraping Results</div>
        <div class="section-body">
            <p><strong>URL:</strong> <a href="{_escape(scrape.url)}" target="_blank" style="color:var(--accent)">{_escape(scrape.url)}</a></p>
            <p><strong>Status:</strong> {scrape.status_code} | <strong>Content-Type:</strong> {_escape(scrape.content_type)}</p>
            <p><strong>Title:</strong> {_escape(scrape.title) or "N/A"}</p>
            <p><strong>Meta Description:</strong> {_escape(scrape.meta_description) or "N/A"}</p>
            {links_list}
            {"<h3 style='margin-top:1rem;margin-bottom:0.5rem'>Forms</h3>" + _render_table(forms_rows, ["Action", "Method", "Name", "Fields"]) if forms_rows else ""}
            {"<h3 style='margin-top:1rem;margin-bottom:0.5rem'>Scripts</h3>" + _render_table(scripts_rows, ["Source", "Type", "Inline"]) if scripts_rows else ""}
        </div>
    </div>
    """


# =============================================================================
# HTML Exporter
# =============================================================================


class HTMLExporter(BaseExporter):
    """
    HTML exporter for visual security reports.

    Generates a self-contained HTML file with embedded CSS and professional
    styling. Supports both batch (complete report) and streaming modes.

    Batch mode (recommended):
        exporter = HTMLExporter("report.html")
        exporter.export_report(analysis_report)

    Streaming mode:
        with HTMLExporter("report.html") as exporter:
            exporter.write_header({"target_url": "..."})
            for item in results:
                exporter.write_item(item)
    """

    extension = ".html"

    def __init__(
        self,
        output_path: str | Path | None = None,
        *,
        stream: TextIO | None = None,
        include_raw: bool = False,
    ) -> None:
        super().__init__(
            output_path=output_path,
            stream=stream,
            indent=None,
            include_raw=include_raw,
        )
        self._items: list[dict[str, Any]] = []
        self._meta: dict[str, Any] | None = None

    def write_header(self, meta: dict[str, Any] | None = None) -> None:
        """Write HTML header opening."""
        if self._started:
            raise ExportWriteError("Header already written")
        self._started = True
        self._meta = meta

    def write_item(self, item: Any) -> None:
        """Write a single item (accumulates for final rendering)."""
        if self._finalized:
            raise ExportWriteError("Cannot write after finalization")
        if not self._started:
            self.write_header()

        data = self._serialize_item(item)
        self._items.append(data)
        self._items_written += 1

    def finalize(self) -> None:
        """Render and write the complete HTML document."""
        if self._finalized:
            return

        target_url = ""
        if self._meta:
            target_url = self._meta.get("target_url", "")

        items_html = ""
        for item in self._items:
            items_html += f"<pre style='background:var(--bg-tertiary);padding:1rem;border-radius:6px;overflow-x:auto;font-size:0.85rem;margin-bottom:1rem'>{html.escape(str(item))}</pre>"

        if not items_html:
            items_html = '<p class="empty-state">No items exported</p>'

        document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CiberWebScan Report{_escape(" - " + target_url) if target_url else ""}</title>
    <style>{_CSS_THEME}</style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>CiberWebScan Report</h1>
            <div class="meta">
                {"<span>Target: " + _escape(target_url) + "</span>" if target_url else ""}
                <span>Generated: {_escape(datetime.now(timezone.utc).isoformat())}</span>
                <span>Items: {self._items_written}</span>
            </div>
        </div>
        {items_html}
        <div class="report-footer">
            Generated by CiberWebScan &mdash; Professional Web Security Scanner
        </div>
    </div>
</body>
</html>"""

        self._write_to_stream(document)
        self._finalized = True
        logger.debug(f"HTML export finalized: {self._items_written} items written")

    def export_report(self, report: AnalysisReport) -> None:
        """Export a complete analysis report to a visual HTML document."""
        if self._started:
            raise ExportWriteError(
                "Cannot use export_report after streaming writes. "
                "Use either streaming (write_header/write_item) or batch (export_report)."
            )

        try:
            report.calculate_summary()
            meta = report.meta

            # Build sections
            sections = []
            sections.append(_render_summary(report))
            sections.append(_render_ssl(report))
            sections.append(_render_fingerprint(report))
            sections.append(_render_headers(report))
            sections.append(_render_cves(report))
            sections.append(_render_attack(report))
            sections.append(_render_scrape(report))

            sections_html = "\n".join(s for s in sections if s)

            target_url = meta.target_url
            timestamp_str = meta.timestamp.isoformat() if meta.timestamp else "N/A"

            document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CiberWebScan Report - {_escape(target_url)}</title>
    <style>{_CSS_THEME}</style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>CiberWebScan Security Report</h1>
            <div class="meta">
                <span>Target: <a href="{_escape(target_url)}" target="_blank" style="color:var(--accent)">{_escape(target_url)}</a></span>
                <span>Generated: {_escape(timestamp_str)}</span>
                <span>Duration: {meta.duration_seconds:.1f}s</span>
                <span>Version: {_escape(meta.version)}</span>
            </div>
        </div>
        {sections_html}
        <div class="report-footer">
            Generated by CiberWebScan v{_escape(meta.version)} &mdash; Professional Web Security Scanner
        </div>
    </div>
</body>
</html>"""

            self._write_to_stream(document)
            self._finalized = True
            logger.info(f"Report exported to HTML: {self.output_path or 'stream'}")

        except Exception as e:
            raise ExportWriteError(f"Failed to export report: {e}") from e

    def _write_to_stream(self, content: str) -> None:
        """Write content to the configured output."""
        if self._stream:
            self._stream.write(content)
        elif self.output_path:
            with open(self.output_path, "w", encoding=self.encoding) as f:
                f.write(content)
        else:
            raise ExportWriteError("No output stream or path configured")


def export_to_html(
    data: Any,
    output_path: str | Path,
    *,
    include_raw: bool = False,
) -> None:
    """
    Convenience function to export data to HTML file.

    Args:
        data: AnalysisReport or data to export.
        output_path: Path to output file.
        include_raw: Include raw HTML/response data.
    """
    exporter = HTMLExporter(
        output_path=output_path,
        include_raw=include_raw,
    )

    if hasattr(data, "meta") and hasattr(data, "calculate_summary"):
        exporter.export_report(data)
    else:
        with exporter:
            exporter.write_item(data)
