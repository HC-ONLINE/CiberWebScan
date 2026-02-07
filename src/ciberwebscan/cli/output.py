"""
Output formatting for CLI.

Simple text output without Rich - uses standard print and logging.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from typing import Any


def print_error(message: str) -> None:
    """Print error message to stderr."""
    print(f"ERROR: {message}", file=sys.stderr)


def print_warning(message: str) -> None:
    """Print warning message to stderr."""
    print(f"WARNING: {message}", file=sys.stderr)


def print_success(message: str) -> None:
    """Print success message."""
    print(f"OK: {message}")


def print_info(message: str) -> None:
    """Print info message."""
    print(message)


def print_header(title: str) -> None:
    """Print section header."""
    print(f"\n=== {title} ===")


def print_subheader(title: str) -> None:
    """Print subsection header."""
    print(f"\n--- {title} ---")


def print_key_value(key: str, value: Any, indent: int = 0) -> None:
    """Print key-value pair."""
    prefix = "  " * indent
    print(f"{prefix}{key}: {value}")


def print_list(items: list[Any], indent: int = 0) -> None:
    """Print list items."""
    prefix = "  " * indent
    for item in items:
        print(f"{prefix}- {item}")


def print_dict(data: dict[str, Any], indent: int = 0) -> None:
    """Print dictionary as key-value pairs."""
    for key, value in data.items():
        if isinstance(value, dict):
            print_key_value(key, "", indent)
            print_dict(value, indent + 1)
        elif isinstance(value, list):
            print_key_value(key, "", indent)
            print_list(value, indent + 1)
        else:
            print_key_value(key, value, indent)


def print_json(data: Any, pretty: bool = True) -> None:
    """Print data as JSON."""
    if pretty:
        print(json.dumps(data, indent=2, default=str, ensure_ascii=False))
    else:
        print(json.dumps(data, default=str, ensure_ascii=False))


def format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"


def format_timestamp(dt: datetime | None) -> str:
    """Format datetime for display."""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def format_size(bytes_count: int | float) -> str:
    """
    Format byte count in human-readable form.
    Optimized for performance and type safety.
    """
    if bytes_count < 0:
        return "0.0 B"

    units = ("B", "KB", "MB", "GB", "TB", "PB")
    size = float(bytes_count)
    unit_index = 0

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    return f"{size:.1f} {units[unit_index]}"


# ============================================================================
# Result Formatters
# ============================================================================


def format_scrape_result(result: Any) -> None:
    """Format and print scrape result."""
    if hasattr(result, "url"):
        print_header("Scrape Result")
        print_key_value("URL", result.url)
        print_key_value("Status", result.status_code)
        if hasattr(result, "title") and result.title:
            print_key_value("Title", result.title)
        if hasattr(result, "elapsed_ms") and result.elapsed_ms is not None:
            print_key_value("Time", f"{result.elapsed_ms:.0f}ms")
        if hasattr(result, "text_content") and result.text_content:
            preview = result.text_content[:200]
            if len(result.text_content) > 200:
                preview += "..."
            print_key_value("Content Preview", preview)
    elif isinstance(result, list):
        print_header(f"Extracted Data ({len(result)} items)")
        for i, item in enumerate(result[:10], 1):
            print(f"\n[{i}]")
            if isinstance(item, dict):
                print_dict(item, indent=1)
            else:
                print(f"  {item}")
        if len(result) > 10:
            print(f"\n  ... and {len(result) - 10} more items")


def format_analysis_result(report: Any) -> None:
    """Format and print analysis report."""
    print_header("Analysis Report")

    if hasattr(report, "meta") and report.meta:
        print_key_value("Target", report.meta.target_url)
        print_key_value("Timestamp", format_timestamp(report.meta.timestamp))

    # SSL Results
    if hasattr(report, "ssl") and report.ssl:
        print_subheader("SSL/TLS")
        ssl = report.ssl
        print_key_value("HTTPS", "Yes" if ssl.is_https else "No", indent=1)
        if ssl.protocol_version:
            print_key_value("Protocol", ssl.protocol_version, indent=1)
        if ssl.grade:
            print_key_value("Grade", ssl.grade, indent=1)
        if ssl.chain_valid is not None:
            print_key_value("Chain Valid", "Yes" if ssl.chain_valid else "No", indent=1)

    # Fingerprint Results
    if hasattr(report, "fingerprint") and report.fingerprint:
        print_subheader("Technologies")
        fp = report.fingerprint
        if fp.technologies:
            for tech in fp.technologies[:15]:
                version = f" v{tech.version}" if tech.version else ""
                confidence = (
                    f" ({tech.confidence.value})" if hasattr(tech, "confidence") else ""
                )
                print(f"  - {tech.name}{version}{confidence}")
            if len(fp.technologies) > 15:
                print(f"  ... and {len(fp.technologies) - 15} more")
        if fp.server:
            print_key_value("Server", fp.server, indent=1)
        if fp.powered_by:
            print_key_value("Powered By", fp.powered_by, indent=1)

    # Security Headers Results
    if hasattr(report, "headers") and report.headers:
        print_subheader("Security Headers")
        headers = report.headers
        print_key_value("Overall Score", f"{headers.score}/100", indent=1)

        if headers.findings:
            for finding in headers.findings:
                status = "SUCCESS" if finding.present else "FAILURE"
                print(f"  {status} {finding.header}")
                if finding.severity.value != "info":
                    print_key_value("Severity", finding.severity.value, indent=2)
                if finding.recommendation:
                    print_key_value("Recommendation", finding.recommendation, indent=2)

    # CVE Results
    if hasattr(report, "cves") and report.cves:
        print_subheader(f"CVEs ({len(report.cves)})")
        for cve in report.cves[:10]:
            severity = f"[{cve.severity.value}]" if hasattr(cve, "severity") else ""
            print(f"  - {cve.id} {severity}")
            if cve.description:
                desc = cve.description[:80]
                if len(cve.description) > 80:
                    desc += "..."
                print(f"      {desc}")
        if len(report.cves) > 10:
            print(f"  ... and {len(report.cves) - 10} more")


def format_config_result(config: dict[str, Any]) -> None:
    """Format and print configuration."""
    print_header("Configuration")
    print_dict(config)


def format_service_result(result: Any, json_output: bool = False) -> int:
    """
    Format and print a ServiceResult.

    Returns exit code (0 for success, 1 for failure).
    """
    if json_output:
        output = {
            "success": result.success,
            "duration": result.duration_seconds,
        }
        if result.success:
            if hasattr(result.data, "model_dump"):
                output["data"] = result.data.model_dump()
            elif hasattr(result.data, "__dict__"):
                output["data"] = result.data.__dict__
            else:
                output["data"] = result.data
        else:
            output["error"] = result.error
            output["error_code"] = result.error_code

        if result.exported:
            output["exported_to"] = str(result.export_path)

        print_json(output)
    else:
        if not result.success:
            print_error(f"{result.error} (code: {result.error_code})")
            return 1

        if result.exported:
            print_success(f"Exported to: {result.export_path}")

        print_info(f"Completed in {format_duration(result.duration_seconds)}")

    return 0 if result.success else 1
