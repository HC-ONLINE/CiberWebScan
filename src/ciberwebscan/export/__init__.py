"""
Export package for CiberWebScan.

Provides exporters for different formats (JSON, JSONL, CSV) with streaming support.
All exporters share a common interface through the BaseExporter class.

Example usage:
    from ciberwebscan.export import JSONExporter, export_to_file

    # Batch export
    exporter = JSONExporter("output.json")
    exporter.export_report(analysis_report)

    # Streaming export
    with JSONExporter("output.json") as exporter:
        exporter.write_header({"version": "2.0"})
        for result in scan_results:
            exporter.write_item(result)

    # Using convenience context manager
    with export_to_file("results.jsonl", format="jsonl") as exporter:
        for item in items:
            exporter.write_item(item)
"""

# Base classes and utilities
from ciberwebscan.export.base import (
    BaseExporter,
    ExportError,
    ExportValidationError,
    ExportWriteError,
    StreamingExporter,
    export_to_file,
    get_exporter,
)

# CSV exporter
from ciberwebscan.export.csv import (
    CSVExporter,
    csv_to_dicts,
    export_to_csv,
    flatten_dict,
)

# JSON exporter
from ciberwebscan.export.json import (
    JSONExporter,
    dump,
    dumps,
    export_to_json,
)

# JSON Lines exporter
from ciberwebscan.export.jsonl import (
    JSONLExporter,
    export_to_jsonl,
    read_jsonl,
)

# Data models
from ciberwebscan.export.models import (
    AnalysisReport,
    AttackPayload,
    AttackResult,
    CertificateInfo,
    ConfidenceLevel,
    CVEReference,
    CVEResult,
    CVSSScore,
    ExportMeta,
    FingerprintResult,
    FormInfo,
    HeaderFinding,
    HeadersResult,
    ImageInfo,
    LinkInfo,
    ScrapeResult,
    ScriptInfo,
    Severity,
    SSLFinding,
    SSLResult,
    TechnologyMatch,
    VulnerabilityFinding,
)

__all__ = [
    # Base classes
    "BaseExporter",
    "StreamingExporter",
    "ExportError",
    "ExportWriteError",
    "ExportValidationError",
    # Factory functions
    "export_to_file",
    "get_exporter",
    # JSON
    "JSONExporter",
    "export_to_json",
    "dumps",
    "dump",
    # JSONL
    "JSONLExporter",
    "export_to_jsonl",
    "read_jsonl",
    # CSV
    "CSVExporter",
    "export_to_csv",
    "csv_to_dicts",
    "flatten_dict",
    # Enums
    "Severity",
    "ConfidenceLevel",
    # Metadata
    "ExportMeta",
    # Scraping models
    "ScrapeResult",
    "LinkInfo",
    "ImageInfo",
    "FormInfo",
    "ScriptInfo",
    # CVE models
    "CVEResult",
    "CVSSScore",
    "CVEReference",
    # Fingerprint models
    "FingerprintResult",
    "TechnologyMatch",
    # SSL models
    "SSLResult",
    "CertificateInfo",
    "SSLFinding",
    # Headers models
    "HeadersResult",
    "HeaderFinding",
    # Attack models
    "AttackResult",
    "AttackPayload",
    "VulnerabilityFinding",
    # Report model
    "AnalysisReport",
]
