"""SARIF 2.1.0 exporter compatible with GitHub Code Scanning (upload-sarif)."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from src.memory_store import DiagnosticRecord

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}
SEVERITY_TO_CVSS = {
    "CRITICAL": "9.5",
    "HIGH": "7.8",
    "MEDIUM": "5.5",
    "LOW": "2.5",
}


def _to_relative_uri(file_path: str, base_dir: Optional[str]) -> str:
    raw = str(file_path or "").replace("\\", "/")
    if base_dir:
        base_drive = os.path.splitdrive(base_dir)[0].lower()
        file_drive = os.path.splitdrive(file_path)[0].lower()
        if base_drive == file_drive or not base_drive or not file_drive:
            rel = os.path.relpath(file_path, base_dir)
            if not rel.startswith(".."):
                return rel.replace("\\", "/")
    if ":" in raw and Path(raw).is_absolute():
        return Path(raw).name
    return raw.lstrip("./")


def build_sarif_report(
    records: Sequence[Union[DiagnosticRecord, Dict[str, Any]]],
    tool_version: str = "2.1.0",
    base_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Constrói um relatório SARIF 2.1.0 válido para GitHub Code Scanning."""
    rules: List[Dict[str, Any]] = []
    rule_index_by_id: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    for rec in records:
        row = rec.model_dump() if isinstance(rec, DiagnosticRecord) else dict(rec)
        rule_id = str(row.get("error_category") or "Unknown")
        severity = str(row.get("severity") or "MEDIUM").upper()
        language = str(row.get("language") or "unknown")
        summary = str(row.get("diagnostic_summary") or rule_id)

        if rule_id not in rule_index_by_id:
            rule_index_by_id[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": rule_id.replace("_", " ")},
                    "fullDescription": {"text": summary},
                    "properties": {
                        "security-severity": SEVERITY_TO_CVSS.get(severity, "5.5"),
                        "tags": ["security", "data-engineering", language],
                    },
                }
            )

        start_line = max(1, int(row.get("start_line") or 1))
        end_line = max(start_line, int(row.get("end_line") or start_line))
        uri = _to_relative_uri(str(row.get("file_path") or ""), base_dir)
        ast_hash = str(row.get("ast_hash") or "")

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index_by_id[rule_id],
            "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "warning"),
            "message": {"text": summary},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": start_line, "endLine": end_line},
                    }
                }
            ],
        }
        if ast_hash:
            result["partialFingerprints"] = {
                "datapulseAstHash/v1": f"{ast_hash}:{rule_id}"
            }
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DataPulse AST Debugger",
                        "version": tool_version,
                        "informationUri": "https://github.com/vinodelucia/datapulse-ast-debugger",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
