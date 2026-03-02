"""
ghostgates/reporting/sarif.py

SARIF 2.1.0 output formatter. Produces Static Analysis Results
Interchange Format for integration with GitHub Code Scanning,
Azure DevOps, and other SARIF consumers.

Usage:
    ghostgates scan --org my-org --format sarif > results.sarif
    gh api -X POST /repos/{owner}/{repo}/code-scanning/sarifs \
        -f sarif=@results.sarif
"""

from __future__ import annotations

import json
from typing import Any

from ghostgates.models.enums import Severity
from ghostgates.models.findings import BypassFinding, ScanResult

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "GhostGates"
_TOOL_URI = "https://github.com/InfoSecHack/ghostgates"

# Map GhostGates severity → SARIF level
_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Map GhostGates severity → SARIF security-severity score (0-10)
_SEVERITY_TO_SCORE: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}


def _build_rule(finding: BypassFinding) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor (rule) from a finding."""
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.rule_name,
        "shortDescription": {
            "text": finding.rule_name,
        },
        "fullDescription": {
            "text": finding.summary,
        },
        "help": {
            "text": finding.remediation,
            "markdown": f"**Remediation:** {finding.remediation}",
        },
        "defaultConfiguration": {
            "level": _SEVERITY_TO_LEVEL[finding.severity],
        },
        "properties": {
            "security-severity": str(_SEVERITY_TO_SCORE[finding.severity]),
            "tags": ["security", "cicd", finding.gate_type.value],
            "precision": "high" if finding.confidence.value == "high" else "medium",
        },
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _build_location(finding: BypassFinding) -> dict[str, Any]:
    """Build a SARIF location from a finding.

    CI/CD findings don't always map to a specific file+line. We use:
    - Workflow path if available (from evidence)
    - Repo as the artifact location otherwise
    """
    wf_path = finding.evidence.get("workflow", "")

    if wf_path:
        return {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": wf_path,
                    "uriBaseId": "%SRCROOT%",
                },
                # Line 1 as default — SARIF requires a region for
                # GitHub Code Scanning to display the result
                "region": {
                    "startLine": 1,
                },
            },
            "logicalLocations": [
                {
                    "name": finding.repo,
                    "kind": "repository",
                },
            ],
        }

    # No workflow path — use repo-level logical location
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": ".github",
                "uriBaseId": "%SRCROOT%",
            },
            "region": {
                "startLine": 1,
            },
        },
        "logicalLocations": [
            {
                "name": finding.repo,
                "kind": "repository",
            },
        ],
    }


def _build_result(finding: BypassFinding, rule_index: int) -> dict[str, Any]:
    """Build a SARIF result from a finding."""
    instance_tag = f" ({finding.instance})" if finding.instance else ""

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _SEVERITY_TO_LEVEL[finding.severity],
        "message": {
            "text": (
                f"{finding.summary}\n\n"
                f"Bypass path:\n{finding.bypass_path}\n\n"
                f"Min privilege: {finding.min_privilege.value}"
            ),
        },
        "locations": [_build_location(finding)],
        "fingerprints": {
            # Stable fingerprint for dedup across scans
            "ghostgates/v1": f"{finding.rule_id}|{finding.repo}|{finding.instance}",
        },
        "properties": {
            "min_privilege": finding.min_privilege.value,
            "confidence": finding.confidence.value,
            "gate_type": finding.gate_type.value,
            "gating_conditions": finding.gating_conditions,
        },
    }

    if finding.settings_url:
        result["properties"]["settings_url"] = finding.settings_url

    # Add fix suggestion if we have a settings URL
    if finding.settings_url:
        result["fixes"] = [
            {
                "description": {
                    "text": finding.remediation.split("\n")[0],
                },
            },
        ]

    return result


def format_sarif(result: ScanResult) -> str:
    """Convert a ScanResult to SARIF 2.1.0 JSON string."""
    # Deduplicate rules by rule_id (multiple findings can share a rule)
    seen_rules: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for finding in result.findings:
        if finding.rule_id not in seen_rules:
            seen_rules[finding.rule_id] = len(rules)
            rules.append(_build_rule(finding))

        rule_index = seen_rules[finding.rule_id]
        results.append(_build_result(finding, rule_index))

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _TOOL_URI,
                        "version": "0.1.0",
                        "rules": rules,
                    },
                },
                "results": results,
                "automationDetails": {
                    "id": f"ghostgates/{result.org}/{result.collected_at}",
                },
            },
        ],
    }

    return json.dumps(sarif, indent=2)
