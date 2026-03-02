"""
ghostgates/reporting/formatter.py

Output formatters for scan results: terminal (rich), JSON, and markdown.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from ghostgates.models.enums import Severity
from ghostgates.models.findings import BypassFinding, ScanResult

logger = logging.getLogger("ghostgates.reporting")

# Terminal colors (ANSI)
_COLORS = {
    Severity.CRITICAL: "\033[1;31m",  # bold red
    Severity.HIGH: "\033[91m",        # red
    Severity.MEDIUM: "\033[93m",      # yellow
    Severity.LOW: "\033[94m",         # blue
    Severity.INFO: "\033[90m",        # gray
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


# ------------------------------------------------------------------
# Terminal formatter
# ------------------------------------------------------------------

def format_terminal(result: ScanResult, *, verbose: bool = False) -> str:
    """Format scan results for terminal output with ANSI colors."""
    lines: list[str] = []

    # Header
    lines.append("")
    lines.append(f"{_BOLD}╔══════════════════════════════════════════════════════╗{_RESET}")
    lines.append(f"{_BOLD}║  GhostGates Scan Results                             ║{_RESET}")
    lines.append(f"{_BOLD}╚══════════════════════════════════════════════════════╝{_RESET}")
    lines.append("")

    # Summary
    lines.append(f"  Organization:   {result.org}")
    lines.append(f"  Repos scanned:  {result.repos_scanned}")
    lines.append(f"  Attacker level: {result.attacker_level}")
    lines.append(f"  Scan time:      {result.collected_at or 'now'}")
    lines.append("")

    # Severity counts
    counts = _severity_counts(result.findings)
    severity_line = "  Findings: "
    parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        c = counts.get(sev, 0)
        if c > 0:
            color = _COLORS.get(sev, "")
            parts.append(f"{color}{c} {sev.value}{_RESET}")
    if parts:
        severity_line += " │ ".join(parts)
    else:
        severity_line += "None"
    lines.append(severity_line)
    lines.append(f"  Total:    {len(result.findings)}")
    lines.append("")

    if not result.findings:
        lines.append(f"  {_BOLD}✓ No bypass findings detected{_RESET}")
        lines.append("")
        return "\n".join(lines)

    # Separator
    lines.append(f"  {'─' * 54}")
    lines.append("")

    # Findings grouped by repo
    findings_by_repo: dict[str, list[BypassFinding]] = {}
    for f in result.findings:
        findings_by_repo.setdefault(f.repo, []).append(f)

    for repo, findings in sorted(findings_by_repo.items()):
        lines.append(f"  {_BOLD}📁 {repo}{_RESET}")
        lines.append("")

        # Sort by severity (critical first)
        sorted_findings = sorted(findings, key=lambda f: _sev_order(f.severity))

        for f in sorted_findings:
            color = _COLORS.get(f.severity, "")
            instance_tag = f" ({f.instance})" if f.instance else ""
            lines.append(f"    {color}[{f.severity.value.upper()}]{_RESET} {f.rule_id}{instance_tag}: {f.rule_name}")
            lines.append(f"    {f.summary}")

            if verbose:
                lines.append("")
                lines.append(f"    {_DIM}Bypass path:{_RESET}")
                for bp_line in f.bypass_path.split("\n"):
                    lines.append(f"      {bp_line}")
                lines.append("")
                lines.append(f"    {_DIM}Min privilege:{_RESET} {f.min_privilege}")
                if f.gating_conditions:
                    lines.append(f"    {_DIM}Conditions:{_RESET}")
                    for gc in f.gating_conditions:
                        lines.append(f"      • {gc}")
                lines.append(f"    {_DIM}Remediation:{_RESET}")
                for rem_line in f.remediation.split("\n"):
                    lines.append(f"      {rem_line}")

            lines.append("")

        lines.append("")

    return "\n".join(lines)


def _severity_counts(findings: list[BypassFinding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _sev_order(sev: Severity) -> int:
    return _SEV_ORDER.get(sev, 99)


# ------------------------------------------------------------------
# JSON formatter
# ------------------------------------------------------------------

def format_json(result: ScanResult, *, indent: int = 2) -> str:
    """Format scan results as JSON."""
    return result.model_dump_json(indent=indent)


# ------------------------------------------------------------------
# Markdown formatter
# ------------------------------------------------------------------

def format_markdown(result: ScanResult) -> str:
    """Format scan results as a markdown report."""
    lines: list[str] = []

    lines.append("# GhostGates Scan Report")
    lines.append("")
    lines.append(f"**Organization:** {result.org}")
    lines.append(f"**Repos scanned:** {result.repos_scanned}")
    lines.append(f"**Attacker level:** {result.attacker_level}")
    lines.append(f"**Scan time:** {result.collected_at or 'now'}")
    lines.append("")

    # Summary table
    counts = _severity_counts(result.findings)
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        c = counts.get(sev, 0)
        if c > 0:
            lines.append(f"| {sev.value.upper()} | {c} |")
    lines.append(f"| **Total** | **{len(result.findings)}** |")
    lines.append("")

    if not result.findings:
        lines.append("✅ No bypass findings detected.")
        return "\n".join(lines)

    # Findings by repo
    findings_by_repo: dict[str, list[BypassFinding]] = {}
    for f in result.findings:
        findings_by_repo.setdefault(f.repo, []).append(f)

    lines.append("## Findings")
    lines.append("")

    for repo, findings in sorted(findings_by_repo.items()):
        lines.append(f"### {repo}")
        lines.append("")

        sorted_findings = sorted(findings, key=lambda f: _sev_order(f.severity))

        for f in sorted_findings:
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(f.severity.value, "⚪")
            instance_tag = f" ({f.instance})" if f.instance else ""
            lines.append(f"#### {sev_emoji} {f.rule_id}{instance_tag}: {f.rule_name}")
            lines.append("")
            lines.append(f"**Severity:** {f.severity.value.upper()} | **Confidence:** {f.confidence} | **Min privilege:** {f.min_privilege}")
            lines.append("")
            lines.append(f"{f.summary}")
            lines.append("")
            lines.append("**Bypass path:**")
            lines.append("```")
            lines.append(f"{f.bypass_path}")
            lines.append("```")
            lines.append("")

            if f.gating_conditions:
                lines.append("**Gating conditions:**")
                for gc in f.gating_conditions:
                    lines.append(f"- {gc}")
                lines.append("")

            lines.append("**Remediation:**")
            lines.append("")
            lines.append(f"{f.remediation}")
            lines.append("")

            if f.evidence:
                lines.append("<details><summary>Evidence</summary>")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(f.evidence, indent=2, default=str))
                lines.append("```")
                lines.append("</details>")
                lines.append("")

    return "\n".join(lines)
