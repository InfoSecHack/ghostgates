"""
ghostgates/reporting/diff.py

Compare two scan results and report new, resolved, and unchanged findings.
Used by the `ghostgates diff` CLI command for drift detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ghostgates.models.findings import BypassFinding, ScanResult


def _finding_key(f: BypassFinding) -> str:
    """Stable unique key for a finding instance.

    Combines rule_id + repo + instance to identify the same finding
    across scans.  If instance is empty, falls back to rule_id + repo
    which means findings without instance keys will match by rule alone
    (acceptable — same rule on same repo is the same finding).
    """
    return f"{f.rule_id}|{f.repo}|{f.instance}"


@dataclass
class ScanDiff:
    """Result of comparing two scans."""

    old_scan_id: int | None
    old_scan_time: str | None
    new_scan_id: int | None
    new_scan_time: str | None
    org: str

    new_findings: list[BypassFinding] = field(default_factory=list)
    resolved_findings: list[BypassFinding] = field(default_factory=list)
    unchanged_findings: list[BypassFinding] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_findings or self.resolved_findings)


def diff_scans(old: ScanResult, new: ScanResult) -> ScanDiff:
    """Compare two scan results and categorize findings."""
    old_by_key = {_finding_key(f): f for f in old.findings}
    new_by_key = {_finding_key(f): f for f in new.findings}

    old_keys = set(old_by_key.keys())
    new_keys = set(new_by_key.keys())

    result = ScanDiff(
        old_scan_id=None,  # caller fills these from store metadata
        old_scan_time=old.collected_at if hasattr(old, "collected_at") else None,
        new_scan_id=None,
        new_scan_time=new.collected_at if hasattr(new, "collected_at") else None,
        org=new.org,
    )

    for key in sorted(new_keys - old_keys):
        result.new_findings.append(new_by_key[key])

    for key in sorted(old_keys - new_keys):
        result.resolved_findings.append(old_by_key[key])

    for key in sorted(old_keys & new_keys):
        result.unchanged_findings.append(new_by_key[key])

    return result


# ── Formatters ──────────────────────────────────────────────────────

_GREEN = "\033[32m"
_RED = "\033[31m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"
_YELLOW = "\033[33m"


def format_diff_terminal(d: ScanDiff) -> str:
    """Human-readable terminal diff output."""
    lines: list[str] = []

    lines.append("")
    lines.append(f"{_BOLD}╔══════════════════════════════════════════════════════╗{_RESET}")
    lines.append(f"{_BOLD}║  GhostGates Diff Report                              ║{_RESET}")
    lines.append(f"{_BOLD}╚══════════════════════════════════════════════════════╝{_RESET}")
    lines.append("")
    lines.append(f"  Organization:   {d.org}")
    if d.old_scan_time:
        lines.append(f"  Previous scan:  {d.old_scan_time}")
    if d.new_scan_time:
        lines.append(f"  Current scan:   {d.new_scan_time}")
    lines.append("")

    # Summary line
    parts = []
    if d.new_findings:
        parts.append(f"{_RED}+{len(d.new_findings)} new{_RESET}")
    if d.resolved_findings:
        parts.append(f"{_GREEN}-{len(d.resolved_findings)} resolved{_RESET}")
    parts.append(f"{len(d.unchanged_findings)} unchanged")

    lines.append(f"  {' │ '.join(parts)}")

    if not d.has_changes:
        lines.append("")
        lines.append(f"  {_GREEN}No changes since last scan.{_RESET}")
        lines.append("")
        return "\n".join(lines)

    # New findings
    if d.new_findings:
        lines.append("")
        lines.append(f"  {_RED}{_BOLD}── New Findings ──{_RESET}")
        for f in d.new_findings:
            instance_tag = f" ({f.instance})" if f.instance else ""
            lines.append(
                f"    {_RED}+ [{f.severity.value.upper()}] "
                f"{f.rule_id}{instance_tag}: {f.rule_name}{_RESET}"
            )
            lines.append(f"      {f.summary}")

    # Resolved findings
    if d.resolved_findings:
        lines.append("")
        lines.append(f"  {_GREEN}{_BOLD}── Resolved Findings ──{_RESET}")
        for f in d.resolved_findings:
            instance_tag = f" ({f.instance})" if f.instance else ""
            lines.append(
                f"    {_GREEN}- [{f.severity.value.upper()}] "
                f"{f.rule_id}{instance_tag}: {f.rule_name}{_RESET}"
            )
            lines.append(f"      {_DIM}{f.summary}{_RESET}")

    lines.append("")
    return "\n".join(lines)


def format_diff_json(d: ScanDiff) -> str:
    """JSON diff output."""
    import json

    return json.dumps(
        {
            "org": d.org,
            "old_scan_time": d.old_scan_time,
            "new_scan_time": d.new_scan_time,
            "summary": {
                "new": len(d.new_findings),
                "resolved": len(d.resolved_findings),
                "unchanged": len(d.unchanged_findings),
            },
            "new_findings": [f.model_dump(mode="json") for f in d.new_findings],
            "resolved_findings": [f.model_dump(mode="json") for f in d.resolved_findings],
        },
        indent=2,
    )


def format_diff_markdown(d: ScanDiff) -> str:
    """Markdown diff output."""
    lines: list[str] = []
    lines.append(f"# GhostGates Diff Report — {d.org}")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| 🆕 New findings | {len(d.new_findings)} |")
    lines.append(f"| ✅ Resolved | {len(d.resolved_findings)} |")
    lines.append(f"| ➡️ Unchanged | {len(d.unchanged_findings)} |")
    lines.append("")

    if d.new_findings:
        lines.append("## 🆕 New Findings")
        lines.append("")
        for f in d.new_findings:
            instance_tag = f" ({f.instance})" if f.instance else ""
            lines.append(f"- **[{f.severity.value.upper()}] {f.rule_id}{instance_tag}**: {f.summary}")
        lines.append("")

    if d.resolved_findings:
        lines.append("## ✅ Resolved Findings")
        lines.append("")
        for f in d.resolved_findings:
            instance_tag = f" ({f.instance})" if f.instance else ""
            lines.append(f"- ~~[{f.severity.value.upper()}] {f.rule_id}{instance_tag}~~: {f.summary}")
        lines.append("")

    if not d.has_changes:
        lines.append("**No changes since last scan.** All findings are unchanged.")
        lines.append("")

    return "\n".join(lines)
