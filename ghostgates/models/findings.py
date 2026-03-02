"""GhostGates — finding models.

Section 5 of ARCHITECTURE.md.

These represent the OUTPUT of the rule engine.
No I/O, no HTTP, no async.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ghostgates.models.enums import AttackerLevel, Confidence, GateType, Severity


class BypassFinding(BaseModel):
    """A single bypass finding produced by a rule."""

    rule_id: str                                    # e.g. "GHOST-BP-001"
    rule_name: str
    repo: str                                       # "org/repo"
    gate_type: GateType
    severity: Severity
    confidence: Confidence
    min_privilege: AttackerLevel
    summary: str                                    # one-line human-readable
    bypass_path: str                                # step-by-step explanation
    evidence: dict                                  # raw config proving the finding
    gating_conditions: list[str]                    # what else must be true
    remediation: str                                # specific fix
    references: list[str] = Field(default_factory=list)
    instance: str = ""                              # unique instance key within a rule

    def model_post_init(self, __context) -> None:
        """Auto-derive instance key from evidence if not explicitly set."""
        if self.instance:
            return
        ev = self.evidence
        parts: list[str] = []
        # Workflow + job is the most specific identifier
        if "workflow" in ev:
            parts.append(ev["workflow"].split("/")[-1])  # filename only
        if "job" in ev:
            parts.append(ev["job"])
        # Environment name
        if "environment" in ev and not parts:
            parts.append(ev["environment"])
        # Branch name
        if "branch" in ev and not parts:
            parts.append(ev["branch"])
        # Ruleset name
        if "ruleset" in ev and not parts:
            parts.append(ev["ruleset"])
        if parts:
            self.instance = "#".join(parts)

    def meets_filter(
        self,
        min_severity: Severity | None = None,
        max_attacker_level: AttackerLevel | None = None,
    ) -> bool:
        """Check if finding passes user-specified filters.

        Severity ordering: CRITICAL(0) > HIGH(1) > MEDIUM(2) > LOW(3) > INFO(4).
        A finding meets the filter when its severity index <= min_severity index.

        NOTE: Severity is a plain StrEnum (no custom __gt__), so we MUST
        use index-based comparison.  Alphabetical comparison is wrong
        (e.g. ``"info" > "medium"`` is False alphabetically).
        """
        if min_severity is not None:
            severity_order = list(Severity)
            if severity_order.index(self.severity) > severity_order.index(min_severity):
                return False
        if max_attacker_level is not None and self.min_privilege > max_attacker_level:
            return False
        return True


class ScanResult(BaseModel):
    """Complete scan result for an org."""

    org: str
    repos_scanned: int
    repos_skipped: int = 0                          # archived, forked, etc.
    findings: list[BypassFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    scan_duration_seconds: float = 0.0
    attacker_level: AttackerLevel
    collected_at: str = ""

    @property
    def finding_count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
