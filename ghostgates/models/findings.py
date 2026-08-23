"""GhostGates — finding models.

Section 5 of ARCHITECTURE.md.

These represent the OUTPUT of the rule engine.
No I/O, no HTTP, no async.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ghostgates.models.enums import AttackerLevel, Confidence, GateType, Severity
from ghostgates.models.gates import CollectionError


class ScanScope(BaseModel):
    """Repositories requested, discovered, selected, and evaluated by a scan."""

    requested_repositories: list[str] | None = None
    discovered_repositories: list[str] = Field(default_factory=list)
    selected_repositories: list[str] = Field(default_factory=list)
    evaluated_repositories: list[str] = Field(default_factory=list)
    enumeration_complete: bool = False

    @property
    def is_complete(self) -> bool:
        if not self.enumeration_complete:
            return False
        if set(self.selected_repositories) != set(self.evaluated_repositories):
            return False
        if self.requested_repositories is not None:
            requested = set(self.requested_repositories)
            return (
                requested <= set(self.discovered_repositories)
                and requested <= set(self.selected_repositories)
            )
        return True



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
    settings_url: str = ""                          # direct link to GitHub settings page for fix

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
        # Ruleset IDs remain stable when a display name changes.
        if "ruleset_id" in ev and not parts:
            parts.append(str(ev["ruleset_id"]))
        elif "ruleset_name" in ev and not parts:
            parts.append(ev["ruleset_name"])
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
    errors: list[CollectionError | str] = Field(default_factory=list)
    scope: ScanScope | None = None
    scan_duration_seconds: float = 0.0
    attacker_level: AttackerLevel
    collected_at: str = ""

    @property
    def is_complete(self) -> bool:
        return not self.errors and self.scope is not None and self.scope.is_complete

    @property
    def error_messages(self) -> list[str]:
        return [str(error) for error in self.errors]

    @property
    def finding_count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
