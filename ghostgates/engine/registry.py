"""
ghostgates/engine/registry.py

Decorator-based bypass rule registry.

Each rule is a plain function decorated with @bypass_rule that:
  - Takes a GateModel
  - Returns a list of BypassFinding (empty if no bypass detected)

The registry collects all decorated rules and provides a single
run_rules() entry point that executes them against a GateModel.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from ghostgates.models.enums import AttackerLevel, GateType
from ghostgates.models.gates import GateModel
from ghostgates.models.findings import BypassFinding

logger = logging.getLogger("ghostgates.engine")

# Type alias for a rule function
RuleFunc = Callable[[GateModel], list[BypassFinding]]


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata attached to a registered rule."""

    rule_id: str          # e.g. "GHOST-BP-001"
    name: str             # human-readable rule name
    gate_type: GateType   # which gate category this rule checks
    min_privilege: AttackerLevel  # minimum attacker level to trigger
    func: RuleFunc        # the actual rule function
    tags: tuple[str, ...] = ()
    enabled: bool = True


class RuleRegistry:
    """Central registry of all bypass rules.

    Usage::

        registry = RuleRegistry()

        @registry.rule(
            rule_id="GHOST-BP-001",
            name="Admin bypass of required reviews",
            gate_type=GateType.BRANCH_PROTECTION,
            min_privilege=AttackerLevel.REPO_ADMIN,
        )
        def bp_001_admin_bypass(gate: GateModel) -> list[BypassFinding]:
            ...

        findings = registry.run_rules(gate_model)
    """

    def __init__(self) -> None:
        self._rules: list[RuleMetadata] = []

    def rule(
        self,
        rule_id: str,
        name: str,
        gate_type: GateType,
        min_privilege: AttackerLevel,
        tags: tuple[str, ...] = (),
        enabled: bool = True,
    ) -> Callable[[RuleFunc], RuleFunc]:
        """Decorator to register a bypass rule."""

        def decorator(func: RuleFunc) -> RuleFunc:
            meta = RuleMetadata(
                rule_id=rule_id,
                name=name,
                gate_type=gate_type,
                min_privilege=min_privilege,
                func=func,
                tags=tags,
                enabled=enabled,
            )
            self._rules.append(meta)
            # Attach metadata to the function for introspection
            func._rule_meta = meta  # type: ignore[attr-defined]
            return func

        return decorator

    @property
    def rules(self) -> list[RuleMetadata]:
        """All registered rules."""
        return list(self._rules)

    @property
    def enabled_rules(self) -> list[RuleMetadata]:
        """Only enabled rules."""
        return [r for r in self._rules if r.enabled]

    def get_rule(self, rule_id: str) -> RuleMetadata | None:
        """Look up a rule by ID."""
        for r in self._rules:
            if r.rule_id == rule_id:
                return r
        return None

    def run_rules(
        self,
        gate: GateModel,
        *,
        attacker_level: AttackerLevel = AttackerLevel.ORG_MEMBER,
        rule_ids: list[str] | None = None,
        gate_types: list[GateType] | None = None,
    ) -> list[BypassFinding]:
        """Execute all applicable rules against a GateModel.

        Args:
            gate: The gate model to analyze.
            attacker_level: Only run rules where min_privilege <= attacker_level.
            rule_ids: If set, only run these specific rules.
            gate_types: If set, only run rules for these gate types.

        Returns:
            List of findings from all rules that fired.
        """
        findings: list[BypassFinding] = []

        for meta in self.enabled_rules:
            # Filter by attacker level
            if meta.min_privilege > attacker_level:
                continue

            # Filter by specific rule IDs
            if rule_ids and meta.rule_id not in rule_ids:
                continue

            # Filter by gate type
            if gate_types and meta.gate_type not in gate_types:
                continue

            try:
                rule_findings = meta.func(gate)
                findings.extend(rule_findings)
            except Exception as exc:
                logger.error(
                    "Rule %s (%s) raised an exception on %s: %s",
                    meta.rule_id, meta.name, gate.full_name, exc,
                )

        return findings

    def run_all_repos(
        self,
        gates: list[GateModel],
        *,
        attacker_level: AttackerLevel = AttackerLevel.ORG_MEMBER,
    ) -> list[BypassFinding]:
        """Run all rules against multiple GateModels."""
        all_findings: list[BypassFinding] = []
        for gate in gates:
            all_findings.extend(
                self.run_rules(gate, attacker_level=attacker_level)
            )
        return all_findings


# ------------------------------------------------------------------
# Global registry instance — rules register themselves on import
# ------------------------------------------------------------------

registry = RuleRegistry()
