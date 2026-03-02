"""
Tests for ghostgates.engine.registry and branch protection rules.

Each rule gets:
  - Positive test (bypass present → finding)
  - Negative test (bypass absent → no finding)
  - Edge cases specific to the rule
"""

from __future__ import annotations

import pytest

from ghostgates.engine import registry
from ghostgates.engine.registry import RuleRegistry
from ghostgates.models.enums import AttackerLevel, GateType, Severity
from ghostgates.models.findings import BypassFinding
from ghostgates.models.gates import GateModel

from tests.mocks.gate_models import (
    make_bp,
    make_environment,
    make_gate,
    make_reviewer,
    make_ruleset,
    make_trigger,
    make_workflow,
    make_job,
)


# ==================================================================
# Tests: Registry mechanics
# ==================================================================

class TestRegistry:
    def test_rules_registered(self):
        """All 6 BP rules are registered."""
        ids = {r.rule_id for r in registry.rules}
        assert "GHOST-BP-001" in ids
        assert "GHOST-BP-002" in ids
        assert "GHOST-BP-003" in ids
        assert "GHOST-BP-004" in ids
        assert "GHOST-BP-005" in ids
        assert "GHOST-BP-006" in ids

    def test_rule_count(self):
        assert len(registry.rules) >= 6

    def test_get_rule_by_id(self):
        r = registry.get_rule("GHOST-BP-001")
        assert r is not None
        assert r.name == "Admin bypass of required reviews"
        assert r.gate_type == GateType.BRANCH_PROTECTION
        assert r.min_privilege == AttackerLevel.REPO_ADMIN

    def test_get_nonexistent_rule(self):
        assert registry.get_rule("GHOST-FAKE-999") is None

    def test_attacker_level_filter(self):
        """Rules with higher min_privilege than attacker_level don't run."""
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=2),  # triggers BP-001 (needs REPO_ADMIN)
        ])
        # ORG_MEMBER can't trigger BP-001 (needs REPO_ADMIN)
        findings = registry.run_rules(gate, attacker_level=AttackerLevel.ORG_MEMBER)
        bp001 = [f for f in findings if f.rule_id == "GHOST-BP-001"]
        assert len(bp001) == 0

        # REPO_ADMIN can trigger BP-001
        findings = registry.run_rules(gate, attacker_level=AttackerLevel.REPO_ADMIN)
        bp001 = [f for f in findings if f.rule_id == "GHOST-BP-001"]
        assert len(bp001) == 1

    def test_rule_id_filter(self):
        """Can run specific rules only."""
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=2),
        ])
        findings = registry.run_rules(
            gate,
            attacker_level=AttackerLevel.ORG_OWNER,
            rule_ids=["GHOST-BP-001"],
        )
        assert all(f.rule_id == "GHOST-BP-001" for f in findings)

    def test_gate_type_filter(self):
        """Can filter by gate type."""
        gate = make_gate(
            branch_protections=[make_bp("main", reviews=2)],
            rulesets=[make_ruleset(enforcement="evaluate")],
        )
        # Only run ruleset rules
        findings = registry.run_rules(
            gate,
            attacker_level=AttackerLevel.ORG_OWNER,
            gate_types=[GateType.RULESET],
        )
        assert all(f.gate_type == GateType.RULESET for f in findings)

    def test_rule_exception_captured(self):
        """A rule that raises doesn't crash the engine."""
        test_registry = RuleRegistry()

        @test_registry.rule(
            rule_id="TEST-CRASH",
            name="Crashing rule",
            gate_type=GateType.BRANCH_PROTECTION,
            min_privilege=AttackerLevel.ORG_MEMBER,
        )
        def crash_rule(gate: GateModel) -> list[BypassFinding]:
            raise RuntimeError("boom")

        gate = make_gate()
        findings = test_registry.run_rules(gate, attacker_level=AttackerLevel.ORG_OWNER)
        assert findings == []  # crashed rule produces no findings, no exception

    def test_disabled_rule_skipped(self):
        """Disabled rules don't execute."""
        test_registry = RuleRegistry()

        @test_registry.rule(
            rule_id="TEST-DISABLED",
            name="Disabled rule",
            gate_type=GateType.BRANCH_PROTECTION,
            min_privilege=AttackerLevel.ORG_MEMBER,
            enabled=False,
        )
        def disabled_rule(gate: GateModel) -> list[BypassFinding]:
            return [BypassFinding(
                rule_id="TEST-DISABLED", rule_name="x", repo="x",
                gate_type=GateType.BRANCH_PROTECTION, severity=Severity.HIGH,
                confidence="high", min_privilege=AttackerLevel.ORG_MEMBER,
                summary="x", bypass_path="x", evidence={},
                gating_conditions=[], remediation="x",
            )]

        gate = make_gate()
        findings = test_registry.run_rules(gate, attacker_level=AttackerLevel.ORG_OWNER)
        assert findings == []

    def test_run_all_repos(self):
        """run_all_repos aggregates findings across multiple gates."""
        gates = [
            make_gate(repo="repo1", branch_protections=[make_bp("main", reviews=1)]),
            make_gate(repo="repo2", branch_protections=[make_bp("main", reviews=2)]),
        ]
        findings = registry.run_all_repos(gates, attacker_level=AttackerLevel.ORG_OWNER)
        repos = {f.repo for f in findings}
        assert "test-org/repo1" in repos
        assert "test-org/repo2" in repos


# ==================================================================
# Tests: GHOST-BP-001 — Admin bypass of required reviews
# ==================================================================

class TestBP001:
    def test_fires_when_reviews_without_enforce_admins(self):
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=2, enforce_admins=False),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_ADMIN,
            rule_ids=["GHOST-BP-001"],
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "GHOST-BP-001"
        assert f.severity == Severity.HIGH
        assert f.min_privilege == AttackerLevel.REPO_ADMIN
        assert "enforce_admins" in f.evidence
        assert f.evidence["enforce_admins"] is False

    def test_silent_when_enforce_admins_enabled(self):
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=2, enforce_admins=True),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_ADMIN,
            rule_ids=["GHOST-BP-001"],
        )
        assert len(findings) == 0

    def test_silent_when_no_reviews_required(self):
        """No reviews required → enforce_admins is irrelevant."""
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=0, enforce_admins=False),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_ADMIN,
            rule_ids=["GHOST-BP-001"],
        )
        assert len(findings) == 0

    def test_multiple_branches(self):
        """Fires for each vulnerable branch independently."""
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=2, enforce_admins=False),
            make_bp("develop", reviews=1, enforce_admins=False),
            make_bp("staging", reviews=1, enforce_admins=True),  # safe
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_ADMIN,
            rule_ids=["GHOST-BP-001"],
        )
        assert len(findings) == 2
        branches = {f.evidence["branch"] for f in findings}
        assert branches == {"main", "develop"}

    def test_no_branch_protections(self):
        """No branch protections → no findings (different concern)."""
        gate = make_gate(branch_protections=[])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_ADMIN,
            rule_ids=["GHOST-BP-001"],
        )
        assert len(findings) == 0


# ==================================================================
# Tests: GHOST-BP-002 — Stale review approval persistence
# ==================================================================

class TestBP002:
    def test_fires_when_stale_reviews_not_dismissed(self):
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=1, dismiss_stale=False),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-002"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].evidence["dismiss_stale_reviews"] is False

    def test_silent_when_stale_reviews_dismissed(self):
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=1, dismiss_stale=True),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-002"],
        )
        assert len(findings) == 0

    def test_silent_when_no_reviews(self):
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=0, dismiss_stale=False),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-002"],
        )
        assert len(findings) == 0


# ==================================================================
# Tests: GHOST-BP-003 — No CODEOWNERS enforcement
# ==================================================================

class TestBP003:
    def test_fires_when_reviews_without_codeowners(self):
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=2, codeowners=False),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-003"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert findings[0].evidence["require_code_owner_reviews"] is False

    def test_silent_when_codeowners_enabled(self):
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=2, codeowners=True),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-003"],
        )
        assert len(findings) == 0

    def test_silent_when_no_reviews(self):
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=0, codeowners=False),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-003"],
        )
        assert len(findings) == 0


# ==================================================================
# Tests: GHOST-BP-004 — Deployment branches unprotected
# ==================================================================

class TestBP004:
    def test_fires_when_deploy_branches_unprotected(self):
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=2, enforce_admins=True),
            # staging, production etc are NOT protected
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-004"],
        )
        assert len(findings) == 1
        assert "unprotected_deploy_branches" in findings[0].evidence
        unprotected = findings[0].evidence["unprotected_deploy_branches"]
        assert "staging" in unprotected
        assert "production" in unprotected

    def test_silent_when_no_default_protection(self):
        """If default branch isn't protected, this isn't the right finding."""
        gate = make_gate(branch_protections=[])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-004"],
        )
        assert len(findings) == 0

    def test_silent_when_default_has_no_reviews(self):
        """Default branch protected but with 0 reviews → not a gap."""
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=0),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-004"],
        )
        assert len(findings) == 0

    def test_deploy_branches_from_environments(self):
        """Detects deploy branches referenced by environment policies."""
        gate = make_gate(
            branch_protections=[
                make_bp("main", reviews=1),
            ],
            environments=[
                make_environment(
                    "production",
                    deployment_policy_type="selected",
                    deployment_patterns=["release-v1"],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-004"],
        )
        assert len(findings) == 1
        unprotected = findings[0].evidence["unprotected_deploy_branches"]
        assert "release-v1" in unprotected

    def test_fewer_unprotected_when_staging_protected(self):
        """Protected deploy branches are excluded from finding."""
        gate = make_gate(branch_protections=[
            make_bp("main", reviews=2),
            make_bp("staging", reviews=1),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-004"],
        )
        assert len(findings) == 1
        unprotected = findings[0].evidence["unprotected_deploy_branches"]
        assert "staging" not in unprotected
        assert "production" in unprotected


# ==================================================================
# Tests: GHOST-BP-005 — Workflows can approve own PRs
# ==================================================================

class TestBP005:
    def test_fires_when_can_approve_with_reviews(self):
        from ghostgates.models.gates import WorkflowPermissions
        gate = make_gate(
            branch_protections=[make_bp("main", reviews=1)],
            workflow_permissions=WorkflowPermissions(
                can_approve_pull_request_reviews=True,
            ),
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-005"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["can_approve_pull_request_reviews"] is True

    def test_silent_when_can_approve_disabled(self):
        from ghostgates.models.gates import WorkflowPermissions
        gate = make_gate(
            branch_protections=[make_bp("main", reviews=1)],
            workflow_permissions=WorkflowPermissions(
                can_approve_pull_request_reviews=False,
            ),
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-005"],
        )
        assert len(findings) == 0

    def test_silent_when_no_review_requirements(self):
        """Can approve is enabled but no branches require reviews → no finding."""
        from ghostgates.models.gates import WorkflowPermissions
        gate = make_gate(
            branch_protections=[make_bp("main", reviews=0)],
            workflow_permissions=WorkflowPermissions(
                can_approve_pull_request_reviews=True,
            ),
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-005"],
        )
        assert len(findings) == 0

    def test_silent_when_no_branch_protections(self):
        from ghostgates.models.gates import WorkflowPermissions
        gate = make_gate(
            branch_protections=[],
            workflow_permissions=WorkflowPermissions(
                can_approve_pull_request_reviews=True,
            ),
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-005"],
        )
        assert len(findings) == 0


# ==================================================================
# Tests: GHOST-BP-006 — Ruleset in evaluate mode
# ==================================================================

class TestBP006:
    def test_fires_on_evaluate_mode(self):
        gate = make_gate(
            rulesets=[make_ruleset("main-rules", enforcement="evaluate")],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-006"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["enforcement"] == "evaluate"

    def test_silent_on_active_mode(self):
        gate = make_gate(
            rulesets=[make_ruleset("main-rules", enforcement="active")],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-006"],
        )
        assert len(findings) == 0

    def test_silent_on_disabled_mode(self):
        gate = make_gate(
            rulesets=[make_ruleset("main-rules", enforcement="disabled")],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-006"],
        )
        assert len(findings) == 0

    def test_higher_severity_without_branch_protection(self):
        """Evaluate-mode ruleset as only protection → HIGH severity."""
        gate = make_gate(
            branch_protections=[],  # no real protection
            rulesets=[make_ruleset("main-rules", enforcement="evaluate")],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-006"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_lower_severity_with_branch_protection(self):
        """Evaluate-mode alongside real protection → MEDIUM severity."""
        gate = make_gate(
            branch_protections=[make_bp("main", reviews=1)],
            rulesets=[make_ruleset("main-rules", enforcement="evaluate")],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-006"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_multiple_rulesets_mixed(self):
        """Only evaluate-mode rulesets produce findings."""
        gate = make_gate(
            rulesets=[
                make_ruleset("active-rules", enforcement="active"),
                make_ruleset("eval-rules", enforcement="evaluate"),
                make_ruleset("disabled-rules", enforcement="disabled"),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-006"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["ruleset_name"] == "eval-rules"

    def test_target_branches_resolved(self):
        """~DEFAULT_BRANCH resolves to the actual default branch name."""
        gate = make_gate(
            default_branch="main",
            rulesets=[make_ruleset("eval", enforcement="evaluate")],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-BP-006"],
        )
        assert len(findings) == 1
        assert "main" in findings[0].evidence["target_branches"]


# ==================================================================
# Tests: Finding quality checks
# ==================================================================

class TestFindingQuality:
    """Verify that all findings have the required fields populated."""

    def _get_all_bp_findings(self) -> list[BypassFinding]:
        """Run all BP rules against a maximally-vulnerable gate."""
        from ghostgates.models.gates import WorkflowPermissions
        gate = make_gate(
            branch_protections=[
                make_bp("main", reviews=2, enforce_admins=False,
                        dismiss_stale=False, codeowners=False),
            ],
            rulesets=[make_ruleset("eval", enforcement="evaluate")],
            workflow_permissions=WorkflowPermissions(
                can_approve_pull_request_reviews=True,
            ),
        )
        return registry.run_rules(gate, attacker_level=AttackerLevel.ORG_OWNER)

    def test_all_findings_have_rule_id(self):
        for f in self._get_all_bp_findings():
            assert f.rule_id.startswith("GHOST-BP-")

    def test_all_findings_have_evidence(self):
        for f in self._get_all_bp_findings():
            assert isinstance(f.evidence, dict)
            assert len(f.evidence) > 0

    def test_all_findings_have_remediation(self):
        for f in self._get_all_bp_findings():
            assert len(f.remediation) > 10

    def test_all_findings_have_bypass_path(self):
        for f in self._get_all_bp_findings():
            assert len(f.bypass_path) > 20
            assert "1." in f.bypass_path  # numbered steps

    def test_all_findings_have_summary(self):
        for f in self._get_all_bp_findings():
            assert len(f.summary) > 10

    def test_all_findings_have_repo(self):
        for f in self._get_all_bp_findings():
            assert "/" in f.repo  # org/repo format
