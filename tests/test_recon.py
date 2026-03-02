"""Tests for ghostgates recon (attack surface view)."""

from __future__ import annotations

import json

import pytest

from ghostgates.models.enums import (
    AttackerLevel,
    Confidence,
    GateType,
    Severity,
)
from ghostgates.models.findings import BypassFinding
from ghostgates.reporting.recon import (
    ReconResult,
    build_recon,
    format_recon_json,
    format_recon_markdown,
    format_recon_terminal,
)


# ── Helpers ──────────────────────────────────────────────────────

def _finding(
    rule_id: str = "GHOST-BP-001",
    repo: str = "acme/api",
    severity: Severity = Severity.HIGH,
    min_privilege: AttackerLevel = AttackerLevel.REPO_WRITE,
    gate_type: GateType = GateType.BRANCH_PROTECTION,
    evidence: dict | None = None,
    settings_url: str = "",
) -> BypassFinding:
    return BypassFinding(
        rule_id=rule_id,
        rule_name="Test rule",
        repo=repo,
        gate_type=gate_type,
        severity=severity,
        confidence=Confidence.HIGH,
        min_privilege=min_privilege,
        summary="Test summary",
        bypass_path="Step 1\nStep 2",
        evidence=evidence or {},
        gating_conditions=["condition"],
        remediation="Fix it",
        settings_url=settings_url,
    )


# ── Category matching ────────────────────────────────────────────


class TestWorkflowExecutionCategory:
    def test_wf001_matches(self):
        findings = [_finding(
            rule_id="GHOST-WF-001",
            severity=Severity.CRITICAL,
            min_privilege=AttackerLevel.EXTERNAL,
            gate_type=GateType.WORKFLOW,
            evidence={"workflow": ".github/workflows/pr_target.yml"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "workflow_exec")
        assert len(cat.hits) == 1
        assert "pr_target.yml" in cat.hits[0].description

    def test_wf004_matches(self):
        findings = [_finding(
            rule_id="GHOST-WF-004",
            min_privilege=AttackerLevel.EXTERNAL,
            gate_type=GateType.WORKFLOW,
            evidence={"workflow": ".github/workflows/post_ci.yml"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "workflow_exec")
        assert len(cat.hits) == 1

    def test_unrelated_rule_no_match(self):
        findings = [_finding(rule_id="GHOST-BP-001")]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "workflow_exec")
        assert len(cat.hits) == 0


class TestSecretsCategory:
    def test_wf003_secrets_inherit(self):
        findings = [_finding(
            rule_id="GHOST-WF-003",
            gate_type=GateType.WORKFLOW,
            evidence={
                "workflow": ".github/workflows/deploy.yml",
                "reusable_workflow": "other-org/shared/.github/workflows/build.yml@main",
            },
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "secrets")
        assert len(cat.hits) == 1
        assert "inherit" in cat.hits[0].description

    def test_wf004_fork_secrets(self):
        findings = [_finding(
            rule_id="GHOST-WF-004",
            gate_type=GateType.WORKFLOW,
            evidence={"workflow": ".github/workflows/ci.yml"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "secrets")
        assert len(cat.hits) == 1

    def test_wf002_write_all_workflow_scope(self):
        findings = [_finding(
            rule_id="GHOST-WF-002",
            gate_type=GateType.WORKFLOW,
            evidence={"workflow": ".github/workflows/ci.yml", "scope": "workflow"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "secrets")
        assert len(cat.hits) == 1

    def test_wf002_default_scope_no_match(self):
        findings = [_finding(
            rule_id="GHOST-WF-002",
            gate_type=GateType.WORKFLOW,
            evidence={"workflow": ".github/workflows/ci.yml", "scope": "default"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "secrets")
        assert len(cat.hits) == 0


class TestCloudCredCategory:
    def test_oidc001(self):
        findings = [_finding(
            rule_id="GHOST-OIDC-001",
            gate_type=GateType.OIDC,
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "cloud_creds")
        assert len(cat.hits) == 1
        assert "cross-repo" in cat.hits[0].description

    def test_oidc002(self):
        findings = [_finding(
            rule_id="GHOST-OIDC-002",
            gate_type=GateType.OIDC,
            evidence={"workflow": ".github/workflows/deploy.yml", "job": "aws"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "cloud_creds")
        assert len(cat.hits) == 1
        assert "deploy.yml#aws" in cat.hits[0].description


class TestCodeToProdCategory:
    def test_bp001_matches(self):
        findings = [_finding(
            rule_id="GHOST-BP-001",
            evidence={"branch": "main"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "code_to_prod")
        assert len(cat.hits) == 1
        assert "enforce_admins" in cat.hits[0].description

    def test_bp002_matches(self):
        findings = [_finding(
            rule_id="GHOST-BP-002",
            evidence={"branch": "main"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "code_to_prod")
        assert len(cat.hits) == 1

    def test_bp004_matches(self):
        findings = [_finding(
            rule_id="GHOST-BP-004",
            evidence={"unprotected_branches": ["staging", "production"]},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "code_to_prod")
        assert len(cat.hits) == 1
        assert "staging" in cat.hits[0].description

    def test_env001_matches(self):
        findings = [_finding(
            rule_id="GHOST-ENV-001",
            gate_type=GateType.ENVIRONMENT,
            evidence={"environment": "staging"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "code_to_prod")
        assert len(cat.hits) == 1

    def test_env002_matches(self):
        findings = [_finding(
            rule_id="GHOST-ENV-002",
            gate_type=GateType.ENVIRONMENT,
            evidence={"environment": "production"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "code_to_prod")
        assert len(cat.hits) == 1

    def test_bp005_matches(self):
        findings = [_finding(
            rule_id="GHOST-BP-005",
            gate_type=GateType.ACTIONS_PERMISSIONS,
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "code_to_prod")
        assert len(cat.hits) == 1


class TestProdDeployCategory:
    def test_env001_prod_matches(self):
        findings = [_finding(
            rule_id="GHOST-ENV-001",
            gate_type=GateType.ENVIRONMENT,
            evidence={"environment": "production"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "prod_deploy")
        assert len(cat.hits) == 1

    def test_env001_staging_no_match(self):
        """Non-prod environments don't match prod_deploy."""
        findings = [_finding(
            rule_id="GHOST-ENV-001",
            gate_type=GateType.ENVIRONMENT,
            evidence={"environment": "staging"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "prod_deploy")
        assert len(cat.hits) == 0

    def test_wf002_deploy_workflow(self):
        findings = [_finding(
            rule_id="GHOST-WF-002",
            gate_type=GateType.WORKFLOW,
            evidence={"workflow": ".github/workflows/deploy_prod.yml", "scope": "default"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "prod_deploy")
        assert len(cat.hits) == 1

    def test_wf002_ci_workflow_no_match(self):
        findings = [_finding(
            rule_id="GHOST-WF-002",
            gate_type=GateType.WORKFLOW,
            evidence={"workflow": ".github/workflows/ci.yml", "scope": "default"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "prod_deploy")
        assert len(cat.hits) == 0


class TestReviewBypassCategory:
    def test_bp001_matches(self):
        findings = [_finding(
            rule_id="GHOST-BP-001",
            evidence={"branch": "main"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "review_bypass")
        assert len(cat.hits) == 1

    def test_bp006_ruleset(self):
        findings = [_finding(
            rule_id="GHOST-BP-006",
            evidence={"ruleset": "test-rules"},
        )]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "review_bypass")
        assert len(cat.hits) == 1
        assert "test-rules" in cat.hits[0].description


# ── Cross-category behavior ──────────────────────────────────────


class TestCrossCategoryBehavior:
    def test_finding_can_appear_in_multiple_categories(self):
        """BP-001 should appear in both code_to_prod and review_bypass."""
        findings = [_finding(
            rule_id="GHOST-BP-001",
            evidence={"branch": "main"},
        )]
        recon = build_recon(findings, org="acme")
        code = next(c for c in recon.categories if c.key == "code_to_prod")
        review = next(c for c in recon.categories if c.key == "review_bypass")
        assert len(code.hits) == 1
        assert len(review.hits) == 1

    def test_empty_findings(self):
        recon = build_recon([], org="acme")
        assert recon.total_findings == 0
        assert recon.repos_exposed == 0
        assert all(len(c.hits) == 0 for c in recon.categories)

    def test_repos_exposed_count(self):
        findings = [
            _finding(rule_id="GHOST-BP-001", repo="acme/api", evidence={"branch": "main"}),
            _finding(rule_id="GHOST-BP-001", repo="acme/web", evidence={"branch": "main"}),
            _finding(rule_id="GHOST-WF-001", repo="acme/api",
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/x.yml"}),
        ]
        recon = build_recon(findings, org="acme")
        assert recon.repos_exposed == 2

    def test_severity_sorting(self):
        """Critical findings should come before high within a category."""
        findings = [
            _finding(rule_id="GHOST-WF-004", repo="acme/web",
                     severity=Severity.HIGH, min_privilege=AttackerLevel.EXTERNAL,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/ci.yml"}),
            _finding(rule_id="GHOST-WF-001", repo="acme/api",
                     severity=Severity.CRITICAL, min_privilege=AttackerLevel.EXTERNAL,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/pr.yml"}),
        ]
        recon = build_recon(findings, org="acme")
        cat = next(c for c in recon.categories if c.key == "workflow_exec")
        assert cat.hits[0].severity == Severity.CRITICAL
        assert cat.hits[1].severity == Severity.HIGH


# ── Formatters ───────────────────────────────────────────────────


class TestReconTerminalFormatter:
    def _recon(self) -> ReconResult:
        findings = [
            _finding(rule_id="GHOST-WF-001", repo="acme/api",
                     severity=Severity.CRITICAL, min_privilege=AttackerLevel.EXTERNAL,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/pr_target.yml"}),
            _finding(rule_id="GHOST-BP-001", repo="acme/api",
                     evidence={"branch": "main"}),
        ]
        return build_recon(findings, org="acme")

    def test_shows_header(self):
        output = format_recon_terminal(self._recon())
        assert "Attack Surface" in output

    def test_shows_categories(self):
        output = format_recon_terminal(self._recon())
        assert "Workflow Execution" in output
        assert "acme/api" in output

    def test_shows_clean_categories(self):
        output = format_recon_terminal(self._recon())
        assert "Clean" in output

    def test_empty_no_crash(self):
        recon = build_recon([], org="test")
        output = format_recon_terminal(recon)
        assert "Attack Surface" in output


class TestReconJsonFormatter:
    def test_valid_json(self):
        findings = [
            _finding(rule_id="GHOST-OIDC-001", gate_type=GateType.OIDC),
        ]
        recon = build_recon(findings, org="acme")
        parsed = json.loads(format_recon_json(recon))
        assert parsed["org"] == "acme"
        assert isinstance(parsed["categories"], list)
        cloud = next(c for c in parsed["categories"] if c["key"] == "cloud_creds")
        assert cloud["hit_count"] == 1

    def test_empty_json(self):
        recon = build_recon([], org="test")
        parsed = json.loads(format_recon_json(recon))
        assert parsed["total_findings"] == 0


class TestReconMarkdownFormatter:
    def test_has_headers(self):
        findings = [
            _finding(rule_id="GHOST-WF-001", repo="acme/api",
                     severity=Severity.CRITICAL, min_privilege=AttackerLevel.EXTERNAL,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/x.yml"}),
        ]
        recon = build_recon(findings, org="acme")
        output = format_recon_markdown(recon)
        assert "# GhostGates Attack Surface Report" in output
        assert "## " in output
        assert "| Repo |" in output
