"""Tests for ghostgates graph (kill chain visualization)."""

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
from ghostgates.reporting.graph import (
    GraphNode,
    NodeKind,
    build_org_graph,
    build_repo_graph,
    format_graph_json,
    format_graph_mermaid,
    format_graph_terminal,
    render_repo_mermaid,
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


# ── Repo graph building ─────────────────────────────────────────


class TestBuildRepoGraph:
    def test_single_finding_creates_three_nodes(self):
        findings = [_finding(
            rule_id="GHOST-BP-001",
            evidence={"branch": "main"},
        )]
        g = build_repo_graph("acme/api", findings)
        kinds = {n.kind for n in g.nodes}
        assert NodeKind.ENTRY in kinds
        assert NodeKind.BYPASS in kinds
        assert NodeKind.IMPACT in kinds

    def test_single_finding_creates_two_edges(self):
        findings = [_finding(
            rule_id="GHOST-BP-001",
            evidence={"branch": "main"},
        )]
        g = build_repo_graph("acme/api", findings)
        assert len(g.edges) == 2  # entry→bypass, bypass→impact

    def test_two_findings_same_level_share_entry(self):
        findings = [
            _finding(rule_id="GHOST-BP-001", evidence={"branch": "main"}),
            _finding(rule_id="GHOST-BP-002", evidence={"branch": "main"}),
        ]
        g = build_repo_graph("acme/api", findings)
        entries = [n for n in g.nodes if n.kind == NodeKind.ENTRY]
        assert len(entries) == 1

    def test_two_findings_different_levels_separate_entries(self):
        findings = [
            _finding(rule_id="GHOST-WF-001",
                     min_privilege=AttackerLevel.EXTERNAL,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/pr.yml"}),
            _finding(rule_id="GHOST-BP-001",
                     min_privilege=AttackerLevel.REPO_WRITE,
                     evidence={"branch": "main"}),
        ]
        g = build_repo_graph("acme/api", findings)
        entries = [n for n in g.nodes if n.kind == NodeKind.ENTRY]
        assert len(entries) == 2

    def test_shared_impact_deduped(self):
        """BP-001 and BP-002 should share the 'unreviewed code' impact."""
        findings = [
            _finding(rule_id="GHOST-BP-001", evidence={"branch": "main"}),
            _finding(rule_id="GHOST-BP-002", evidence={"branch": "main"}),
        ]
        g = build_repo_graph("acme/api", findings)
        impacts = [n for n in g.nodes if n.kind == NodeKind.IMPACT]
        assert len(impacts) == 1
        assert "Unreviewed" in impacts[0].label

    def test_empty_findings_empty_graph(self):
        g = build_repo_graph("acme/api", [])
        assert len(g.nodes) == 0
        assert len(g.edges) == 0

    def test_bypass_node_has_severity(self):
        findings = [_finding(
            rule_id="GHOST-WF-001",
            severity=Severity.CRITICAL,
            min_privilege=AttackerLevel.EXTERNAL,
            gate_type=GateType.WORKFLOW,
            evidence={"workflow": ".github/workflows/pr.yml"},
        )]
        g = build_repo_graph("acme/api", findings)
        bypass = next(n for n in g.nodes if n.kind == NodeKind.BYPASS)
        assert bypass.severity == Severity.CRITICAL
        assert bypass.rule_id == "GHOST-WF-001"

    def test_bypass_node_has_rule_id(self):
        findings = [_finding(
            rule_id="GHOST-OIDC-002",
            gate_type=GateType.OIDC,
            evidence={"workflow": ".github/workflows/deploy.yml", "job": "aws"},
        )]
        g = build_repo_graph("acme/api", findings)
        bypass = next(n for n in g.nodes if n.kind == NodeKind.BYPASS)
        assert bypass.rule_id == "GHOST-OIDC-002"


# ── Bypass labels ────────────────────────────────────────────────


class TestBypassLabels:
    """Ensure each rule ID produces a meaningful label."""

    def _get_bypass_label(self, rule_id, evidence, **kw):
        findings = [_finding(rule_id=rule_id, evidence=evidence, **kw)]
        g = build_repo_graph("acme/api", findings)
        bypass = next(n for n in g.nodes if n.kind == NodeKind.BYPASS)
        return bypass.label

    def test_wf001_label(self):
        label = self._get_bypass_label(
            "GHOST-WF-001",
            {"workflow": ".github/workflows/pr_target.yml"},
            gate_type=GateType.WORKFLOW,
        )
        assert "pr_target.yml" in label
        assert "pull_request_target" in label

    def test_bp001_label(self):
        label = self._get_bypass_label("GHOST-BP-001", {"branch": "main"})
        assert "enforce_admins" in label
        assert "main" in label

    def test_env001_label(self):
        label = self._get_bypass_label(
            "GHOST-ENV-001",
            {"environment": "production"},
            gate_type=GateType.ENVIRONMENT,
        )
        assert "production" in label
        assert "reviewer" in label

    def test_oidc001_label(self):
        label = self._get_bypass_label(
            "GHOST-OIDC-001", {},
            gate_type=GateType.OIDC,
        )
        assert "OIDC" in label
        assert "default" in label

    def test_oidc002_label(self):
        label = self._get_bypass_label(
            "GHOST-OIDC-002",
            {"workflow": ".github/workflows/deploy.yml", "job": "aws"},
            gate_type=GateType.OIDC,
        )
        assert "deploy.yml" in label
        assert "aws" in label

    def test_bp006_label(self):
        label = self._get_bypass_label("GHOST-BP-006", {"ruleset": "test-rules"})
        assert "test-rules" in label
        assert "evaluate" in label

    def test_wf003_label(self):
        label = self._get_bypass_label(
            "GHOST-WF-003",
            {"workflow": ".github/workflows/deploy.yml"},
            gate_type=GateType.WORKFLOW,
        )
        assert "inherit" in label


# ── Impact derivation ────────────────────────────────────────────


class TestImpactDerivation:
    def _get_impact_label(self, rule_id, **kw):
        findings = [_finding(rule_id=rule_id, **kw)]
        g = build_repo_graph("acme/api", findings)
        impact = next(n for n in g.nodes if n.kind == NodeKind.IMPACT)
        return impact.label

    def test_wf001_impact(self):
        label = self._get_impact_label(
            "GHOST-WF-001", gate_type=GateType.WORKFLOW,
            evidence={"workflow": ".github/workflows/x.yml"},
        )
        assert "Code Execution" in label

    def test_oidc002_impact(self):
        label = self._get_impact_label(
            "GHOST-OIDC-002", gate_type=GateType.OIDC,
            evidence={"workflow": ".github/workflows/x.yml", "job": "y"},
        )
        assert "Cloud" in label

    def test_env001_impact(self):
        label = self._get_impact_label(
            "GHOST-ENV-001", gate_type=GateType.ENVIRONMENT,
            evidence={"environment": "production"},
        )
        assert "Production" in label

    def test_bp004_impact(self):
        label = self._get_impact_label(
            "GHOST-BP-004", evidence={"unprotected_branches": ["staging"]},
        )
        assert "Unprotected" in label


# ── Org graph ────────────────────────────────────────────────────


class TestBuildOrgGraph:
    def test_groups_by_repo(self):
        findings = [
            _finding(rule_id="GHOST-BP-001", repo="acme/api", evidence={"branch": "main"}),
            _finding(rule_id="GHOST-BP-001", repo="acme/web", evidence={"branch": "main"}),
        ]
        og = build_org_graph(findings, org="acme")
        assert len(og.repo_graphs) == 2

    def test_empty_findings(self):
        og = build_org_graph([], org="acme")
        assert len(og.repo_graphs) == 0

    def test_sorted_by_repo(self):
        findings = [
            _finding(rule_id="GHOST-BP-001", repo="acme/zzz", evidence={"branch": "main"}),
            _finding(rule_id="GHOST-BP-001", repo="acme/aaa", evidence={"branch": "main"}),
        ]
        og = build_org_graph(findings, org="acme")
        assert og.repo_graphs[0].repo == "acme/aaa"
        assert og.repo_graphs[1].repo == "acme/zzz"


# ── Mermaid renderer ─────────────────────────────────────────────


class TestMermaidRenderer:
    def _sample_graph(self):
        findings = [
            _finding(rule_id="GHOST-WF-001", repo="acme/api",
                     severity=Severity.CRITICAL, min_privilege=AttackerLevel.EXTERNAL,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/pr_target.yml"}),
            _finding(rule_id="GHOST-BP-001", repo="acme/api",
                     evidence={"branch": "main"}),
        ]
        return build_repo_graph("acme/api", findings)

    def test_starts_with_graph_lr(self):
        mermaid = render_repo_mermaid(self._sample_graph())
        assert mermaid.startswith("graph LR")

    def test_contains_entry_stadium_shape(self):
        mermaid = render_repo_mermaid(self._sample_graph())
        assert "([" in mermaid  # stadium shape

    def test_contains_bypass_hexagon_shape(self):
        mermaid = render_repo_mermaid(self._sample_graph())
        assert '{{' in mermaid  # hexagon shape

    def test_contains_impact_double_circle(self):
        mermaid = render_repo_mermaid(self._sample_graph())
        assert '(((' in mermaid  # double circle

    def test_contains_edges(self):
        mermaid = render_repo_mermaid(self._sample_graph())
        assert " --> " in mermaid

    def test_contains_style_directives(self):
        mermaid = render_repo_mermaid(self._sample_graph())
        assert "style " in mermaid
        assert "fill:" in mermaid

    def test_critical_gets_red_style(self):
        mermaid = render_repo_mermaid(self._sample_graph())
        assert "#dc2626" in mermaid  # critical red

    def test_full_mermaid_doc(self):
        findings = [
            _finding(rule_id="GHOST-WF-001", repo="acme/api",
                     severity=Severity.CRITICAL, min_privilege=AttackerLevel.EXTERNAL,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/pr.yml"}),
        ]
        og = build_org_graph(findings, org="acme")
        md = format_graph_mermaid(og)
        assert "# GhostGates Attack Graph" in md
        assert "```mermaid" in md
        assert "graph LR" in md
        assert "```" in md

    def test_empty_org_graph(self):
        og = build_org_graph([], org="acme")
        md = format_graph_mermaid(og)
        assert "No attack paths" in md


# ── JSON formatter ───────────────────────────────────────────────


class TestJsonFormatter:
    def test_valid_json(self):
        findings = [
            _finding(rule_id="GHOST-BP-001", repo="acme/api",
                     evidence={"branch": "main"}),
        ]
        og = build_org_graph(findings, org="acme")
        parsed = json.loads(format_graph_json(og))
        assert parsed["org"] == "acme"
        assert parsed["repo_count"] == 1
        assert len(parsed["repos"][0]["nodes"]) > 0
        assert len(parsed["repos"][0]["edges"]) > 0

    def test_node_fields(self):
        findings = [
            _finding(rule_id="GHOST-WF-001", repo="acme/api",
                     severity=Severity.CRITICAL, min_privilege=AttackerLevel.EXTERNAL,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/pr.yml"}),
        ]
        og = build_org_graph(findings, org="acme")
        parsed = json.loads(format_graph_json(og))
        nodes = parsed["repos"][0]["nodes"]
        bypass = next(n for n in nodes if n["kind"] == "bypass")
        assert bypass["severity"] == "critical"
        assert bypass["rule_id"] == "GHOST-WF-001"


# ── Terminal formatter ───────────────────────────────────────────


class TestTerminalFormatter:
    def test_shows_header(self):
        findings = [
            _finding(rule_id="GHOST-BP-001", repo="acme/api",
                     evidence={"branch": "main"}),
        ]
        og = build_org_graph(findings, org="acme")
        output = format_graph_terminal(og)
        assert "Kill Chain" in output

    def test_shows_repo(self):
        findings = [
            _finding(rule_id="GHOST-BP-001", repo="acme/api",
                     evidence={"branch": "main"}),
        ]
        og = build_org_graph(findings, org="acme")
        output = format_graph_terminal(og)
        assert "acme/api" in output

    def test_shows_impact_arrow(self):
        findings = [
            _finding(rule_id="GHOST-WF-001", repo="acme/api",
                     severity=Severity.CRITICAL, min_privilege=AttackerLevel.EXTERNAL,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/pr.yml"}),
        ]
        og = build_org_graph(findings, org="acme")
        output = format_graph_terminal(og)
        assert "└─▶" in output

    def test_empty_no_crash(self):
        og = build_org_graph([], org="acme")
        output = format_graph_terminal(og)
        assert "Kill Chain" in output
        assert "No attack paths" in output


# ── Complex scenario ─────────────────────────────────────────────


class TestComplexScenario:
    """Full attack path: external → WF-001 → secrets → OIDC → cloud."""

    def test_multi_finding_chain(self):
        findings = [
            _finding(rule_id="GHOST-WF-001", repo="acme/api",
                     severity=Severity.CRITICAL, min_privilege=AttackerLevel.EXTERNAL,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/pr_target.yml"}),
            _finding(rule_id="GHOST-WF-003", repo="acme/api",
                     severity=Severity.HIGH, min_privilege=AttackerLevel.REPO_WRITE,
                     gate_type=GateType.WORKFLOW,
                     evidence={"workflow": ".github/workflows/deploy.yml",
                               "reusable_workflow": "org/shared/.github/workflows/build.yml@main"}),
            _finding(rule_id="GHOST-OIDC-002", repo="acme/api",
                     severity=Severity.HIGH, min_privilege=AttackerLevel.REPO_WRITE,
                     gate_type=GateType.OIDC,
                     evidence={"workflow": ".github/workflows/deploy.yml", "job": "aws"}),
            _finding(rule_id="GHOST-BP-001", repo="acme/api",
                     severity=Severity.HIGH,
                     evidence={"branch": "main"}),
            _finding(rule_id="GHOST-ENV-001", repo="acme/api",
                     severity=Severity.HIGH, min_privilege=AttackerLevel.REPO_WRITE,
                     gate_type=GateType.ENVIRONMENT,
                     evidence={"environment": "production"}),
        ]

        g = build_repo_graph("acme/api", findings)

        # Should have 2 entry points (external + repo-write)
        entries = [n for n in g.nodes if n.kind == NodeKind.ENTRY]
        assert len(entries) == 2

        # Should have 5 bypass nodes
        bypasses = [n for n in g.nodes if n.kind == NodeKind.BYPASS]
        assert len(bypasses) == 5

        # Should have multiple distinct impacts
        impacts = [n for n in g.nodes if n.kind == NodeKind.IMPACT]
        assert len(impacts) >= 3  # code exec, secrets, cloud, prod, unreviewed

        # All three formats should render without error
        og = build_org_graph(findings, org="acme")
        assert "```mermaid" in format_graph_mermaid(og)
        assert '"acme"' in format_graph_json(og)
        assert "Kill Chain" in format_graph_terminal(og)
