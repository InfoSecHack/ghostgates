"""Tests for ghostgates diff (drift detection)."""

from __future__ import annotations

import json

from ghostgates.models.enums import (
    AttackerLevel,
    Confidence,
    GateType,
    Severity,
)
from ghostgates.models.findings import BypassFinding, ScanResult, ScanScope
from ghostgates.reporting.diff import (
    ScanDiff,
    diff_scans,
    format_diff_json,
    format_diff_markdown,
    format_diff_terminal,
)


def _finding(rule_id: str = "GHOST-BP-001", instance: str = "main", **kw) -> BypassFinding:
    defaults = dict(
        rule_id=rule_id,
        rule_name="Test rule",
        repo="org/repo",
        gate_type=GateType.BRANCH_PROTECTION,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        min_privilege=AttackerLevel.REPO_ADMIN,
        summary="Test summary",
        bypass_path="1. step one",
        evidence={"branch": instance},
        gating_conditions=["condition"],
        remediation="Fix it",
        instance=instance,
    )
    defaults.update(kw)
    return BypassFinding(**defaults)


def _scan(
    findings: list[BypassFinding],
    org: str = "test-org",
    errors: list | None = None,
    scope: ScanScope | None = None,
) -> ScanResult:
    if scope is None:
        repositories = sorted({finding.repo for finding in findings}) or ["org/repo"]
        scope = ScanScope(
            discovered_repositories=repositories,
            selected_repositories=repositories,
            evaluated_repositories=repositories,
            enumeration_complete=True,
        )
    return ScanResult(
        org=org,
        repos_scanned=len(scope.evaluated_repositories),
        repos_skipped=0,
        findings=findings,
        errors=errors or [],
        scope=scope,
        scan_duration_seconds=0.1,
        attacker_level="org-owner",
        collected_at="2026-03-01T00:00:00Z",
    )


# ── Core diff logic ──────────────────────────────────────────────


class TestDiffScans:
    def test_identical_scans_no_changes(self):
        f = _finding()
        d = diff_scans(_scan([f]), _scan([f]))
        assert len(d.new_findings) == 0
        assert len(d.resolved_findings) == 0
        assert len(d.unchanged_findings) == 1
        assert not d.has_changes

    def test_new_finding_detected(self):
        old = _scan([_finding("GHOST-BP-001")])
        new = _scan([_finding("GHOST-BP-001"), _finding("GHOST-BP-002", instance="main")])
        d = diff_scans(old, new)
        assert len(d.new_findings) == 1
        assert d.new_findings[0].rule_id == "GHOST-BP-002"
        assert d.has_changes

    def test_resolved_finding_detected(self):
        old = _scan([_finding("GHOST-BP-001"), _finding("GHOST-BP-002", instance="main")])
        new = _scan([_finding("GHOST-BP-001")])
        d = diff_scans(old, new)
        assert len(d.resolved_findings) == 1
        assert d.resolved_findings[0].rule_id == "GHOST-BP-002"
        assert d.has_changes

    def test_mixed_changes(self):
        old = _scan([
            _finding("GHOST-BP-001"),
            _finding("GHOST-BP-002", instance="main"),
        ])
        new = _scan([
            _finding("GHOST-BP-001"),
            _finding("GHOST-WF-001", instance="ci.yml#build"),
        ])
        d = diff_scans(old, new)
        assert len(d.new_findings) == 1
        assert len(d.resolved_findings) == 1
        assert len(d.unchanged_findings) == 1

    def test_empty_to_findings(self):
        d = diff_scans(_scan([]), _scan([_finding()]))
        assert len(d.new_findings) == 1
        assert len(d.resolved_findings) == 0

    def test_findings_to_empty(self):
        d = diff_scans(_scan([_finding()]), _scan([]))
        assert len(d.new_findings) == 0
        assert len(d.resolved_findings) == 1

    def test_instance_key_differentiates(self):
        """Same rule_id but different instances are different findings."""
        old = _scan([_finding("GHOST-OIDC-002", instance="a.yml#job1")])
        new = _scan([
            _finding("GHOST-OIDC-002", instance="a.yml#job1"),
            _finding("GHOST-OIDC-002", instance="b.yml#job2"),
        ])
        d = diff_scans(old, new)
        assert len(d.new_findings) == 1
        assert d.new_findings[0].instance == "b.yml#job2"
        assert len(d.unchanged_findings) == 1

    def test_finding_from_removed_rule_is_unverified_not_resolved(self):
        old = _scan([_finding("GHOST-BP-004")])
        new = _scan([])

        d = diff_scans(old, new, evaluated_rule_ids={"GHOST-BP-001"})

        assert d.resolved_findings == []
        assert [f.rule_id for f in d.unverified_findings] == ["GHOST-BP-004"]
        parsed = json.loads(format_diff_json(d))
        assert parsed["summary"]["unverified"] == 1

    def test_missing_finding_in_incomplete_scan_is_unverified(self):
        old = _scan([_finding("GHOST-BP-001")])
        new = _scan([], errors=["org/repo: 403 Forbidden"])

        d = diff_scans(old, new)

        assert d.resolved_findings == []
        assert [f.rule_id for f in d.unverified_findings] == ["GHOST-BP-001"]

    def test_missing_repo_variants_are_unverified(self):
        old = _scan([_finding()])
        scopes = [
            ScanScope(
                discovered_repositories=["org/repo"],
                selected_repositories=[],
                evaluated_repositories=[],
                enumeration_complete=True,
            ),
            ScanScope(
                discovered_repositories=["org/renamed"],
                selected_repositories=["org/renamed"],
                evaluated_repositories=["org/renamed"],
                enumeration_complete=True,
            ),
            ScanScope(
                discovered_repositories=["org/repo"],
                selected_repositories=["org/repo"],
                evaluated_repositories=[],
                enumeration_complete=True,
            ),
        ]

        for scope in scopes:
            diff = diff_scans(old, _scan([], scope=scope))
            assert diff.resolved_findings == []
            assert diff.unverified_findings == old.findings

    def test_material_inference_change_is_reported(self):
        old = _scan([_finding()])
        new = _scan([_finding(
            confidence=Confidence.MEDIUM,
            min_privilege=AttackerLevel.REPO_WRITE,
            evidence={"branch": "main", "enforce_admins": False},
        )])

        diff = diff_scans(old, new)

        assert len(diff.changed_findings) == 1
        summary = format_diff_terminal(diff)
        assert "confidence HIGH → MEDIUM" in summary
        assert "attacker prerequisite REPO-ADMIN → REPO-WRITE" in summary
        assert "evidence changed" in summary

    def test_ruleset_display_name_change_is_unchanged(self):
        old = _scan([_finding(
            instance="42",
            evidence={"ruleset_id": 42, "ruleset_name": "old"},
        )])
        new = _scan([_finding(
            instance="42",
            evidence={"ruleset_id": 42, "ruleset_name": "renamed"},
        )])

        diff = diff_scans(old, new)

        assert len(diff.unchanged_findings) == 1
        assert diff.changed_findings == []

    def test_severity_change_is_reported_as_changed(self):
        old = _scan([_finding(severity=Severity.HIGH)])
        new = _scan([_finding(severity=Severity.MEDIUM)])

        d = diff_scans(old, new)

        assert d.unchanged_findings == []
        assert len(d.changed_findings) == 1
        assert d.changed_findings[0].old.severity == Severity.HIGH
        assert d.changed_findings[0].new.severity == Severity.MEDIUM
        assert "HIGH → MEDIUM" in format_diff_terminal(d)

    def test_both_empty(self):
        d = diff_scans(_scan([]), _scan([]))
        assert not d.has_changes


# ── Terminal formatter ───────────────────────────────────────────


class TestDiffTerminalFormatter:
    def test_no_changes_message(self):
        d = diff_scans(_scan([_finding()]), _scan([_finding()]))
        output = format_diff_terminal(d)
        assert "No changes" in output

    def test_new_findings_shown(self):
        d = diff_scans(_scan([]), _scan([_finding("GHOST-BP-001")]))
        output = format_diff_terminal(d)
        assert "New Findings" in output
        assert "GHOST-BP-001" in output
        assert "+1 new" in output

    def test_resolved_findings_shown(self):
        d = diff_scans(_scan([_finding("GHOST-BP-001")]), _scan([]))
        output = format_diff_terminal(d)
        assert "Resolved" in output
        assert "GHOST-BP-001" in output
        assert "-1 resolved" in output

    def test_instance_shown(self):
        f = _finding("GHOST-OIDC-002", instance="oidc.yml#deploy")
        d = diff_scans(_scan([]), _scan([f]))
        output = format_diff_terminal(d)
        assert "oidc.yml#deploy" in output


# ── JSON formatter ───────────────────────────────────────────────


class TestDiffJsonFormatter:
    def test_valid_json(self):
        d = diff_scans(
            _scan([_finding("GHOST-BP-001")]),
            _scan([_finding("GHOST-BP-001"), _finding("GHOST-WF-001", instance="ci.yml#build")]),
        )
        output = format_diff_json(d)
        parsed = json.loads(output)
        assert parsed["summary"]["new"] == 1
        assert parsed["summary"]["resolved"] == 0
        assert parsed["summary"]["unchanged"] == 1
        assert len(parsed["new_findings"]) == 1
        assert parsed["new_findings"][0]["rule_id"] == "GHOST-WF-001"

    def test_empty_diff_json(self):
        d = diff_scans(_scan([_finding()]), _scan([_finding()]))
        parsed = json.loads(format_diff_json(d))
        assert parsed["summary"]["new"] == 0
        assert parsed["summary"]["resolved"] == 0


# ── Markdown formatter ───────────────────────────────────────────


class TestDiffMarkdownFormatter:
    def test_has_table(self):
        d = diff_scans(_scan([]), _scan([_finding()]))
        output = format_diff_markdown(d)
        assert "New findings" in output
        assert "Resolved" in output

    def test_new_section(self):
        d = diff_scans(_scan([]), _scan([_finding("GHOST-BP-001")]))
        output = format_diff_markdown(d)
        assert "## 🆕 New Findings" in output
        assert "GHOST-BP-001" in output

    def test_resolved_section(self):
        d = diff_scans(_scan([_finding("GHOST-BP-001")]), _scan([]))
        output = format_diff_markdown(d)
        assert "## ✅ Resolved" in output

    def test_no_changes_message(self):
        d = diff_scans(_scan([_finding()]), _scan([_finding()]))
        output = format_diff_markdown(d)
        assert "No changes" in output
