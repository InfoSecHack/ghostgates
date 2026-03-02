"""Tests for ghostgates rank (risk scoring)."""

from __future__ import annotations

import json

from ghostgates.models.enums import (
    AttackerLevel,
    Confidence,
    GateType,
    Severity,
)
from ghostgates.models.findings import BypassFinding
from ghostgates.reporting.rank import (
    RepoRiskScore,
    format_rank_json,
    format_rank_terminal,
    score_repos,
)


def _finding(
    rule_id: str = "GHOST-BP-001",
    repo: str = "org/repo-a",
    severity: Severity = Severity.HIGH,
    min_privilege: AttackerLevel = AttackerLevel.REPO_ADMIN,
    evidence: dict | None = None,
    **kw,
) -> BypassFinding:
    return BypassFinding(
        rule_id=rule_id,
        rule_name="Test",
        repo=repo,
        gate_type=GateType.BRANCH_PROTECTION,
        severity=severity,
        confidence=Confidence.HIGH,
        min_privilege=min_privilege,
        summary="Test summary",
        bypass_path="1. test",
        evidence=evidence or {},
        gating_conditions=[],
        remediation="Fix it",
        **kw,
    )


# ── Scoring logic ────────────────────────────────────────────────


class TestScoreRepos:
    def test_empty_findings(self):
        assert score_repos([]) == []

    def test_single_finding(self):
        scores = score_repos([_finding(severity=Severity.HIGH)])
        assert len(scores) == 1
        assert scores[0].score == 20  # HIGH = 20
        assert scores[0].high == 1
        assert scores[0].tier == "MEDIUM"  # 20 >= 15

    def test_critical_finding_score(self):
        scores = score_repos([_finding(severity=Severity.CRITICAL)])
        assert scores[0].score == 50
        assert scores[0].tier == "HIGH"  # 50 >= 40 but < 75

    def test_external_bonus(self):
        scores = score_repos([
            _finding(
                severity=Severity.CRITICAL,
                min_privilege=AttackerLevel.EXTERNAL,
            ),
        ])
        # 50 (critical) + 25 (external bonus) = 75
        assert scores[0].score == 75
        assert scores[0].has_external_path is True
        assert scores[0].tier == "CRITICAL"

    def test_oidc_bonus(self):
        scores = score_repos([
            _finding(rule_id="GHOST-OIDC-001", severity=Severity.HIGH),
        ])
        # 20 (high) + 15 (OIDC bonus) = 35
        assert scores[0].score == 35
        assert scores[0].has_oidc_finding is True

    def test_prod_env_bonus(self):
        scores = score_repos([
            _finding(
                severity=Severity.HIGH,
                evidence={"environment": "production"},
            ),
        ])
        # 20 (high) + 10 (prod bonus) = 30
        assert scores[0].score == 30
        assert scores[0].has_prod_env is True

    def test_all_bonuses_stack(self):
        scores = score_repos([
            _finding(
                rule_id="GHOST-OIDC-002",
                severity=Severity.CRITICAL,
                min_privilege=AttackerLevel.EXTERNAL,
                evidence={"environment": "production"},
            ),
        ])
        # 50 + 25 + 15 + 10 = 100
        assert scores[0].score == 100
        assert scores[0].tier == "CRITICAL"

    def test_multiple_repos_sorted_descending(self):
        findings = [
            _finding(repo="org/low", severity=Severity.LOW),
            _finding(repo="org/high", severity=Severity.CRITICAL),
            _finding(repo="org/med", severity=Severity.MEDIUM),
        ]
        scores = score_repos(findings)
        assert [s.repo for s in scores] == ["org/high", "org/med", "org/low"]

    def test_multiple_findings_same_repo(self):
        findings = [
            _finding(repo="org/repo", severity=Severity.HIGH),
            _finding(repo="org/repo", severity=Severity.MEDIUM),
            _finding(repo="org/repo", severity=Severity.LOW),
        ]
        scores = score_repos(findings)
        assert len(scores) == 1
        # 20 + 7 + 2 = 29
        assert scores[0].score == 29
        assert scores[0].high == 1
        assert scores[0].medium == 1
        assert scores[0].low == 1

    def test_finding_summary_format(self):
        findings = [
            _finding(repo="org/r", severity=Severity.CRITICAL),
            _finding(repo="org/r", severity=Severity.HIGH),
            _finding(repo="org/r", severity=Severity.HIGH),
            _finding(repo="org/r", severity=Severity.MEDIUM),
        ]
        scores = score_repos(findings)
        assert scores[0].finding_summary == "1C 2H 1M"

    def test_top_finding_is_highest_severity(self):
        findings = [
            _finding(repo="org/r", rule_id="GHOST-BP-003", severity=Severity.LOW),
            _finding(repo="org/r", rule_id="GHOST-WF-001", severity=Severity.CRITICAL),
            _finding(repo="org/r", rule_id="GHOST-BP-001", severity=Severity.HIGH),
        ]
        scores = score_repos(findings)
        assert scores[0].top_finding == "GHOST-WF-001"


# ── Tier thresholds ──────────────────────────────────────────────


class TestTierThresholds:
    def test_critical_tier(self):
        s = RepoRiskScore(
            repo="x", score=75, critical=0, high=0, medium=0, low=0, info=0,
            has_external_path=False, has_oidc_finding=False, has_prod_env=False,
        )
        assert s.tier == "CRITICAL"

    def test_high_tier(self):
        s = RepoRiskScore(
            repo="x", score=40, critical=0, high=0, medium=0, low=0, info=0,
            has_external_path=False, has_oidc_finding=False, has_prod_env=False,
        )
        assert s.tier == "HIGH"

    def test_medium_tier(self):
        s = RepoRiskScore(
            repo="x", score=15, critical=0, high=0, medium=0, low=0, info=0,
            has_external_path=False, has_oidc_finding=False, has_prod_env=False,
        )
        assert s.tier == "MEDIUM"

    def test_low_tier(self):
        s = RepoRiskScore(
            repo="x", score=14, critical=0, high=0, medium=0, low=0, info=0,
            has_external_path=False, has_oidc_finding=False, has_prod_env=False,
        )
        assert s.tier == "LOW"


# ── Terminal formatter ───────────────────────────────────────────


class TestRankTerminalFormatter:
    def test_empty_scores(self):
        output = format_rank_terminal([], "test-org")
        assert "No findings to rank" in output

    def test_shows_repo_and_score(self):
        scores = score_repos([
            _finding(repo="org/payments", severity=Severity.CRITICAL),
        ])
        output = format_rank_terminal(scores, "org")
        assert "payments" in output
        assert "Risk Ranking" in output

    def test_shows_flags(self):
        scores = score_repos([
            _finding(
                repo="org/api",
                rule_id="GHOST-OIDC-001",
                severity=Severity.HIGH,
                min_privilege=AttackerLevel.EXTERNAL,
            ),
        ])
        output = format_rank_terminal(scores, "org")
        assert "external" in output
        assert "OIDC" in output

    def test_top_n_limits_output(self):
        findings = [
            _finding(repo=f"org/repo-{i}", severity=Severity.MEDIUM)
            for i in range(10)
        ]
        scores = score_repos(findings)
        output = format_rank_terminal(scores, "org", top_n=3)
        assert "7 more" in output

    def test_summary_line(self):
        scores = score_repos([
            _finding(repo="org/a", severity=Severity.CRITICAL,
                     min_privilege=AttackerLevel.EXTERNAL),
        ])
        output = format_rank_terminal(scores, "org")
        assert "Total risk" in output


# ── JSON formatter ───────────────────────────────────────────────


class TestRankJsonFormatter:
    def test_valid_json(self):
        scores = score_repos([
            _finding(repo="org/api", severity=Severity.HIGH),
            _finding(repo="org/web", severity=Severity.MEDIUM),
        ])
        output = format_rank_json(scores, "org")
        parsed = json.loads(output)
        assert parsed["repos_ranked"] == 2
        assert parsed["rankings"][0]["rank"] == 1
        assert parsed["rankings"][0]["score"] > parsed["rankings"][1]["score"]

    def test_includes_flags(self):
        scores = score_repos([
            _finding(
                repo="org/api",
                rule_id="GHOST-OIDC-001",
                severity=Severity.HIGH,
                min_privilege=AttackerLevel.EXTERNAL,
            ),
        ])
        parsed = json.loads(format_rank_json(scores, "org"))
        r = parsed["rankings"][0]
        assert r["has_external_path"] is True
        assert r["has_oidc_finding"] is True

    def test_total_risk_score(self):
        scores = score_repos([
            _finding(repo="org/a", severity=Severity.HIGH),
            _finding(repo="org/b", severity=Severity.MEDIUM),
        ])
        parsed = json.loads(format_rank_json(scores, "org"))
        assert parsed["total_risk_score"] == 20 + 7
