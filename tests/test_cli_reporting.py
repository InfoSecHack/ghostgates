"""
Tests for ghostgates.cli and ghostgates.reporting.formatter

Tests the output formatters (terminal, JSON, markdown) and CLI
commands (list-rules, offline, show) without live API calls.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghostgates.models.enums import AttackerLevel, Confidence, GateType, Severity
from ghostgates.models.findings import BypassFinding, ScanResult
from ghostgates.reporting.formatter import (
    format_terminal,
    format_json,
    format_markdown,
)
from ghostgates.storage import SQLiteStore


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

def _make_finding(
    rule_id: str = "GHOST-BP-001",
    severity: Severity = Severity.HIGH,
    repo: str = "org/repo",
) -> BypassFinding:
    return BypassFinding(
        rule_id=rule_id,
        rule_name="Test Rule",
        repo=repo,
        gate_type=GateType.BRANCH_PROTECTION,
        severity=severity,
        confidence=Confidence.HIGH,
        min_privilege=AttackerLevel.REPO_ADMIN,
        summary="Test summary for the finding.",
        bypass_path="1. Step one\n2. Step two\n3. Step three",
        evidence={"branch": "main", "enforce_admins": False},
        gating_conditions=["Attacker must have admin access"],
        remediation="Enable enforce_admins on branch protection.",
    )


def _make_result(n_findings: int = 3) -> ScanResult:
    findings = []
    sevs = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
    for i in range(n_findings):
        findings.append(_make_finding(
            rule_id=f"GHOST-TEST-{i:03d}",
            severity=sevs[i % len(sevs)],
            repo=f"org/repo-{i % 2}",
        ))
    return ScanResult(
        org="test-org",
        repos_scanned=5,
        findings=findings,
        attacker_level=AttackerLevel.ORG_OWNER,
        collected_at=datetime.now(timezone.utc).isoformat(),
    )


# ==================================================================
# Tests: Terminal formatter
# ==================================================================

class TestTerminalFormatter:
    def test_basic_output(self):
        result = _make_result(2)
        output = format_terminal(result)
        assert "GhostGates Scan Results" in output
        assert "test-org" in output
        assert "GHOST-TEST-000" in output
        assert "GHOST-TEST-001" in output

    def test_empty_findings(self):
        result = ScanResult(
            org="clean-org", repos_scanned=10, findings=[],
            attacker_level=AttackerLevel.ORG_OWNER,
        )
        output = format_terminal(result)
        assert "No bypass findings" in output

    def test_verbose_mode(self):
        result = _make_result(1)
        output = format_terminal(result, verbose=True)
        assert "Bypass path:" in output
        assert "Step one" in output
        assert "Remediation:" in output
        assert "Min privilege:" in output

    def test_severity_counts(self):
        result = _make_result(3)
        output = format_terminal(result)
        assert "3" in output  # total count

    def test_repos_grouped(self):
        result = _make_result(4)
        output = format_terminal(result)
        assert "org/repo-0" in output
        assert "org/repo-1" in output


# ==================================================================
# Tests: JSON formatter
# ==================================================================

class TestJsonFormatter:
    def test_valid_json(self):
        result = _make_result(2)
        output = format_json(result)
        parsed = json.loads(output)
        assert parsed["org"] == "test-org"
        assert len(parsed["findings"]) == 2

    def test_round_trip(self):
        """JSON can be parsed back to a ScanResult."""
        result = _make_result(3)
        output = format_json(result)
        restored = ScanResult.model_validate_json(output)
        assert restored.org == result.org
        assert len(restored.findings) == len(result.findings)

    def test_empty_findings_json(self):
        result = ScanResult(
            org="clean", repos_scanned=5, findings=[],
            attacker_level=AttackerLevel.ORG_OWNER,
        )
        output = format_json(result)
        parsed = json.loads(output)
        assert parsed["findings"] == []


# ==================================================================
# Tests: Markdown formatter
# ==================================================================

class TestMarkdownFormatter:
    def test_basic_structure(self):
        result = _make_result(2)
        output = format_markdown(result)
        assert "# GhostGates Scan Report" in output
        assert "## Summary" in output
        assert "## Findings" in output
        assert "| Severity | Count |" in output

    def test_findings_include_bypass_path(self):
        result = _make_result(1)
        output = format_markdown(result)
        assert "**Bypass path:**" in output
        assert "Step one" in output

    def test_evidence_in_details(self):
        result = _make_result(1)
        output = format_markdown(result)
        assert "<details>" in output
        assert "Evidence" in output

    def test_empty_findings_markdown(self):
        result = ScanResult(
            org="clean", repos_scanned=5, findings=[],
            attacker_level=AttackerLevel.ORG_OWNER,
        )
        output = format_markdown(result)
        assert "No bypass findings" in output

    def test_severity_emojis(self):
        result = _make_result(3)
        output = format_markdown(result)
        assert "🔴" in output  # CRITICAL
        assert "🟠" in output  # HIGH
        assert "🟡" in output  # MEDIUM


# ==================================================================
# Tests: CLI commands (subprocess)
# ==================================================================

class TestCLI:
    def test_help(self):
        r = subprocess.run(
            [sys.executable, "-m", "ghostgates.cli", "--help"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "scan" in r.stdout
        assert "list-rules" in r.stdout

    def test_list_rules(self):
        r = subprocess.run(
            [sys.executable, "-m", "ghostgates.cli", "list-rules"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "GHOST-BP-001" in r.stdout
        assert "GHOST-WF-001" in r.stdout

    def test_list_rules_json(self):
        r = subprocess.run(
            [sys.executable, "-m", "ghostgates.cli", "list-rules", "--format", "json"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert len(data) >= 15
        ids = {d["rule_id"] for d in data}
        assert "GHOST-BP-001" in ids

    def test_scan_requires_token(self):
        """Scan without token fails gracefully."""
        import os
        env = os.environ.copy()
        env.pop("GITHUB_TOKEN", None)
        r = subprocess.run(
            [sys.executable, "-m", "ghostgates.cli", "scan", "--org", "fake-org", "--token", ""],
            capture_output=True, text=True, env=env,
        )
        assert r.returncode == 1
        assert "token" in r.stderr.lower()


# ==================================================================
# Tests: Offline scan (integration with storage)
# ==================================================================

class TestOfflineScan:
    def test_offline_with_stored_models(self, tmp_path):
        """Store gate models, then run offline analysis."""
        from tests.mocks.gate_models import make_gate, make_bp

        db_path = tmp_path / "test.db"
        store = SQLiteStore(db_path)

        gate = make_gate(
            org="offline-org",
            repo="web-app",
            branch_protections=[make_bp("main", reviews=2, enforce_admins=False)],
        )
        store.upsert_gate_model(gate)
        store.close()

        r = subprocess.run(
            [sys.executable, "-m", "ghostgates.cli", "offline",
             "--org", "offline-org", "--db", str(db_path),
             "--format", "json"],
            capture_output=True, text=True,
        )
        assert r.returncode in (0, 1, 2)  # depends on finding severity
        data = json.loads(r.stdout)
        assert data["org"] == "offline-org"
        assert len(data["findings"]) > 0

        # Verify BP-001 was detected
        rule_ids = {f["rule_id"] for f in data["findings"]}
        assert "GHOST-BP-001" in rule_ids

    def test_offline_no_stored_models(self, tmp_path):
        """Offline scan with empty DB returns error."""
        db_path = tmp_path / "empty.db"
        r = subprocess.run(
            [sys.executable, "-m", "ghostgates.cli", "offline",
             "--org", "nobody", "--db", str(db_path)],
            capture_output=True, text=True,
        )
        assert r.returncode == 1
        assert "No stored gate models" in r.stderr


# ==================================================================
# Tests: Show command
# ==================================================================

class TestShowCommand:
    def test_show_latest(self, tmp_path):
        """Show the latest scan result."""
        db_path = tmp_path / "test.db"
        store = SQLiteStore(db_path)
        result = _make_result(2)
        store.save_scan_result(result)
        store.close()

        r = subprocess.run(
            [sys.executable, "-m", "ghostgates.cli", "show",
             "--org", "test-org", "--db", str(db_path),
             "--format", "json"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert data["org"] == "test-org"

    def test_show_no_results(self, tmp_path):
        db_path = tmp_path / "empty.db"
        r = subprocess.run(
            [sys.executable, "-m", "ghostgates.cli", "show",
             "--org", "nobody", "--db", str(db_path)],
            capture_output=True, text=True,
        )
        assert r.returncode == 1


# ==================================================================
# Tests: Exit codes
# ==================================================================

class TestExitCodes:
    def test_exit_0_clean(self, tmp_path):
        """No findings → exit 0."""
        from tests.mocks.gate_models import make_gate
        db_path = tmp_path / "test.db"
        store = SQLiteStore(db_path)
        gate = make_gate(org="clean-org", repo="safe-repo")
        store.upsert_gate_model(gate)
        store.close()

        r = subprocess.run(
            [sys.executable, "-m", "ghostgates.cli", "offline",
             "--org", "clean-org", "--db", str(db_path)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_exit_2_critical(self, tmp_path):
        """Critical findings → exit 2."""
        from tests.mocks.gate_models import make_gate, make_bp, make_workflow, make_trigger, make_job, make_step
        db_path = tmp_path / "test.db"
        store = SQLiteStore(db_path)
        gate = make_gate(
            org="vuln-org",
            repo="vuln-repo",
            workflows=[
                make_workflow(
                    triggers=[make_trigger("pull_request_target")],
                    jobs=[make_job(steps=[
                        make_step(
                            uses="actions/checkout@v4",
                            with_={"ref": "${{ github.event.pull_request.head.sha }}"},
                        ),
                        make_step(run="npm install"),
                    ])],
                ),
            ],
        )
        store.upsert_gate_model(gate)
        store.close()

        r = subprocess.run(
            [sys.executable, "-m", "ghostgates.cli", "offline",
             "--org", "vuln-org", "--db", str(db_path)],
            capture_output=True, text=True,
        )
        assert r.returncode == 2  # critical finding
