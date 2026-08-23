"""Tests for SARIF 2.1.0 output format."""

from __future__ import annotations

import json
from pathlib import Path

from ruamel.yaml import YAML

from ghostgates.models.enums import (
    AttackerLevel,
    Confidence,
    GateType,
    Severity,
)
from ghostgates.models.findings import BypassFinding, ScanResult, ScanScope
from ghostgates.reporting.sarif import format_sarif


def _finding(
    rule_id: str = "GHOST-BP-001",
    severity: Severity = Severity.HIGH,
    evidence: dict | None = None,
    settings_url: str = "https://github.com/org/repo/settings/branches",
    **kw,
) -> BypassFinding:
    defaults = dict(
        rule_id=rule_id,
        rule_name="Test rule",
        repo="org/repo",
        gate_type=GateType.BRANCH_PROTECTION,
        severity=severity,
        confidence=Confidence.HIGH,
        min_privilege=AttackerLevel.REPO_ADMIN,
        summary="Test summary",
        bypass_path="1. step one\n2. step two",
        evidence=evidence or {"branch": "main"},
        gating_conditions=["condition one"],
        remediation="Fix it\n→ https://github.com/org/repo/settings/branches",
        instance="main",
        settings_url=settings_url,
        references=["https://docs.github.com/example"],
    )
    defaults.update(kw)
    return BypassFinding(**defaults)


def _scan(findings: list[BypassFinding], errors: list[str] | None = None) -> ScanResult:
    return ScanResult(
        org="test-org",
        repos_scanned=1,
        repos_skipped=0,
        findings=findings,
        errors=errors or [],
        scope=ScanScope(
            discovered_repositories=["org/repo"],
            selected_repositories=["org/repo"],
            evaluated_repositories=["org/repo"],
            enumeration_complete=True,
        ),
        scan_duration_seconds=0.5,
        attacker_level="org-owner",
        collected_at="2026-03-01T00:00:00Z",
    )


class TestSarifSchema:
    """Verify SARIF 2.1.0 structural compliance."""

    def test_valid_json(self):
        output = format_sarif(_scan([_finding()]))
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_schema_and_version(self):
        parsed = json.loads(format_sarif(_scan([_finding()])))
        assert parsed["version"] == "2.1.0"
        assert "$schema" in parsed

    def test_has_runs(self):
        parsed = json.loads(format_sarif(_scan([_finding()])))
        assert len(parsed["runs"]) == 1

    def test_tool_info(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        driver = run["tool"]["driver"]
        assert driver["name"] == "GhostGates"
        assert "informationUri" in driver
        assert "version" in driver

    def test_automation_details(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        assert "automationDetails" in run
        assert "test-org" in run["automationDetails"]["id"]


class TestSarifRules:
    """Verify SARIF rule (reportingDescriptor) generation."""

    def test_rule_count_matches_unique_rule_ids(self):
        findings = [
            _finding(rule_id="GHOST-BP-001"),
            _finding(rule_id="GHOST-BP-001", instance="develop"),
            _finding(rule_id="GHOST-WF-001", severity=Severity.CRITICAL,
                     evidence={"workflow": ".github/workflows/ci.yml"}),
        ]
        run = json.loads(format_sarif(_scan(findings)))["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 2  # deduplicated

    def test_rule_has_required_fields(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["id"] == "GHOST-BP-001"
        assert "shortDescription" in rule
        assert "fullDescription" in rule
        assert "help" in rule
        assert "defaultConfiguration" in rule

    def test_rule_severity_mapping(self):
        run = json.loads(format_sarif(_scan([
            _finding(severity=Severity.CRITICAL),
        ])))["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_security_severity_maps_qualitative_categories(self):
        cases = [
            (Severity.CRITICAL, "9.1"),
            (Severity.HIGH, "7.0"),
            (Severity.MEDIUM, "4.0"),
            (Severity.LOW, "0.1"),
            (Severity.INFO, "0.0"),
        ]
        for severity, expected in cases:
            run = json.loads(format_sarif(_scan([
                _finding(severity=severity),
            ])))["runs"][0]
            properties = run["tool"]["driver"]["rules"][0]["properties"]
            assert properties["security-severity"] == expected
            assert properties["ghostgates/severity-mapping"] == "qualitative-category"

    def test_rule_has_help_uri(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["helpUri"] == "https://docs.github.com/example"

    def test_rule_tags(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        assert "security" in rule["properties"]["tags"]
        assert "cicd" in rule["properties"]["tags"]


class TestSarifResults:
    """Verify SARIF result generation."""

    def test_result_count_matches_findings(self):
        findings = [
            _finding(rule_id="GHOST-BP-001"),
            _finding(rule_id="GHOST-BP-001", instance="develop"),
            _finding(rule_id="GHOST-WF-001"),
        ]
        run = json.loads(format_sarif(_scan(findings)))["runs"][0]
        assert len(run["results"]) == 3

    def test_result_has_rule_reference(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        result = run["results"][0]
        assert result["ruleId"] == "GHOST-BP-001"
        assert result["ruleIndex"] == 0

    def test_result_level_mapping(self):
        cases = [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ]
        for sev, expected_level in cases:
            run = json.loads(format_sarif(_scan([_finding(severity=sev)])))["runs"][0]
            assert run["results"][0]["level"] == expected_level, f"Failed for {sev}"

    def test_result_message_includes_bypass_path(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        msg = run["results"][0]["message"]["text"]
        assert "step one" in msg
        assert "step two" in msg

    def test_result_has_fingerprint(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        fp = run["results"][0]["fingerprints"]
        assert "ghostgates/v1" in fp
        assert "GHOST-BP-001|org/repo|main" == fp["ghostgates/v1"]

    def test_result_properties_include_privilege(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        props = run["results"][0]["properties"]
        assert props["min_privilege"] == "repo-admin"
        assert props["gate_type"] == "branch_protection"

    def test_result_has_settings_url(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        props = run["results"][0]["properties"]
        assert "settings_url" in props
        assert "github.com" in props["settings_url"]
        assert "fixes" not in run["results"][0]


class TestSarifLocations:
    """Verify SARIF location mapping."""

    def test_workflow_finding_has_file_location(self):
        f = _finding(
            rule_id="GHOST-WF-001",
            evidence={"workflow": ".github/workflows/ci.yml", "job": "build"},
        )
        run = json.loads(format_sarif(_scan([f])))["runs"][0]
        loc = run["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == ".github/workflows/ci.yml"

    def test_branch_finding_uses_dotgithub(self):
        f = _finding(evidence={"branch": "main", "enforce_admins": False})
        run = json.loads(format_sarif(_scan([f])))["runs"][0]
        loc = run["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == ".github"

    def test_location_has_region(self):
        """GitHub Code Scanning requires a region."""
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        loc = run["results"][0]["locations"][0]
        assert "region" in loc["physicalLocation"]
        assert loc["physicalLocation"]["region"]["startLine"] == 1

    def test_logical_location_has_repo(self):
        run = json.loads(format_sarif(_scan([_finding()])))["runs"][0]
        loc = run["results"][0]["locations"][0]
        logical = loc["logicalLocations"][0]
        assert logical["name"] == "org/repo"
        assert logical["kind"] == "repository"


class TestSarifEdgeCases:
    """Edge cases and empty inputs."""

    def test_empty_findings(self):
        parsed = json.loads(format_sarif(_scan([])))
        run = parsed["runs"][0]
        assert len(run["results"]) == 0
        assert len(run["tool"]["driver"]["rules"]) == 0

    def test_finding_without_settings_url(self):
        f = _finding(settings_url="")
        run = json.loads(format_sarif(_scan([f])))["runs"][0]
        result = run["results"][0]
        assert "settings_url" not in result.get("properties", {})

    def test_finding_without_references(self):
        f = _finding(references=[])
        run = json.loads(format_sarif(_scan([f])))["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        assert "helpUri" not in rule

    def test_duplicate_rule_ids_share_rule_index(self):
        findings = [
            _finding(rule_id="GHOST-BP-001", instance="main"),
            _finding(rule_id="GHOST-BP-001", instance="develop"),
        ]
        run = json.loads(format_sarif(_scan(findings)))["runs"][0]
        assert run["results"][0]["ruleIndex"] == 0
        assert run["results"][1]["ruleIndex"] == 0
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_ruleset_ids_produce_stable_fingerprints(self):
        findings = [
            _finding(
                rule_id="GHOST-BP-006",
                evidence={"ruleset_id": ruleset_id, "ruleset_name": "same"},
                instance="",
            )
            for ruleset_id in (101, 202)
        ]
        run = json.loads(format_sarif(_scan(findings)))["runs"][0]

        fingerprints = {
            result["fingerprints"]["ghostgates/v1"] for result in run["results"]
        }
        assert len(fingerprints) == 2

        renamed = findings[0].model_copy(update={
            "evidence": {"ruleset_id": 101, "ruleset_name": "renamed"},
        })
        renamed.instance = ""
        renamed.model_post_init(None)
        renamed_run = json.loads(format_sarif(_scan([renamed])))["runs"][0]
        assert (
            renamed_run["results"][0]["fingerprints"]["ghostgates/v1"]
            == run["results"][0]["fingerprints"]["ghostgates/v1"]
        )

    def test_partial_collection_marks_run_incomplete(self):
        run = json.loads(format_sarif(_scan(
            [_finding()],
            errors=["org/hidden: 403 Forbidden"],
        )))["runs"][0]
        assert run["invocations"][0]["executionSuccessful"] is False
        assert run["properties"]["ghostgates/complete"] is False
        assert run["properties"]["ghostgates/collectionErrors"]

    def test_zero_repo_scope_controls_completeness(self):
        known_empty = ScanResult(
            org="empty-org",
            repos_scanned=0,
            scope=ScanScope(enumeration_complete=True),
            attacker_level=AttackerLevel.ORG_OWNER,
        )
        collapsed = ScanResult(
            org="test-org",
            repos_scanned=0,
            scope=ScanScope(
                requested_repositories=["test-org/missing"],
                discovered_repositories=["test-org/missing"],
                enumeration_complete=True,
            ),
            attacker_level=AttackerLevel.ORG_OWNER,
        )

        known_run = json.loads(format_sarif(known_empty))["runs"][0]
        collapsed_run = json.loads(format_sarif(collapsed))["runs"][0]

        assert known_run["properties"]["ghostgates/complete"] is True
        assert collapsed_run["properties"]["ghostgates/complete"] is False

    def test_example_workflow_withholds_incomplete_sarif(self):
        workflow_path = (
            Path(__file__).parents[1]
            / ".github"
            / "workflows"
            / "ghostgates-scan.yml"
        )
        workflow = YAML(typ="safe").load(workflow_path.read_text(encoding="utf-8"))
        steps = workflow["jobs"]["ghostgates-scan"]["steps"]
        upload = next(step for step in steps if step["name"] == "Upload SARIF to GitHub Security")

        assert "steps.completeness.outputs.complete == 'true'" in upload["if"]
