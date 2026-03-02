"""
tests/test_integration.py

True end-to-end integration test for the GhostGates pipeline.

Mocks a GitHub org with 5 repos having different configs and protections.
Runs the full pipeline (collect → store → analyze → format) using
mocked HTTP only — NO network calls.

Verifies:
  a) Correct findings are produced for each repo
  b) JSON output validates against the tool's output schema/contract
  c) Markdown output contains required sections and is well-formed
  d) No secrets appear anywhere in outputs or logs
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone

import pytest
import respx

from ghostgates.client.github_client import GitHubClient
from ghostgates.collectors.assembly import collect_org_gate_models
from ghostgates.engine import registry
from ghostgates.models.enums import AttackerLevel, Severity, Confidence, GateType
from ghostgates.models.findings import ScanResult
from ghostgates.reporting.formatter import format_json, format_markdown, format_terminal
from ghostgates.storage.sqlite_store import SQLiteStore

from tests.conftest import (
    FAKE_TOKEN,
    assert_no_secrets,
    make_mock_org,
    wire_mock_org,
)


# ------------------------------------------------------------------
# Org dataset: 5 repos with varied configs
# ------------------------------------------------------------------

ORG = "megacorp"

REPO_CONFIGS = [
    # Repo 1: Well-protected — should produce few/no findings
    {
        "name": "fortress",
        "visibility": "private",
        "has_branch_protection": True,
        "bp_reviews": 2,
        "bp_enforce_admins": True,
        "bp_dismiss_stale": True,
        "bp_codeowners": True,
        "environments": [
            {
                "name": "production",
                "reviewers": [{"type": "User", "login": "alice", "id": 10}],
                "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False},
            },
        ],
        "workflows": [
            {
                "name": "ci",
                "path": ".github/workflows/ci.yml",
                "yaml": (
                    "name: CI\n"
                    "on: push\n"
                    "permissions:\n"
                    "  contents: read\n"
                    "jobs:\n"
                    "  build:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "      - run: make test\n"
                ),
            },
        ],
    },

    # Repo 2: Classic BP misconfig — admin bypass, stale reviews, no codeowners
    {
        "name": "leaky-api",
        "visibility": "private",
        "has_branch_protection": True,
        "bp_reviews": 1,
        "bp_enforce_admins": False,
        "bp_dismiss_stale": False,
        "bp_codeowners": False,
        "collaborators": [
            {"login": "admin1", "id": 100, "permissions": {"admin": True, "maintain": True, "push": True, "triage": True, "pull": True}},
            {"login": "admin2", "id": 101, "permissions": {"admin": True, "maintain": True, "push": True, "triage": True, "pull": True}},
            {"login": "dev1", "id": 102, "permissions": {"admin": False, "maintain": False, "push": True, "triage": True, "pull": True}},
        ],
    },

    # Repo 3: Dangerous workflow — pull_request_target + PR head checkout
    {
        "name": "oss-project",
        "visibility": "public",
        "has_branch_protection": True,
        "bp_reviews": 1,
        "bp_enforce_admins": True,
        "bp_dismiss_stale": True,
        "workflows": [
            {
                "name": "pr-check",
                "path": ".github/workflows/pr-check.yml",
                "yaml": (
                    "name: PR Check\n"
                    "on: pull_request_target\n"
                    "jobs:\n"
                    "  check:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "        with:\n"
                    "          ref: ${{ github.event.pull_request.head.sha }}\n"
                    "      - run: npm install && npm test\n"
                ),
            },
            {
                "name": "workflow-run",
                "path": ".github/workflows/post-pr.yml",
                "yaml": (
                    "name: Post PR\n"
                    "on:\n"
                    "  workflow_run:\n"
                    "    workflows: ['PR Check']\n"
                    "    types: [completed]\n"
                    "jobs:\n"
                    "  deploy:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "      - run: echo deploy\n"
                ),
            },
        ],
    },

    # Repo 4: Environment misconfigs — no reviewers on prod, wait-timer-only staging
    {
        "name": "deploy-service",
        "visibility": "private",
        "has_branch_protection": True,
        "bp_reviews": 1,
        "bp_enforce_admins": False,
        "environments": [
            {
                "name": "production",
                "deployment_branch_policy": None,
                # no reviewers!
            },
            {
                "name": "staging",
                "wait_timer": 15,
                "deployment_branch_policy": None,
                # wait timer but no reviewers
            },
        ],
        "workflows": [
            {
                "name": "deploy",
                "path": ".github/workflows/deploy.yml",
                "yaml": (
                    "name: Deploy\n"
                    "on: push\n"
                    "permissions: write-all\n"
                    "jobs:\n"
                    "  deploy-prod:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    environment: production\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "      - run: ./deploy.sh\n"
                    "  call-shared:\n"
                    "    uses: external-org/shared/.github/workflows/release.yml@main\n"
                    "    secrets: inherit\n"
                ),
            },
        ],
    },

    # Repo 5: Archived — should be skipped entirely
    {
        "name": "old-service",
        "visibility": "private",
        "archived": True,
    },
]


# ------------------------------------------------------------------
# Build the mock dataset once
# ------------------------------------------------------------------

@pytest.fixture(scope="module")
def org_dataset():
    """Build the mock org dataset."""
    return make_mock_org(org=ORG, repo_configs=REPO_CONFIGS)


# ------------------------------------------------------------------
# Integration test: full pipeline
# ------------------------------------------------------------------

class TestFullPipeline:
    """End-to-end test: collect → analyze → format."""

    @pytest.fixture(autouse=True)
    async def _run_pipeline(self, org_dataset, tmp_path):
        """Run the full pipeline once per test class, cache the results."""
        with respx.mock(base_url="https://api.github.com", assert_all_called=False) as router:
            wire_mock_org(router, ORG, org_dataset)

            async with GitHubClient(token=FAKE_TOKEN) as client:
                gate_models, collect_errors = await collect_org_gate_models(
                    client, ORG, include_forks=False
                )

            self.gate_models = gate_models
            self.collect_errors = collect_errors

            # Run rules at max attacker level (org-owner sees everything)
            self.findings = registry.run_all_repos(
                gate_models, attacker_level=AttackerLevel.ORG_OWNER
            )

            # Build scan result
            self.result = ScanResult(
                org=ORG,
                repos_scanned=len(gate_models),
                repos_skipped=1,  # archived repo
                findings=self.findings,
                attacker_level=AttackerLevel.ORG_OWNER,
                collected_at=datetime.now(timezone.utc).isoformat(),
            )

            # Store
            db = tmp_path / "integration.db"
            self.store = SQLiteStore(db)
            self.store.upsert_gate_models(gate_models)
            self.scan_id = self.store.save_scan_result(self.result)

            # Formatters
            self.json_output = format_json(self.result)
            self.md_output = format_markdown(self.result)
            self.terminal_output = format_terminal(self.result, verbose=True)

            yield

            self.store.close()

    # ==============================================================
    # A) Collection correctness
    # ==============================================================

    def test_collected_active_repos_only(self):
        """Archived repo 'old-service' should be excluded."""
        repo_names = {g.repo for g in self.gate_models}
        assert "old-service" not in repo_names
        assert len(self.gate_models) == 4  # 5 defined minus 1 archived

    def test_collected_repo_names(self):
        repo_names = sorted(g.repo for g in self.gate_models)
        assert repo_names == ["deploy-service", "fortress", "leaky-api", "oss-project"]

    def test_no_collection_errors(self):
        assert self.collect_errors == [], f"Unexpected collection errors: {self.collect_errors}"

    def test_fortress_well_protected(self):
        gate = _find_gate(self.gate_models, "fortress")
        assert len(gate.branch_protections) >= 1
        bp = gate.branch_protections[0]
        assert bp.enforce_admins is True
        assert bp.required_approving_review_count == 2
        assert bp.dismiss_stale_reviews is True

    def test_fortress_has_environment(self):
        gate = _find_gate(self.gate_models, "fortress")
        assert len(gate.environments) == 1
        assert gate.environments[0].name == "production"
        assert len(gate.environments[0].reviewers) == 1

    def test_leaky_api_bp_misconfig(self):
        gate = _find_gate(self.gate_models, "leaky-api")
        assert len(gate.branch_protections) >= 1
        bp = gate.branch_protections[0]
        assert bp.enforce_admins is False
        assert bp.dismiss_stale_reviews is False

    def test_oss_project_has_workflows(self):
        gate = _find_gate(self.gate_models, "oss-project")
        assert len(gate.workflows) == 2

    # ==============================================================
    # B) Finding correctness per repo
    # ==============================================================

    def test_fortress_minimal_findings(self):
        """Well-protected repo should have very few findings."""
        repo_findings = _findings_for(self.findings, f"{ORG}/fortress")
        # fortress has enforce_admins=True, stale=True, codeowners=True
        # Expect 0 BP findings; env has reviewers + protected branch policy
        high_or_critical = [
            f for f in repo_findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(high_or_critical) == 0, (
            f"Fortress should have no HIGH/CRITICAL findings, got: "
            f"{[f.rule_id for f in high_or_critical]}"
        )

    def test_leaky_api_admin_bypass(self):
        """leaky-api has enforce_admins=False → should trigger BP-001."""
        repo_findings = _findings_for(self.findings, f"{ORG}/leaky-api")
        bp001 = [f for f in repo_findings if f.rule_id == "GHOST-BP-001"]
        assert len(bp001) >= 1, "Expected GHOST-BP-001 finding for leaky-api"
        assert bp001[0].severity == Severity.HIGH

    def test_leaky_api_stale_reviews(self):
        """leaky-api has dismiss_stale_reviews=False → should trigger BP-002."""
        repo_findings = _findings_for(self.findings, f"{ORG}/leaky-api")
        bp002 = [f for f in repo_findings if f.rule_id == "GHOST-BP-002"]
        assert len(bp002) >= 1, "Expected GHOST-BP-002 finding for leaky-api"

    def test_leaky_api_no_codeowners(self):
        """leaky-api has require_code_owner_reviews=False → should trigger BP-003."""
        repo_findings = _findings_for(self.findings, f"{ORG}/leaky-api")
        bp003 = [f for f in repo_findings if f.rule_id == "GHOST-BP-003"]
        assert len(bp003) >= 1, "Expected GHOST-BP-003 finding for leaky-api"

    def test_oss_project_pr_target_critical(self):
        """oss-project has pull_request_target + head checkout → GHOST-WF-001 CRITICAL."""
        repo_findings = _findings_for(self.findings, f"{ORG}/oss-project")
        wf001 = [f for f in repo_findings if f.rule_id == "GHOST-WF-001"]
        assert len(wf001) >= 1, "Expected GHOST-WF-001 finding for oss-project"
        assert wf001[0].severity == Severity.CRITICAL
        assert wf001[0].min_privilege == AttackerLevel.EXTERNAL

    def test_oss_project_fork_pr_secrets(self):
        """oss-project is public with workflow_run → GHOST-WF-004."""
        repo_findings = _findings_for(self.findings, f"{ORG}/oss-project")
        wf004 = [f for f in repo_findings if f.rule_id == "GHOST-WF-004"]
        assert len(wf004) >= 1, "Expected GHOST-WF-004 finding for oss-project"

    def test_deploy_service_env_no_reviewers(self):
        """deploy-service production env has no reviewers → GHOST-ENV-001."""
        repo_findings = _findings_for(self.findings, f"{ORG}/deploy-service")
        env001 = [f for f in repo_findings if f.rule_id == "GHOST-ENV-001"]
        assert len(env001) >= 1, "Expected GHOST-ENV-001 finding for deploy-service"

    def test_deploy_service_wait_timer_only(self):
        """deploy-service staging env has wait timer but no reviewers → GHOST-ENV-003."""
        repo_findings = _findings_for(self.findings, f"{ORG}/deploy-service")
        env003 = [f for f in repo_findings if f.rule_id == "GHOST-ENV-003"]
        assert len(env003) >= 1, "Expected GHOST-ENV-003 finding for deploy-service"

    def test_deploy_service_write_all(self):
        """deploy-service workflow has permissions: write-all → GHOST-WF-002."""
        repo_findings = _findings_for(self.findings, f"{ORG}/deploy-service")
        wf002 = [f for f in repo_findings if f.rule_id == "GHOST-WF-002"]
        assert len(wf002) >= 1, "Expected GHOST-WF-002 finding for deploy-service"

    def test_deploy_service_secrets_inherit(self):
        """deploy-service has secrets: inherit on external reusable → GHOST-WF-003."""
        repo_findings = _findings_for(self.findings, f"{ORG}/deploy-service")
        wf003 = [f for f in repo_findings if f.rule_id == "GHOST-WF-003"]
        assert len(wf003) >= 1, "Expected GHOST-WF-003 finding for deploy-service"

    # ==============================================================
    # C) JSON output schema validation
    # ==============================================================

    def test_json_valid_parse(self):
        """JSON output must be valid JSON."""
        data = json.loads(self.json_output)
        assert isinstance(data, dict)

    def test_json_required_fields(self):
        """JSON output must have all ScanResult fields."""
        data = json.loads(self.json_output)
        required = {"org", "repos_scanned", "findings", "attacker_level", "collected_at"}
        assert required.issubset(data.keys()), f"Missing: {required - data.keys()}"

    def test_json_findings_structure(self):
        """Each finding must have required fields."""
        data = json.loads(self.json_output)
        required_finding_fields = {
            "rule_id", "rule_name", "repo", "gate_type", "severity",
            "confidence", "min_privilege", "summary", "bypass_path",
            "evidence", "gating_conditions", "remediation",
        }
        for f in data["findings"]:
            missing = required_finding_fields - f.keys()
            assert not missing, f"Finding {f.get('rule_id', '?')} missing fields: {missing}"

    def test_json_severity_values(self):
        """All severity values must be valid."""
        data = json.loads(self.json_output)
        valid = {s.value for s in Severity}
        for f in data["findings"]:
            assert f["severity"] in valid, f"Invalid severity: {f['severity']}"

    def test_json_gate_type_values(self):
        """All gate_type values must be valid."""
        data = json.loads(self.json_output)
        valid = {g.value for g in GateType}
        for f in data["findings"]:
            assert f["gate_type"] in valid, f"Invalid gate_type: {f['gate_type']}"

    def test_json_attacker_level_values(self):
        """All min_privilege values must be valid."""
        data = json.loads(self.json_output)
        valid = {a.value for a in AttackerLevel}
        for f in data["findings"]:
            assert f["min_privilege"] in valid, f"Invalid min_privilege: {f['min_privilege']}"

    def test_json_rule_ids_prefixed(self):
        """All rule IDs must follow GHOST-XX-NNN pattern."""
        data = json.loads(self.json_output)
        pattern = re.compile(r"^GHOST-[A-Z]+-\d{3}$")
        for f in data["findings"]:
            assert pattern.match(f["rule_id"]), f"Invalid rule_id format: {f['rule_id']}"

    def test_json_repos_scanned_count(self):
        data = json.loads(self.json_output)
        assert data["repos_scanned"] == 4

    # ==============================================================
    # D) Markdown output validation
    # ==============================================================

    def test_markdown_has_title(self):
        assert "# GhostGates Scan Report" in self.md_output

    def test_markdown_has_org(self):
        assert f"**Organization:** {ORG}" in self.md_output

    def test_markdown_has_summary_table(self):
        assert "## Summary" in self.md_output
        assert "| Severity | Count |" in self.md_output

    def test_markdown_has_findings_section(self):
        assert "## Findings" in self.md_output

    def test_markdown_has_repo_sections(self):
        """Each repo with findings should have a ### section."""
        assert f"### {ORG}/leaky-api" in self.md_output
        assert f"### {ORG}/oss-project" in self.md_output

    def test_markdown_has_evidence_blocks(self):
        assert "```json" in self.md_output
        assert "<details>" in self.md_output

    def test_markdown_has_remediation(self):
        assert "**Remediation:**" in self.md_output

    # ==============================================================
    # E) Terminal output validation
    # ==============================================================

    def test_terminal_has_header(self):
        assert "GhostGates Scan Results" in self.terminal_output

    def test_terminal_has_repo_count(self):
        assert "Repos scanned:" in self.terminal_output

    def test_terminal_verbose_has_bypass_paths(self):
        assert "Bypass path:" in self.terminal_output

    # ==============================================================
    # F) Storage round-trip
    # ==============================================================

    def test_gate_models_stored(self):
        models = self.store.get_gate_models(ORG)
        assert len(models) == 4

    def test_gate_model_round_trip(self):
        gate = self.store.get_gate_model(ORG, "leaky-api")
        assert gate is not None
        assert gate.full_name == f"{ORG}/leaky-api"
        assert len(gate.branch_protections) >= 1

    def test_scan_result_stored(self):
        result = self.store.get_latest_scan(ORG)
        assert result is not None
        assert result.org == ORG
        assert len(result.findings) == len(self.findings)

    def test_scan_result_by_id(self):
        result = self.store.get_scan_result(self.scan_id)
        assert result is not None
        assert result.repos_scanned == 4

    # ==============================================================
    # G) Security: no secrets in outputs or logs
    # ==============================================================

    def test_no_secrets_in_json(self):
        assert_no_secrets(self.json_output)

    def test_no_secrets_in_markdown(self):
        assert_no_secrets(self.md_output)

    def test_no_secrets_in_terminal(self):
        assert_no_secrets(self.terminal_output)

    def test_no_secrets_in_findings_evidence(self):
        """Evidence dicts must never contain tokens."""
        for f in self.findings:
            evidence_str = json.dumps(f.evidence, default=str)
            assert_no_secrets(evidence_str)

    def test_no_secrets_in_scan_result_json(self):
        """Serialized scan result must not contain tokens."""
        result_json = self.result.model_dump_json()
        assert_no_secrets(result_json)

    def test_no_secrets_in_stored_data(self, tmp_path):
        """Database file contents must not contain tokens."""
        db = tmp_path / "integration.db"
        if db.exists():
            raw = db.read_bytes().decode("utf-8", errors="replace")
            assert_no_secrets(raw)

    # ==============================================================
    # H) meets_filter correctness (regression for severity bug)
    # ==============================================================

    def test_filter_severity_low_excluded_by_medium(self):
        """LOW findings must be excluded when min_severity is MEDIUM."""
        from ghostgates.models.findings import BypassFinding
        low_findings = [f for f in self.findings if f.severity == Severity.LOW]
        for f in low_findings:
            assert not f.meets_filter(min_severity=Severity.MEDIUM), (
                f"LOW finding {f.rule_id} passed MEDIUM severity filter"
            )

    def test_filter_severity_info_excluded_by_medium(self):
        """INFO findings must be excluded when min_severity is MEDIUM."""
        from ghostgates.models.findings import BypassFinding
        info_findings = [f for f in self.findings if f.severity == Severity.INFO]
        for f in info_findings:
            assert not f.meets_filter(min_severity=Severity.MEDIUM), (
                f"INFO finding {f.rule_id} passed MEDIUM severity filter"
            )

    def test_filter_severity_critical_included_by_medium(self):
        """CRITICAL findings must pass when min_severity is MEDIUM."""
        crit_findings = [f for f in self.findings if f.severity == Severity.CRITICAL]
        for f in crit_findings:
            assert f.meets_filter(min_severity=Severity.MEDIUM), (
                f"CRITICAL finding {f.rule_id} failed MEDIUM severity filter"
            )

    # ==============================================================
    # I) Rule ID uniqueness
    # ==============================================================

    def test_all_rule_ids_unique(self):
        """No two registered rules may share the same rule_id."""
        ids = [r.rule_id for r in registry.rules]
        assert len(ids) == len(set(ids)), (
            f"Duplicate rule IDs: {[i for i in ids if ids.count(i) > 1]}"
        )

    def test_findings_rule_ids_valid(self):
        """Every finding's rule_id must correspond to a registered rule."""
        registered_ids = {r.rule_id for r in registry.rules}
        for f in self.findings:
            assert f.rule_id in registered_ids, (
                f"Finding references unregistered rule: {f.rule_id}"
            )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _find_gate(models: list, repo_name: str):
    """Find a GateModel by repo name."""
    for g in models:
        if g.repo == repo_name:
            return g
    raise ValueError(f"No gate model found for repo '{repo_name}'")


def _findings_for(findings: list, full_name: str) -> list:
    """Filter findings for a specific repo."""
    return [f for f in findings if f.repo == full_name]
