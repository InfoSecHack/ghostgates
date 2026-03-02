"""
Tests for ghostgates.collectors.assembly and ghostgates.storage.sqlite_store

Tests assembly orchestration with mocked sub-collectors, and storage
round-trip serialization + CRUD operations.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from ghostgates.collectors.assembly import (
    collect_org_gate_models,
    _filter_repos,
    _build_workflow_permissions,
    _build_oidc_config,
)
from ghostgates.models.enums import AttackerLevel, Confidence, GateType, Severity
from ghostgates.models.gates import (
    BranchProtection,
    Collaborator,
    EnvironmentConfig,
    GateModel,
    OIDCConfig,
    Ruleset,
    WorkflowDefinition,
    WorkflowPermissions,
    WorkflowTrigger,
)
from ghostgates.models.findings import BypassFinding, ScanResult
from ghostgates.storage.sqlite_store import SQLiteStore


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def store(tmp_db) -> SQLiteStore:
    s = SQLiteStore(tmp_db)
    yield s
    s.close()


def _make_gate_model(
    org: str = "test-org",
    repo: str = "test-repo",
    **overrides,
) -> GateModel:
    """Create a minimal GateModel for testing."""
    defaults = dict(
        org=org,
        repo=repo,
        full_name=f"{org}/{repo}",
        default_branch="main",
        visibility="private",
        is_fork=False,
        is_archived=False,
        collected_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return GateModel(**defaults)


def _make_gate_model_with_data() -> GateModel:
    """Create a GateModel with all sub-models populated."""
    return GateModel(
        org="acme",
        repo="web-app",
        full_name="acme/web-app",
        default_branch="main",
        visibility="private",
        branch_protections=[
            BranchProtection(
                branch="main",
                required_approving_review_count=2,
                dismiss_stale_reviews=True,
                enforce_admins=False,
                raw={"test": "data"},
            ),
        ],
        rulesets=[
            Ruleset(
                id=1,
                name="main-protection",
                enforcement="active",
                target="branch",
            ),
        ],
        environments=[
            EnvironmentConfig(name="production", wait_timer=15),
            EnvironmentConfig(name="staging"),
        ],
        workflow_permissions=WorkflowPermissions(
            default_workflow_permissions="read",
            can_approve_pull_request_reviews=False,
        ),
        workflows=[
            WorkflowDefinition(
                path=".github/workflows/ci.yml",
                name="CI",
                triggers=[WorkflowTrigger(event="push", branches=["main"])],
            ),
        ],
        oidc=OIDCConfig(org_level_template=["repo", "ref"]),
        collaborators=[
            Collaborator(login="alice", id=1, permission="admin"),
            Collaborator(login="bob", id=2, permission="write"),
        ],
        collected_at=datetime.now(timezone.utc),
    )


def _make_scan_result(org: str = "test-org", n_findings: int = 2) -> ScanResult:
    """Create a ScanResult with findings."""
    findings = []
    for i in range(n_findings):
        findings.append(BypassFinding(
            rule_id=f"GHOST-BP-{i:03d}",
            rule_name=f"Test Rule {i}",
            repo=f"{org}/repo",
            gate_type=GateType.BRANCH_PROTECTION,
            severity=Severity.HIGH if i == 0 else Severity.MEDIUM,
            confidence=Confidence.HIGH,
            min_privilege=AttackerLevel.REPO_ADMIN,
            summary=f"Test finding {i}",
            bypass_path=f"Step 1 -> Step 2 for finding {i}",
            evidence={"key": f"value-{i}"},
            gating_conditions=["Attacker must have admin access"],
            remediation=f"Fix {i}",
        ))

    return ScanResult(
        org=org,
        repos_scanned=5,
        findings=findings,
        attacker_level=AttackerLevel.REPO_ADMIN,
        collected_at=datetime.now(timezone.utc).isoformat(),
    )


# ==================================================================
# Tests: SQLiteStore — lifecycle
# ==================================================================

class TestStoreLifecycle:
    def test_creates_db_file(self, tmp_db):
        store = SQLiteStore(tmp_db)
        assert tmp_db.exists()
        store.close()

    def test_db_file_permissions(self, tmp_db):
        """DB file should be created with 0o600 permissions."""
        store = SQLiteStore(tmp_db)
        mode = oct(os.stat(tmp_db).st_mode & 0o777)
        store.close()
        assert mode == "0o600"

    def test_context_manager(self, tmp_db):
        with SQLiteStore(tmp_db) as store:
            assert store.db_path == tmp_db
        # Should be closed after exiting context

    def test_reopen_existing_db(self, tmp_db):
        """Can close and reopen an existing database."""
        store1 = SQLiteStore(tmp_db)
        store1.upsert_gate_model(_make_gate_model())
        store1.close()

        store2 = SQLiteStore(tmp_db)
        model = store2.get_gate_model("test-org", "test-repo")
        store2.close()
        assert model is not None
        assert model.repo == "test-repo"


# ==================================================================
# Tests: SQLiteStore — GateModel CRUD
# ==================================================================

class TestGateModelCRUD:
    def test_upsert_and_get(self, store):
        model = _make_gate_model()
        store.upsert_gate_model(model)
        retrieved = store.get_gate_model("test-org", "test-repo")
        assert retrieved is not None
        assert retrieved.org == "test-org"
        assert retrieved.repo == "test-repo"
        assert retrieved.full_name == "test-org/test-repo"

    def test_upsert_replaces(self, store):
        """Second upsert replaces the first."""
        model1 = _make_gate_model(visibility="private")
        model2 = _make_gate_model(visibility="public")
        store.upsert_gate_model(model1)
        store.upsert_gate_model(model2)
        retrieved = store.get_gate_model("test-org", "test-repo")
        assert retrieved.visibility == "public"
        assert store.count_gate_models() == 1

    def test_get_nonexistent(self, store):
        assert store.get_gate_model("no", "such") is None

    def test_get_gate_models_by_org(self, store):
        store.upsert_gate_model(_make_gate_model(repo="repo1"))
        store.upsert_gate_model(_make_gate_model(repo="repo2"))
        store.upsert_gate_model(_make_gate_model(org="other-org", repo="repo3"))

        models = store.get_gate_models("test-org")
        assert len(models) == 2
        names = {m.repo for m in models}
        assert names == {"repo1", "repo2"}

    def test_delete(self, store):
        store.upsert_gate_model(_make_gate_model())
        assert store.delete_gate_model("test-org", "test-repo") is True
        assert store.get_gate_model("test-org", "test-repo") is None

    def test_delete_nonexistent(self, store):
        assert store.delete_gate_model("no", "such") is False

    def test_count(self, store):
        assert store.count_gate_models() == 0
        store.upsert_gate_model(_make_gate_model(repo="a"))
        store.upsert_gate_model(_make_gate_model(repo="b"))
        store.upsert_gate_model(_make_gate_model(org="other", repo="c"))
        assert store.count_gate_models() == 3
        assert store.count_gate_models("test-org") == 2
        assert store.count_gate_models("other") == 1

    def test_batch_upsert(self, store):
        models = [_make_gate_model(repo=f"repo{i}") for i in range(5)]
        count = store.upsert_gate_models(models)
        assert count == 5
        assert store.count_gate_models() == 5

    def test_round_trip_complex_model(self, store):
        """Full GateModel with all sub-models survives JSON round-trip."""
        model = _make_gate_model_with_data()
        store.upsert_gate_model(model)
        retrieved = store.get_gate_model("acme", "web-app")

        assert retrieved is not None
        assert len(retrieved.branch_protections) == 1
        assert retrieved.branch_protections[0].required_approving_review_count == 2
        assert retrieved.branch_protections[0].dismiss_stale_reviews is True
        assert retrieved.branch_protections[0].raw == {"test": "data"}

        assert len(retrieved.rulesets) == 1
        assert retrieved.rulesets[0].enforcement == "active"

        assert len(retrieved.environments) == 2
        assert retrieved.environments[0].wait_timer == 15

        assert retrieved.workflow_permissions.default_workflow_permissions == "read"

        assert len(retrieved.workflows) == 1
        assert retrieved.workflows[0].name == "CI"
        assert retrieved.workflows[0].triggers[0].branches == ["main"]

        assert retrieved.oidc.org_level_template == ["repo", "ref"]

        assert len(retrieved.collaborators) == 2
        assert retrieved.collaborators[0].permission == "admin"


# ==================================================================
# Tests: SQLiteStore — ScanResult CRUD
# ==================================================================

class TestScanResultCRUD:
    def test_save_and_get(self, store):
        result = _make_scan_result()
        row_id = store.save_scan_result(result)
        assert row_id > 0

        retrieved = store.get_scan_result(row_id)
        assert retrieved is not None
        assert retrieved.org == "test-org"
        assert retrieved.repos_scanned == 5
        assert len(retrieved.findings) == 2

    def test_get_nonexistent(self, store):
        assert store.get_scan_result(999) is None

    def test_get_latest_scan(self, store):
        r1 = _make_scan_result(n_findings=1)
        r1.collected_at = "2025-01-01T00:00:00+00:00"
        r2 = _make_scan_result(n_findings=3)
        r2.collected_at = "2025-06-01T00:00:00+00:00"
        store.save_scan_result(r1)
        store.save_scan_result(r2)

        latest = store.get_latest_scan("test-org")
        assert latest is not None
        assert len(latest.findings) == 3

    def test_get_latest_scan_no_results(self, store):
        assert store.get_latest_scan("empty-org") is None

    def test_list_scans(self, store):
        for i in range(5):
            r = _make_scan_result(n_findings=i)
            r.collected_at = f"2025-0{i+1}-01T00:00:00+00:00"
            store.save_scan_result(r)

        summaries = store.list_scans("test-org", limit=3)
        assert len(summaries) == 3
        # Should be newest first
        assert summaries[0]["finding_count"] == 4
        assert summaries[1]["finding_count"] == 3
        assert summaries[2]["finding_count"] == 2

    def test_list_scans_empty(self, store):
        assert store.list_scans("empty") == []

    def test_findings_round_trip(self, store):
        """Findings with all fields survive serialization."""
        result = _make_scan_result(n_findings=1)
        row_id = store.save_scan_result(result)
        retrieved = store.get_scan_result(row_id)

        f = retrieved.findings[0]
        assert f.rule_id == "GHOST-BP-000"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert f.min_privilege == AttackerLevel.REPO_ADMIN
        assert f.evidence == {"key": "value-0"}
        assert len(f.gating_conditions) == 1
        assert f.remediation == "Fix 0"


# ==================================================================
# Tests: Assembly helpers (unit, no API)
# ==================================================================

class TestAssemblyHelpers:
    def test_filter_repos_excludes_forks(self):
        repos = [
            {"name": "real", "fork": False},
            {"name": "forked", "fork": True},
        ]
        result = _filter_repos(repos, include_forks=False, repo_filter=None)
        assert len(result) == 1
        assert result[0]["name"] == "real"

    def test_filter_repos_includes_forks(self):
        repos = [
            {"name": "real", "fork": False},
            {"name": "forked", "fork": True},
        ]
        result = _filter_repos(repos, include_forks=True, repo_filter=None)
        assert len(result) == 2

    def test_filter_repos_by_name(self):
        repos = [
            {"name": "api"},
            {"name": "web"},
            {"name": "docs"},
        ]
        result = _filter_repos(repos, include_forks=True, repo_filter=["api", "docs"])
        names = {r["name"] for r in result}
        assert names == {"api", "docs"}

    def test_build_workflow_permissions_defaults(self):
        perms = _build_workflow_permissions({}, {})
        assert perms.default_workflow_permissions == "read"
        assert perms.can_approve_pull_request_reviews is False
        assert perms.allowed_actions == "all"

    def test_build_workflow_permissions_org_level(self):
        org = {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True}
        perms = _build_workflow_permissions(org, {})
        assert perms.default_workflow_permissions == "write"
        assert perms.can_approve_pull_request_reviews is True

    def test_build_workflow_permissions_repo_overrides(self):
        org = {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True}
        repo = {"can_approve_pull_request_reviews": False}
        perms = _build_workflow_permissions(org, repo)
        assert perms.default_workflow_permissions == "write"  # from org
        assert perms.can_approve_pull_request_reviews is False  # repo override

    def test_build_oidc_config_none(self):
        oidc = _build_oidc_config(None)
        assert oidc.org_level_template == []

    def test_build_oidc_config_with_claims(self):
        template = {"include_claim_keys": ["repo", "ref", "actor"]}
        oidc = _build_oidc_config(template)
        assert oidc.org_level_template == ["repo", "ref", "actor"]
        assert oidc.raw == template


# ==================================================================
# Tests: Assembly orchestration (mocked sub-collectors)
# ==================================================================

class TestAssemblyOrchestration:
    @pytest.mark.asyncio
    async def test_collect_org_gate_models_basic(self):
        """End-to-end assembly with mocked collectors."""
        mock_client = AsyncMock()

        with (
            patch("ghostgates.collectors.assembly.collect_org_metadata") as mock_org_meta,
            patch("ghostgates.collectors.assembly.collect_repos") as mock_repos,
            patch("ghostgates.collectors.assembly.collect_branch_protections") as mock_bp,
            patch("ghostgates.collectors.assembly.collect_environments") as mock_env,
            patch("ghostgates.collectors.assembly.collect_workflows") as mock_wf,
            patch("ghostgates.collectors.assembly.collect_collaborators") as mock_collab,
            patch("ghostgates.collectors.assembly.collect_rulesets") as mock_rs,
            patch("ghostgates.collectors.assembly._collect_repo_actions_permissions") as mock_perms,
        ):
            mock_org_meta.return_value = {
                "actions_permissions": {"default_workflow_permissions": "read"},
                "oidc_template": None,
            }
            mock_repos.return_value = [
                {"name": "web-app", "default_branch": "main", "visibility": "private", "fork": False, "archived": False},
            ]
            mock_bp.return_value = [
                BranchProtection(branch="main", required_approving_review_count=1),
            ]
            mock_env.return_value = [
                EnvironmentConfig(name="production"),
            ]
            mock_wf.return_value = []
            mock_collab.return_value = [
                Collaborator(login="alice", id=1, permission="admin"),
            ]
            mock_rs.return_value = []
            mock_perms.return_value = {}

            models, errors = await collect_org_gate_models(mock_client, "acme")

            assert len(models) == 1
            assert errors == []
            assert models[0].org == "acme"
            assert models[0].repo == "web-app"
            assert len(models[0].branch_protections) == 1
            assert len(models[0].environments) == 1
            assert len(models[0].collaborators) == 1

    @pytest.mark.asyncio
    async def test_collect_with_repo_filter(self):
        """repo_filter limits which repos are scanned."""
        mock_client = AsyncMock()

        with (
            patch("ghostgates.collectors.assembly.collect_org_metadata") as mock_org_meta,
            patch("ghostgates.collectors.assembly.collect_repos") as mock_repos,
            patch("ghostgates.collectors.assembly.collect_branch_protections") as mock_bp,
            patch("ghostgates.collectors.assembly.collect_environments") as mock_env,
            patch("ghostgates.collectors.assembly.collect_workflows") as mock_wf,
            patch("ghostgates.collectors.assembly.collect_collaborators") as mock_collab,
            patch("ghostgates.collectors.assembly.collect_rulesets") as mock_rs,
            patch("ghostgates.collectors.assembly._collect_repo_actions_permissions") as mock_perms,
        ):
            mock_org_meta.return_value = {"actions_permissions": {}, "oidc_template": None}
            mock_repos.return_value = [
                {"name": "api", "default_branch": "main", "visibility": "private", "fork": False, "archived": False},
                {"name": "web", "default_branch": "main", "visibility": "private", "fork": False, "archived": False},
                {"name": "docs", "default_branch": "main", "visibility": "public", "fork": False, "archived": False},
            ]
            mock_bp.return_value = []
            mock_env.return_value = []
            mock_wf.return_value = []
            mock_collab.return_value = []
            mock_rs.return_value = []
            mock_perms.return_value = {}

            models, errors = await collect_org_gate_models(
                mock_client, "acme", repo_filter=["api"]
            )

            assert len(models) == 1
            assert models[0].repo == "api"

    @pytest.mark.asyncio
    async def test_single_repo_failure_doesnt_stop_scan(self):
        """If one repo fails, others still complete."""
        mock_client = AsyncMock()

        with (
            patch("ghostgates.collectors.assembly.collect_org_metadata") as mock_org_meta,
            patch("ghostgates.collectors.assembly.collect_repos") as mock_repos,
            patch("ghostgates.collectors.assembly.collect_branch_protections") as mock_bp,
            patch("ghostgates.collectors.assembly.collect_environments") as mock_env,
            patch("ghostgates.collectors.assembly.collect_workflows") as mock_wf,
            patch("ghostgates.collectors.assembly.collect_collaborators") as mock_collab,
            patch("ghostgates.collectors.assembly.collect_rulesets") as mock_rs,
            patch("ghostgates.collectors.assembly._collect_repo_actions_permissions") as mock_perms,
        ):
            mock_org_meta.return_value = {"actions_permissions": {}, "oidc_template": None}
            mock_repos.return_value = [
                {"name": "good", "default_branch": "main", "visibility": "private", "fork": False, "archived": False},
                {"name": "bad", "default_branch": "main", "visibility": "private", "fork": False, "archived": False},
            ]

            call_count = 0
            async def bp_side_effect(client, owner, repo, branch):
                nonlocal call_count
                call_count += 1
                if repo == "bad":
                    raise RuntimeError("API explosion")
                return []

            mock_bp.side_effect = bp_side_effect
            mock_env.return_value = []
            mock_wf.return_value = []
            mock_collab.return_value = []
            mock_rs.return_value = []
            mock_perms.return_value = {}

            models, errors = await collect_org_gate_models(mock_client, "acme")

            assert len(models) == 1
            assert models[0].repo == "good"
            assert len(errors) == 1
            assert "bad" in errors[0]
