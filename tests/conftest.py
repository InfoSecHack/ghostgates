"""
tests/conftest.py

Shared fixtures for all GhostGates tests.

Provides:
  - Temp workspace fixtures (tmp_path is built-in to pytest)
  - Fake tokens that look realistic but are obviously fake
  - Deterministic time freezing
  - Mocked HTTP transport for GitHubClient
  - Mock GitHub org dataset generator
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import respx

from ghostgates.client.github_client import GitHubClient
from ghostgates.models.enums import AttackerLevel
from ghostgates.models.gates import GateModel
from ghostgates.storage.sqlite_store import SQLiteStore

from tests.mocks.gate_models import (
    make_bp,
    make_environment,
    make_gate,
    make_job,
    make_reviewer,
    make_ruleset,
    make_step,
    make_trigger,
    make_workflow,
)


# ------------------------------------------------------------------
# Fake tokens — obviously fake, never real
# ------------------------------------------------------------------

FAKE_TOKEN = "ghp_TESTONLYFAKETOKEN000000000000000fake"
"""A fake GitHub PAT for tests.  Matches ghp_ pattern but is clearly fake."""


@pytest.fixture
def fake_token() -> str:
    """Provide a fake GitHub token for tests."""
    return FAKE_TOKEN


# ------------------------------------------------------------------
# Deterministic time
# ------------------------------------------------------------------

FROZEN_TIME = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def frozen_now():
    """Patch datetime.now(timezone.utc) to return a deterministic value."""
    with patch("ghostgates.collectors.assembly.datetime") as mock_dt:
        mock_dt.now.return_value = FROZEN_TIME
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        yield FROZEN_TIME


# ------------------------------------------------------------------
# Temp workspace
# ------------------------------------------------------------------

@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Provide a clean temporary workspace directory."""
    ws = tmp_path / "ghostgates_test"
    ws.mkdir()
    return ws


@pytest.fixture
def db_path(workspace: Path) -> Path:
    """Provide a temporary database path."""
    return workspace / "test.db"


@pytest.fixture
def store(db_path: Path) -> SQLiteStore:
    """Provide a fresh SQLiteStore pointed at a temp DB."""
    s = SQLiteStore(db_path)
    yield s
    s.close()


# ------------------------------------------------------------------
# Mocked HTTP client
# ------------------------------------------------------------------

@pytest.fixture
def mock_transport():
    """Provide a respx mock router for all GitHub API calls.

    Usage::

        def test_something(mock_transport, github_client):
            mock_transport.get("/orgs/acme/repos").respond(200, json=[...])
            result = await github_client.list_org_repos("acme")
    """
    with respx.mock(base_url="https://api.github.com", assert_all_called=False) as router:
        yield router


@pytest.fixture
async def github_client(mock_transport) -> GitHubClient:
    """Provide a GitHubClient wired to the mocked transport.

    The client uses a fake token and the respx-mocked transport.
    """
    client = GitHubClient(token=FAKE_TOKEN)
    yield client
    await client.close()


# ------------------------------------------------------------------
# Mock GitHub org dataset generator
# ------------------------------------------------------------------

def make_mock_org(
    org: str = "acme-corp",
    repo_configs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate a complete mock GitHub org dataset for integration testing.

    Args:
        org: Organization name.
        repo_configs: List of dicts configuring each repo.  Keys:
            - name (str): repo name
            - default_branch (str): default branch name (default "main")
            - visibility (str): "private", "public", "internal"
            - archived (bool): whether repo is archived
            - fork (bool): whether repo is a fork
            - has_branch_protection (bool): add branch protection to default branch
            - bp_reviews (int): required review count
            - bp_enforce_admins (bool): enforce admins
            - bp_dismiss_stale (bool): dismiss stale reviews
            - environments (list[dict]): environment configs
            - workflows (list[dict]): raw workflow file configs
            - collaborators (list[dict]): collaborator configs

    Returns:
        Dict with keys:
            - repos: list of raw GitHub repo API responses
            - branch_protections: dict mapping "owner/repo/branch" -> raw BP response
            - environments: dict mapping "owner/repo" -> raw environments list
            - workflow_files: dict mapping "owner/repo" -> list of file entries
            - workflow_contents: dict mapping "owner/repo/path" -> raw YAML string
            - collaborators: dict mapping "owner/repo" -> list of raw collaborator responses
            - rulesets: dict mapping "owner/repo" -> list of raw rulesets
            - actions_permissions: org-level actions permissions
            - oidc_template: org-level OIDC template
            - repo_actions_permissions: dict mapping "owner/repo" -> actions perms
    """
    if repo_configs is None:
        repo_configs = [{"name": "default-repo"}]

    dataset: dict[str, Any] = {
        "repos": [],
        "branch_protections": {},
        "environments": {},
        "workflow_files": {},
        "workflow_contents": {},
        "collaborators": {},
        "rulesets": {},
        "actions_permissions": {
            "enabled_repositories": "all",
            "allowed_actions": "all",
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
        "oidc_template": None,
        "repo_actions_permissions": {},
    }

    for rc in repo_configs:
        repo_name = rc.get("name", "unnamed")
        default_branch = rc.get("default_branch", "main")
        visibility = rc.get("visibility", "private")
        archived = rc.get("archived", False)
        fork = rc.get("fork", False)

        # --- Repo API response ---
        dataset["repos"].append({
            "id": hash(repo_name) % 100000,
            "name": repo_name,
            "full_name": f"{org}/{repo_name}",
            "default_branch": default_branch,
            "visibility": visibility,
            "private": visibility == "private",
            "archived": archived,
            "disabled": False,
            "fork": fork,
            "owner": {"login": org},
        })

        key = f"{org}/{repo_name}"

        # --- Branch protections ---
        if rc.get("has_branch_protection", False):
            bp_key = f"{org}/{repo_name}/{default_branch}"
            reviews = rc.get("bp_reviews", 1)
            dismiss_stale = rc.get("bp_dismiss_stale", False)
            enforce_admins = rc.get("bp_enforce_admins", False)
            codeowners = rc.get("bp_codeowners", False)

            dataset["branch_protections"][bp_key] = {
                "required_pull_request_reviews": {
                    "required_approving_review_count": reviews,
                    "dismiss_stale_reviews": dismiss_stale,
                    "require_code_owner_reviews": codeowners,
                    "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
                },
                "enforce_admins": {"enabled": enforce_admins},
                "required_status_checks": {
                    "strict": False,
                    "contexts": rc.get("status_checks", []),
                },
                "restrictions": None,
                "required_linear_history": {"enabled": False},
                "allow_force_pushes": {"enabled": rc.get("allow_force_pushes", False)},
                "allow_deletions": {"enabled": False},
                "lock_branch": {"enabled": False},
                "required_signatures": {"enabled": False},
            }

        # --- Environments ---
        env_configs = rc.get("environments", [])
        if env_configs:
            env_list = []
            for ec in env_configs:
                env_entry: dict[str, Any] = {
                    "name": ec.get("name", "production"),
                    "protection_rules": [],
                    "deployment_branch_policy": ec.get("deployment_branch_policy"),
                }
                # Reviewers
                if ec.get("reviewers"):
                    reviewer_entries = []
                    for rev in ec["reviewers"]:
                        reviewer_entries.append({
                            "type": rev.get("type", "User"),
                            "reviewer": {
                                "login": rev.get("login", "reviewer"),
                                "id": rev.get("id", 1),
                                "slug": rev.get("login", "reviewer"),
                            },
                        })
                    env_entry["protection_rules"].append({
                        "type": "required_reviewers",
                        "reviewers": reviewer_entries,
                    })
                # Wait timer
                wt = ec.get("wait_timer", 0)
                if wt:
                    env_entry["protection_rules"].append({
                        "type": "wait_timer",
                        "wait_timer": wt,
                    })
                env_list.append(env_entry)
            dataset["environments"][key] = env_list

        # --- Workflows ---
        wf_configs = rc.get("workflows", [])
        if wf_configs:
            file_entries = []
            for wfc in wf_configs:
                path = wfc.get("path", f".github/workflows/{wfc.get('name', 'ci')}.yml")
                yaml_content = wfc.get("yaml", "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
                file_entries.append({
                    "name": path.split("/")[-1],
                    "path": path,
                    "type": "file",
                })
                dataset["workflow_contents"][f"{key}/{path}"] = yaml_content
            dataset["workflow_files"][key] = file_entries

        # --- Collaborators ---
        collab_configs = rc.get("collaborators", [
            {"login": "admin-user", "id": 1, "permissions": {"admin": True, "maintain": True, "push": True, "triage": True, "pull": True}},
            {"login": "dev-user", "id": 2, "permissions": {"admin": False, "maintain": False, "push": True, "triage": True, "pull": True}},
        ])
        dataset["collaborators"][key] = collab_configs

        # --- Rulesets ---
        dataset["rulesets"][key] = rc.get("rulesets", [])

        # --- Repo Actions permissions ---
        dataset["repo_actions_permissions"][key] = rc.get(
            "repo_actions_permissions",
            {"default_workflow_permissions": "read", "allowed_actions": "all", "enabled": True},
        )

    return dataset


def wire_mock_org(
    router: respx.Router,
    org: str,
    dataset: dict[str, Any],
) -> None:
    """Wire a mock org dataset to a respx router.

    After calling this, a GitHubClient using the router will receive
    realistic responses for all collection endpoints.
    """
    # Org repos
    router.get(f"/orgs/{org}/repos").respond(200, json=dataset["repos"])

    # Org actions permissions
    router.get(f"/orgs/{org}/actions/permissions").respond(
        200, json=dataset["actions_permissions"]
    )

    # OIDC template
    if dataset["oidc_template"]:
        router.get(f"/orgs/{org}/actions/oidc/customization/sub").respond(
            200, json=dataset["oidc_template"]
        )
    else:
        router.get(f"/orgs/{org}/actions/oidc/customization/sub").respond(
            404, json={"message": "Not Found"}
        )

    # Per-repo endpoints
    for repo_resp in dataset["repos"]:
        repo_name = repo_resp["name"]
        default_branch = repo_resp["default_branch"]
        key = f"{org}/{repo_name}"

        # Branch protections — default branch
        bp_key = f"{key}/{default_branch}"
        if bp_key in dataset["branch_protections"]:
            router.get(
                f"/repos/{org}/{repo_name}/branches/{default_branch}/protection"
            ).respond(200, json=dataset["branch_protections"][bp_key])
        else:
            router.get(
                f"/repos/{org}/{repo_name}/branches/{default_branch}/protection"
            ).respond(404, json={"message": "Not Found"})

        # Other well-known branches — 404 unless explicitly set
        for branch in ["master", "develop", "staging", "production"]:
            bp_key2 = f"{key}/{branch}"
            if bp_key2 in dataset["branch_protections"]:
                router.get(
                    f"/repos/{org}/{repo_name}/branches/{branch}/protection"
                ).respond(200, json=dataset["branch_protections"][bp_key2])
            else:
                router.get(
                    f"/repos/{org}/{repo_name}/branches/{branch}/protection"
                ).respond(404, json={"message": "Not Found"})

        # Environments
        env_list = dataset["environments"].get(key, [])
        router.get(f"/repos/{org}/{repo_name}/environments").respond(
            200, json={"environments": env_list}
        )

        # Workflow files
        wf_files = dataset["workflow_files"].get(key, [])
        if wf_files:
            router.get(
                f"/repos/{org}/{repo_name}/contents/.github/workflows"
            ).respond(200, json=wf_files)
        else:
            router.get(
                f"/repos/{org}/{repo_name}/contents/.github/workflows"
            ).respond(404, json={"message": "Not Found"})

        # Workflow file contents
        for wf_file in wf_files:
            path = wf_file["path"]
            content = dataset["workflow_contents"].get(f"{key}/{path}", "")
            router.get(
                f"/repos/{org}/{repo_name}/contents/{path}"
            ).respond(200, text=content, headers={"Content-Type": "application/vnd.github.raw+json"})

        # Collaborators
        collabs = dataset["collaborators"].get(key, [])
        router.get(
            f"/repos/{org}/{repo_name}/collaborators"
        ).respond(200, json=collabs)

        # Rulesets
        rulesets = dataset["rulesets"].get(key, [])
        router.get(
            f"/repos/{org}/{repo_name}/rulesets"
        ).respond(200, json=rulesets)

        # Repo actions permissions
        repo_perms = dataset["repo_actions_permissions"].get(key, {})
        router.get(
            f"/repos/{org}/{repo_name}/actions/permissions"
        ).respond(200, json=repo_perms)


@pytest.fixture
def mock_org_factory():
    """Fixture providing the make_mock_org factory function."""
    return make_mock_org


@pytest.fixture
def wire_factory():
    """Fixture providing the wire_mock_org wiring function."""
    return wire_mock_org


# ------------------------------------------------------------------
# Helpers for asserting no secrets in output
# ------------------------------------------------------------------

def assert_no_secrets(text: str, token: str = FAKE_TOKEN) -> None:
    """Assert that a text blob contains no token patterns.

    Checks for:
      - The literal fake token
      - Any ghp_/ghs_/gho_/ghu_/gha_ prefixed strings
      - Bearer tokens
    """
    import re
    assert token not in text, f"Output contains the literal token"
    assert "ghp_" not in text, "Output contains ghp_ token pattern"
    assert "ghs_" not in text, "Output contains ghs_ token pattern"
    assert "Bearer" not in text, "Output contains Bearer token pattern"
    # Check for the token pattern used in tests
    matches = re.findall(r"gh[psoua]_[A-Za-z0-9_]{20,}", text)
    assert not matches, f"Output contains token-like patterns: {matches}"
