"""
Tests for ghostgates.collectors.environments
"""

from __future__ import annotations

import pytest
import httpx
import respx

from ghostgates.client.github_client import GitHubClient
from ghostgates.collectors.environments import (
    collect_environments,
    _parse_environment,
    _parse_reviewer,
    _parse_deployment_branch_policy,
)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

BASE_URL = "https://api.github.com"


def _rl_headers(remaining: int = 4999) -> dict:
    return {
        "x-ratelimit-remaining": str(remaining),
        "x-ratelimit-reset": "9999999999",
    }


@pytest.fixture
def mock_router():
    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        yield router


@pytest.fixture
async def client(mock_router) -> GitHubClient:
    c = GitHubClient(token="ghp_test123", base_url=BASE_URL, max_concurrent=5)
    yield c
    await c.close()


# ------------------------------------------------------------------
# Mock data
# ------------------------------------------------------------------

def _make_environment_response(
    name: str,
    *,
    reviewers: list[dict] | None = None,
    wait_timer: int = 0,
    protected_branches: bool = False,
    custom_branch_policies: bool = False,
    deployment_branch_policy: dict | None = "auto",
) -> dict:
    """Build a realistic GitHub environment API response."""
    protection_rules: list[dict] = []

    if reviewers:
        protection_rules.append({
            "type": "required_reviewers",
            "reviewers": reviewers,
        })

    if wait_timer > 0:
        protection_rules.append({
            "type": "wait_timer",
            "wait_timer": wait_timer,
        })

    if protected_branches or custom_branch_policies:
        protection_rules.append({"type": "branch_policy"})

    result: dict = {
        "name": name,
        "protection_rules": protection_rules,
    }

    if deployment_branch_policy == "auto":
        if protected_branches or custom_branch_policies:
            result["deployment_branch_policy"] = {
                "protected_branches": protected_branches,
                "custom_branch_policies": custom_branch_policies,
            }
        else:
            result["deployment_branch_policy"] = None
    else:
        result["deployment_branch_policy"] = deployment_branch_policy

    return result


# ==================================================================
# Tests: collect_environments (API integration)
# ==================================================================

@pytest.mark.asyncio
async def test_collect_environments_success(client, mock_router):
    """Collects and parses multiple environments."""
    mock_router.get("/repos/org/repo/environments").mock(
        return_value=httpx.Response(200, json={
            "total_count": 2,
            "environments": [
                _make_environment_response("production", wait_timer=15,
                    reviewers=[
                        {"type": "User", "reviewer": {"login": "alice", "id": 1}},
                    ],
                    protected_branches=True,
                ),
                _make_environment_response("staging"),
            ],
        }, headers=_rl_headers())
    )

    envs = await collect_environments(client, "org", "repo")
    assert len(envs) == 2
    assert envs[0].name == "production"
    assert envs[0].wait_timer == 15
    assert len(envs[0].reviewers) == 1
    assert envs[0].reviewers[0].login == "alice"
    assert envs[0].deployment_branch_policy.type == "protected"
    assert envs[1].name == "staging"


@pytest.mark.asyncio
async def test_collect_environments_empty(client, mock_router):
    """Returns empty list when repo has no environments."""
    mock_router.get("/repos/org/repo/environments").mock(
        return_value=httpx.Response(200, json={
            "total_count": 0, "environments": [],
        }, headers=_rl_headers())
    )

    envs = await collect_environments(client, "org", "repo")
    assert envs == []


@pytest.mark.asyncio
async def test_collect_environments_404(client, mock_router):
    """Returns empty list on 404."""
    mock_router.get("/repos/org/repo/environments").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
    )

    envs = await collect_environments(client, "org", "repo")
    assert envs == []


# ==================================================================
# Tests: _parse_environment (unit)
# ==================================================================

def test_parse_env_with_all_protections():
    """Full environment with reviewers, wait timer, branch policy."""
    raw = _make_environment_response(
        "production",
        reviewers=[
            {"type": "User", "reviewer": {"login": "alice", "id": 1}},
            {"type": "Team", "reviewer": {"slug": "security", "id": 42, "members_count": 5}},
        ],
        wait_timer=30,
        protected_branches=True,
    )
    env = _parse_environment(raw)
    assert env.name == "production"
    assert env.wait_timer == 30
    assert len(env.reviewers) == 2
    assert env.reviewers[0].type == "User"
    assert env.reviewers[0].login == "alice"
    assert env.reviewers[1].type == "Team"
    assert env.reviewers[1].login == "security"
    assert env.reviewers[1].member_count == 5
    assert env.deployment_branch_policy.type == "protected"


def test_parse_env_no_protections():
    """Environment with zero protections (any branch, no reviewers)."""
    raw = _make_environment_response("dev")
    env = _parse_environment(raw)
    assert env.name == "dev"
    assert env.wait_timer == 0
    assert env.reviewers == []
    assert env.deployment_branch_policy.type == "all"


def test_parse_env_custom_branch_policy():
    """Environment with custom branch policies."""
    raw = _make_environment_response("staging", custom_branch_policies=True)
    env = _parse_environment(raw)
    assert env.deployment_branch_policy.type == "selected"


def test_parse_env_wait_timer_only():
    """Wait timer without required reviewers."""
    raw = _make_environment_response("canary", wait_timer=10)
    env = _parse_environment(raw)
    assert env.wait_timer == 10
    assert env.reviewers == []


def test_parse_env_custom_protection_rule():
    """Custom deployment protection rule (external webhook)."""
    raw = {
        "name": "production",
        "protection_rules": [
            {
                "id": 99,
                "type": "custom",
                "app": {"slug": "policy-bot", "id": 123},
            }
        ],
        "deployment_branch_policy": None,
    }
    env = _parse_environment(raw)
    assert len(env.custom_rules) == 1
    assert env.custom_rules[0].app_slug == "policy-bot"
    assert env.custom_rules[0].timeout_minutes == 30  # default


def test_parse_env_raw_preserved():
    """The raw API response is preserved for evidence."""
    raw = _make_environment_response("test")
    env = _parse_environment(raw)
    assert env.raw == raw


# ==================================================================
# Tests: _parse_reviewer (unit)
# ==================================================================

def test_parse_reviewer_user():
    entry = {"type": "User", "reviewer": {"login": "bob", "id": 2}}
    r = _parse_reviewer(entry)
    assert r is not None
    assert r.type == "User"
    assert r.login == "bob"
    assert r.id == 2
    assert r.member_count is None


def test_parse_reviewer_team():
    entry = {"type": "Team", "reviewer": {"slug": "devops", "id": 10, "members_count": 8}}
    r = _parse_reviewer(entry)
    assert r is not None
    assert r.type == "Team"
    assert r.login == "devops"
    assert r.member_count == 8


def test_parse_reviewer_empty_reviewer():
    entry = {"type": "User", "reviewer": {}}
    r = _parse_reviewer(entry)
    assert r is None


def test_parse_reviewer_missing_reviewer():
    entry = {"type": "User"}
    r = _parse_reviewer(entry)
    assert r is None


# ==================================================================
# Tests: _parse_deployment_branch_policy (unit)
# ==================================================================

def test_deployment_policy_none():
    """null → all branches."""
    p = _parse_deployment_branch_policy(None)
    assert p.type == "all"


def test_deployment_policy_protected():
    p = _parse_deployment_branch_policy({"protected_branches": True, "custom_branch_policies": False})
    assert p.type == "protected"


def test_deployment_policy_custom():
    p = _parse_deployment_branch_policy({"protected_branches": False, "custom_branch_policies": True})
    assert p.type == "selected"


def test_deployment_policy_both_false():
    """Neither protected nor custom → none."""
    p = _parse_deployment_branch_policy({"protected_branches": False, "custom_branch_policies": False})
    assert p.type == "none"
