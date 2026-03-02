"""
Tests for ghostgates.collectors.org and ghostgates.collectors.repos

Uses respx to mock GitHub API responses. No live API calls.
"""

from __future__ import annotations

import pytest
import httpx
import respx

from ghostgates.client.github_client import GitHubClient
from ghostgates.collectors.org import collect_org_metadata
from ghostgates.collectors.repos import (
    collect_repos,
    collect_branch_protections,
    collect_collaborators,
    collect_rulesets,
    _parse_branch_protection,
    _highest_permission,
)
from ghostgates.models.gates import BranchProtection, Collaborator, Ruleset


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
# Mock response factories
# ------------------------------------------------------------------

def _make_repo(name: str, *, archived: bool = False, disabled: bool = False,
               default_branch: str = "main", fork: bool = False,
               visibility: str = "private") -> dict:
    """Generate a realistic GitHub repo API response dict."""
    return {
        "id": hash(name) % 100000,
        "name": name,
        "full_name": f"test-org/{name}",
        "default_branch": default_branch,
        "archived": archived,
        "disabled": disabled,
        "fork": fork,
        "visibility": visibility,
        "owner": {"login": "test-org"},
    }


def _make_branch_protection(
    *,
    reviews: int = 0,
    dismiss_stale: bool = False,
    codeowners: bool = False,
    enforce_admins: bool = False,
    status_checks: list[str] | None = None,
    strict: bool = False,
    restrict_pushes: bool = False,
    bypass_users: list[str] | None = None,
) -> dict:
    """Generate a realistic GitHub branch protection API response."""
    result: dict = {}

    if reviews > 0:
        pr_section: dict = {
            "required_approving_review_count": reviews,
            "dismiss_stale_reviews": dismiss_stale,
            "require_code_owner_reviews": codeowners,
            "dismissal_restrictions": {"users": [], "teams": []},
        }
        if bypass_users:
            pr_section["bypass_pull_request_allowances"] = {
                "users": [{"login": u} for u in bypass_users],
                "teams": [],
                "apps": [],
            }
        else:
            pr_section["bypass_pull_request_allowances"] = {
                "users": [], "teams": [], "apps": [],
            }
        result["required_pull_request_reviews"] = pr_section

    result["enforce_admins"] = {"enabled": enforce_admins}

    if status_checks is not None:
        result["required_status_checks"] = {
            "strict": strict,
            "contexts": status_checks,
        }

    if restrict_pushes:
        result["restrictions"] = {"users": [], "teams": [], "apps": []}
    else:
        result["restrictions"] = None

    result["required_linear_history"] = {"enabled": False}
    result["allow_force_pushes"] = {"enabled": False}
    result["allow_deletions"] = {"enabled": False}
    result["lock_branch"] = {"enabled": False}
    result["required_signatures"] = {"enabled": False}

    return result


def _make_collaborator(login: str, cid: int, *, admin: bool = False,
                        maintain: bool = False, push: bool = False,
                        triage: bool = False, pull: bool = True) -> dict:
    """Generate a realistic GitHub collaborator API response."""
    return {
        "login": login,
        "id": cid,
        "permissions": {
            "admin": admin,
            "maintain": maintain,
            "push": push,
            "triage": triage,
            "pull": pull,
        },
        "role_name": "",
    }


def _make_ruleset(name: str, enforcement: str = "active",
                   target: str = "branch") -> dict:
    return {
        "id": hash(name) % 100000,
        "name": name,
        "enforcement": enforcement,
        "target": target,
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [{"type": "pull_request", "parameters": {"required_approving_review_count": 1}}],
        "bypass_actors": [],
    }


# ==================================================================
# Tests: collect_org_metadata
# ==================================================================

@pytest.mark.asyncio
async def test_collect_org_metadata_success(client, mock_router):
    """Collects both Actions permissions and OIDC template."""
    mock_router.get("/orgs/test-org/actions/permissions").mock(
        return_value=httpx.Response(200, json={
            "enabled_repositories": "all",
            "allowed_actions": "selected",
        }, headers=_rl_headers())
    )
    mock_router.get("/orgs/test-org/actions/oidc/customization/sub").mock(
        return_value=httpx.Response(200, json={
            "include_claim_keys": ["repo", "ref"],
        }, headers=_rl_headers())
    )

    result = await collect_org_metadata(client, "test-org")
    assert result["actions_permissions"]["enabled_repositories"] == "all"
    assert result["oidc_template"]["include_claim_keys"] == ["repo", "ref"]


@pytest.mark.asyncio
async def test_collect_org_metadata_no_oidc(client, mock_router):
    """OIDC template is None when not configured (404)."""
    mock_router.get("/orgs/test-org/actions/permissions").mock(
        return_value=httpx.Response(200, json={
            "enabled_repositories": "all",
        }, headers=_rl_headers())
    )
    mock_router.get("/orgs/test-org/actions/oidc/customization/sub").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
    )

    result = await collect_org_metadata(client, "test-org")
    assert result["actions_permissions"]["enabled_repositories"] == "all"
    assert result["oidc_template"] is None


@pytest.mark.asyncio
async def test_collect_org_metadata_permissions_fail(client, mock_router):
    """If Actions permissions fail, still returns with empty dict."""
    mock_router.get("/orgs/test-org/actions/permissions").mock(
        return_value=httpx.Response(403, json={
            "message": "Must have admin access",
        }, headers=_rl_headers())
    )
    mock_router.get("/orgs/test-org/actions/oidc/customization/sub").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
    )

    result = await collect_org_metadata(client, "test-org")
    assert result["actions_permissions"] == {}
    assert result["oidc_template"] is None


# ==================================================================
# Tests: collect_repos
# ==================================================================

@pytest.mark.asyncio
async def test_collect_repos_filters_archived(client, mock_router):
    """Archived and disabled repos are excluded."""
    mock_router.get("/orgs/test-org/repos").mock(
        return_value=httpx.Response(200, json=[
            _make_repo("active-repo"),
            _make_repo("old-repo", archived=True),
            _make_repo("disabled-repo", disabled=True),
            _make_repo("another-active"),
        ], headers=_rl_headers())
    )

    repos = await collect_repos(client, "test-org")
    names = [r["name"] for r in repos]
    assert "active-repo" in names
    assert "another-active" in names
    assert "old-repo" not in names
    assert "disabled-repo" not in names
    assert len(repos) == 2


@pytest.mark.asyncio
async def test_collect_repos_all_active(client, mock_router):
    """When no repos are archived, all are returned."""
    mock_router.get("/orgs/test-org/repos").mock(
        return_value=httpx.Response(200, json=[
            _make_repo("repo1"),
            _make_repo("repo2"),
        ], headers=_rl_headers())
    )

    repos = await collect_repos(client, "test-org")
    assert len(repos) == 2


# ==================================================================
# Tests: collect_branch_protections
# ==================================================================

@pytest.mark.asyncio
async def test_branch_protection_with_reviews(client, mock_router):
    """Parses a branch protection with required reviews."""
    mock_router.get("/repos/org/repo/branches/main/protection").mock(
        return_value=httpx.Response(200, json=_make_branch_protection(
            reviews=2, dismiss_stale=True, codeowners=True, enforce_admins=True,
        ), headers=_rl_headers())
    )
    # Other branches return 404
    for branch in ["master", "develop", "staging", "production"]:
        mock_router.get(f"/repos/org/repo/branches/{branch}/protection").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
        )

    protections = await collect_branch_protections(client, "org", "repo", "main")
    assert len(protections) == 1
    bp = protections[0]
    assert bp.branch == "main"
    assert bp.required_approving_review_count == 2
    assert bp.dismiss_stale_reviews is True
    assert bp.require_code_owner_reviews is True
    assert bp.enforce_admins is True


@pytest.mark.asyncio
async def test_branch_protection_404_returns_empty(client, mock_router):
    """No protections on any branch returns empty list."""
    for branch in ["main", "master", "develop", "staging", "production"]:
        mock_router.get(f"/repos/org/repo/branches/{branch}/protection").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
        )

    protections = await collect_branch_protections(client, "org", "repo", "main")
    assert protections == []


@pytest.mark.asyncio
async def test_branch_protection_multiple_branches(client, mock_router):
    """Can collect protection from multiple branches."""
    mock_router.get("/repos/org/repo/branches/main/protection").mock(
        return_value=httpx.Response(200, json=_make_branch_protection(reviews=1), headers=_rl_headers())
    )
    mock_router.get("/repos/org/repo/branches/develop/protection").mock(
        return_value=httpx.Response(200, json=_make_branch_protection(reviews=1, enforce_admins=True), headers=_rl_headers())
    )
    for branch in ["master", "staging", "production"]:
        mock_router.get(f"/repos/org/repo/branches/{branch}/protection").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
        )

    protections = await collect_branch_protections(client, "org", "repo", "main")
    assert len(protections) == 2
    branches = {bp.branch for bp in protections}
    assert branches == {"main", "develop"}


@pytest.mark.asyncio
async def test_branch_protection_deduplicates_default(client, mock_router):
    """If default_branch is 'main', don't check 'main' twice."""
    # Should only get ONE call to /branches/main/protection
    route = mock_router.get("/repos/org/repo/branches/main/protection").mock(
        return_value=httpx.Response(200, json=_make_branch_protection(reviews=1), headers=_rl_headers())
    )
    for branch in ["master", "develop", "staging", "production"]:
        mock_router.get(f"/repos/org/repo/branches/{branch}/protection").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
        )

    protections = await collect_branch_protections(client, "org", "repo", "main")
    assert len(protections) == 1
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_branch_protection_bypass_actors_parsed(client, mock_router):
    """Bypass allowances are extracted as typed strings."""
    mock_router.get("/repos/org/repo/branches/main/protection").mock(
        return_value=httpx.Response(200, json=_make_branch_protection(
            reviews=1, bypass_users=["admin-user"],
        ), headers=_rl_headers())
    )
    for branch in ["master", "develop", "staging", "production"]:
        mock_router.get(f"/repos/org/repo/branches/{branch}/protection").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
        )

    protections = await collect_branch_protections(client, "org", "repo", "main")
    assert "user:admin-user" in protections[0].bypass_pull_request_allowances


# ==================================================================
# Tests: _parse_branch_protection (unit, no API)
# ==================================================================

def test_parse_minimal_protection():
    """Parse a protection response with minimal fields."""
    raw = {
        "enforce_admins": {"enabled": False},
        "restrictions": None,
        "required_linear_history": {"enabled": False},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "lock_branch": {"enabled": False},
        "required_signatures": {"enabled": False},
    }
    bp = _parse_branch_protection("main", raw)
    assert bp.branch == "main"
    assert bp.required_approving_review_count == 0
    assert bp.enforce_admins is False
    assert bp.restrict_pushes is False


def test_parse_full_protection():
    """Parse a fully-configured protection response."""
    raw = _make_branch_protection(
        reviews=3, dismiss_stale=True, codeowners=True,
        enforce_admins=True, status_checks=["ci/build", "ci/lint"],
        strict=True, restrict_pushes=True,
    )
    bp = _parse_branch_protection("release", raw)
    assert bp.branch == "release"
    assert bp.required_approving_review_count == 3
    assert bp.dismiss_stale_reviews is True
    assert bp.require_code_owner_reviews is True
    assert bp.enforce_admins is True
    assert bp.required_status_checks == ["ci/build", "ci/lint"]
    assert bp.require_status_checks_strict is True
    assert bp.restrict_pushes is True
    assert bp.raw == raw


def test_parse_protection_missing_sections():
    """Handles missing sections gracefully (no crash)."""
    raw = {}  # completely empty
    bp = _parse_branch_protection("main", raw)
    assert bp.branch == "main"
    assert bp.required_approving_review_count == 0
    assert bp.enforce_admins is False


# ==================================================================
# Tests: collect_collaborators
# ==================================================================

@pytest.mark.asyncio
async def test_collect_collaborators_maps_permissions(client, mock_router):
    """Permission levels are correctly determined from GitHub API format."""
    mock_router.get("/repos/org/repo/collaborators").mock(
        return_value=httpx.Response(200, json=[
            _make_collaborator("alice", 1, admin=True, push=True, pull=True),
            _make_collaborator("bob", 2, push=True, pull=True),
            _make_collaborator("carol", 3, maintain=True, push=True, pull=True),
            _make_collaborator("dave", 4, triage=True, pull=True),
            _make_collaborator("eve", 5, pull=True),
        ], headers=_rl_headers())
    )

    collabs = await collect_collaborators(client, "org", "repo")
    assert len(collabs) == 5

    by_login = {c.login: c for c in collabs}
    assert by_login["alice"].permission == "admin"
    assert by_login["bob"].permission == "write"
    assert by_login["carol"].permission == "maintain"
    assert by_login["dave"].permission == "triage"
    assert by_login["eve"].permission == "read"


@pytest.mark.asyncio
async def test_collect_collaborators_empty(client, mock_router):
    """Empty collaborator list returns empty."""
    mock_router.get("/repos/org/repo/collaborators").mock(
        return_value=httpx.Response(200, json=[], headers=_rl_headers())
    )

    collabs = await collect_collaborators(client, "org", "repo")
    assert collabs == []


# ==================================================================
# Tests: _highest_permission (unit)
# ==================================================================

def test_highest_permission_admin():
    assert _highest_permission({"admin": True, "push": True, "pull": True}) == "admin"

def test_highest_permission_maintain():
    assert _highest_permission({"maintain": True, "push": True, "pull": True}) == "maintain"

def test_highest_permission_push():
    assert _highest_permission({"push": True, "pull": True}) == "write"

def test_highest_permission_triage():
    assert _highest_permission({"triage": True, "pull": True}) == "triage"

def test_highest_permission_pull_only():
    assert _highest_permission({"pull": True}) == "read"

def test_highest_permission_empty_with_role_name():
    assert _highest_permission({}, "write") == "write"

def test_highest_permission_empty_default():
    assert _highest_permission({}) == "read"


# ==================================================================
# Tests: collect_rulesets
# ==================================================================

@pytest.mark.asyncio
async def test_collect_rulesets_success(client, mock_router):
    """Parses rulesets from API response."""
    mock_router.get("/repos/org/repo/rulesets").mock(
        return_value=httpx.Response(200, json=[
            _make_ruleset("main-protection", enforcement="active"),
            _make_ruleset("tag-rules", enforcement="evaluate", target="tag"),
        ], headers=_rl_headers())
    )

    rulesets = await collect_rulesets(client, "org", "repo")
    assert len(rulesets) == 2
    assert rulesets[0].name == "main-protection"
    assert rulesets[0].enforcement == "active"
    assert rulesets[1].name == "tag-rules"
    assert rulesets[1].enforcement == "evaluate"
    assert rulesets[1].target == "tag"


@pytest.mark.asyncio
async def test_collect_rulesets_404_empty(client, mock_router):
    """Returns empty when rulesets not available (404)."""
    mock_router.get("/repos/org/repo/rulesets").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
    )

    rulesets = await collect_rulesets(client, "org", "repo")
    assert rulesets == []


@pytest.mark.asyncio
async def test_collect_rulesets_empty_list(client, mock_router):
    """Returns empty when org has rulesets feature but repo has none."""
    mock_router.get("/repos/org/repo/rulesets").mock(
        return_value=httpx.Response(200, json=[], headers=_rl_headers())
    )

    rulesets = await collect_rulesets(client, "org", "repo")
    assert rulesets == []
