"""
Tests for ghostgates.client.github_client

Uses respx to mock httpx requests. No live API calls.
"""

from __future__ import annotations

import asyncio
import pytest
import httpx
import respx

from ghostgates.client.github_client import (
    GitHubClient,
    GitHubClientError,
    _parse_link_next,
    _scrub,
    _validate_name,
)


async def _noop(*args, **kwargs):
    """Instant async function used to replace asyncio.sleep in tests."""
    return None


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def base_url() -> str:
    return "https://api.github.com"


@pytest.fixture
def mock_router(base_url: str):
    """Activate a respx router scoped to each test."""
    with respx.mock(base_url=base_url, assert_all_called=False) as router:
        yield router


@pytest.fixture
async def client(base_url: str, mock_router) -> GitHubClient:
    """Provide a GitHubClient wired to the mock router."""
    c = GitHubClient(token="ghp_test_token_abc123", base_url=base_url, max_concurrent=5)
    yield c
    await c.close()


# ------------------------------------------------------------------
# Helper: standard rate limit headers
# ------------------------------------------------------------------

def _rl_headers(remaining: int = 4999, reset: int = 9999999999) -> dict:
    return {
        "x-ratelimit-remaining": str(remaining),
        "x-ratelimit-reset": str(reset),
    }


# ------------------------------------------------------------------
# Tests: basic GET
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_returns_json(client: GitHubClient, mock_router):
    """Successful GET returns parsed JSON dict."""
    mock_router.get("/user").mock(
        return_value=httpx.Response(200, json={"login": "testuser"}, headers=_rl_headers())
    )
    result = await client.get("/user")
    assert result == {"login": "testuser"}


@pytest.mark.asyncio
async def test_get_returns_list(client: GitHubClient, mock_router):
    """Successful GET returning a list works."""
    mock_router.get("/repos").mock(
        return_value=httpx.Response(200, json=[{"name": "a"}, {"name": "b"}], headers=_rl_headers())
    )
    result = await client.get("/repos")
    assert isinstance(result, list)
    assert len(result) == 2


# ------------------------------------------------------------------
# Tests: 404 handling
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_branch_protection_404_returns_none(client: GitHubClient, mock_router):
    """get_branch_protection returns None when branch has no protection."""
    mock_router.get("/repos/org/repo/branches/main/protection").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
    )
    result = await client.get_branch_protection("org", "repo", "main")
    assert result is None


@pytest.mark.asyncio
async def test_get_oidc_template_404_returns_none(client: GitHubClient, mock_router):
    """get_oidc_template returns None when not configured."""
    mock_router.get("/orgs/org/actions/oidc/customization/sub").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
    )
    result = await client.get_oidc_template("org")
    assert result is None


@pytest.mark.asyncio
async def test_list_workflow_files_404_returns_empty(client: GitHubClient, mock_router):
    """list_workflow_files returns [] if no .github/workflows/ directory."""
    mock_router.get("/repos/org/repo/contents/.github/workflows").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
    )
    result = await client.list_workflow_files("org", "repo")
    assert result == []


@pytest.mark.asyncio
async def test_list_environments_404_returns_empty(client: GitHubClient, mock_router):
    """list_environments returns [] for repos without environments."""
    mock_router.get("/repos/org/repo/environments").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
    )
    result = await client.list_environments("org", "repo")
    assert result == []


@pytest.mark.asyncio
async def test_list_rulesets_404_returns_empty(client: GitHubClient, mock_router):
    """list_rulesets returns [] when not available."""
    mock_router.get("/repos/org/repo/rulesets").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
    )
    result = await client.list_rulesets("org", "repo")
    assert result == []


# ------------------------------------------------------------------
# Tests: pagination
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pagination_follows_link_header(client: GitHubClient, mock_router, base_url: str):
    """get_paginated correctly parses and would follow Link: rel='next'.

    Note: respx with base_url cannot match absolute URLs from Link headers,
    so we test that single-page pagination works correctly and that link
    parsing is correct (tested separately in test_parse_link_next_*).
    """
    # Single page with no next link — verifies basic pagination flow
    mock_router.get("/orgs/org/repos").mock(
        return_value=httpx.Response(
            200,
            json=[{"name": "repo1"}, {"name": "repo2"}],
            headers=_rl_headers(),  # no Link header = single page
        )
    )

    result = await client.list_org_repos("org")
    assert len(result) == 2
    assert result[0]["name"] == "repo1"
    assert result[1]["name"] == "repo2"


@pytest.mark.asyncio
async def test_pagination_unwraps_environments(client: GitHubClient, mock_router):
    """list_environments unwraps the 'environments' key from response."""
    mock_router.get("/repos/org/repo/environments").mock(
        return_value=httpx.Response(
            200,
            json={
                "total_count": 2,
                "environments": [
                    {"name": "production"},
                    {"name": "staging"},
                ],
            },
            headers=_rl_headers(),
        )
    )
    result = await client.list_environments("org", "repo")
    assert len(result) == 2
    assert result[0]["name"] == "production"


# ------------------------------------------------------------------
# Tests: retry on 5xx
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_retry_on_500(client: GitHubClient, mock_router, monkeypatch):
    """Client retries on 5xx and succeeds on later attempt."""
    # Patch sleep to be instant
    monkeypatch.setattr(asyncio, "sleep", _noop)
    route = mock_router.get("/test").mock(
        side_effect=[
            httpx.Response(500, headers=_rl_headers()),
            httpx.Response(500, headers=_rl_headers()),
            httpx.Response(200, json={"ok": True}, headers=_rl_headers()),
        ]
    )
    result = await client.get("/test")
    assert result == {"ok": True}
    assert route.call_count == 3


@pytest.mark.asyncio
async def test_retry_exhausted_raises(client: GitHubClient, mock_router, monkeypatch):
    """Client raises after max retries on persistent 5xx."""
    monkeypatch.setattr(asyncio, "sleep", _noop)
    mock_router.get("/fail").mock(
        return_value=httpx.Response(502, headers=_rl_headers())
    )
    with pytest.raises(GitHubClientError, match="502"):
        await client.get("/fail")


# ------------------------------------------------------------------
# Tests: rate limit handling
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_permission_403_raises_immediately(client: GitHubClient, mock_router):
    """A real 403 (not rate limit) raises without retry."""
    mock_router.get("/forbidden").mock(
        return_value=httpx.Response(
            403,
            json={"message": "Must have admin access to repository"},
            headers=_rl_headers(remaining=4000),
        )
    )
    with pytest.raises(GitHubClientError, match="403"):
        await client.get("/forbidden")


# ------------------------------------------------------------------
# Tests: token safety
# ------------------------------------------------------------------

def test_repr_masks_token():
    """repr never shows the token."""
    c = GitHubClient.__new__(GitHubClient)
    c._token = "ghp_supersecret123"
    c._base_url = "https://api.github.com"
    r = repr(c)
    assert "ghp_supersecret123" not in r
    assert "***" in r


def test_scrub_removes_ghp_tokens():
    assert "ghp_" not in _scrub("error with ghp_abc123xyz token")
    assert "***" in _scrub("error with ghp_abc123xyz token")


def test_scrub_removes_github_pat():
    assert "github_pat_" not in _scrub("bad github_pat_abc123 here")
    assert "***" in _scrub("bad github_pat_abc123 here")


def test_scrub_removes_bearer():
    assert "mysecret" not in _scrub("Bearer mysecret")
    assert "Bearer ***" in _scrub("Bearer mysecret")


def test_scrub_preserves_safe_strings():
    safe = "just a normal error message"
    assert _scrub(safe) == safe


@pytest.mark.asyncio
async def test_error_message_does_not_contain_token(client: GitHubClient, mock_router):
    """Exceptions from failed requests must not leak the token."""
    mock_router.get("/error").mock(
        return_value=httpx.Response(
            422,
            json={"message": "Validation failed"},
            headers=_rl_headers(),
        )
    )
    with pytest.raises(GitHubClientError) as exc_info:
        await client.get("/error")
    error_str = str(exc_info.value)
    assert "ghp_test_token_abc123" not in error_str


# ------------------------------------------------------------------
# Tests: input validation
# ------------------------------------------------------------------

def test_validate_name_accepts_valid():
    _validate_name("my-org")
    _validate_name("repo.name")
    _validate_name("under_score")
    _validate_name("CamelCase")
    _validate_name("123numeric")


def test_validate_name_rejects_invalid():
    with pytest.raises(ValueError):
        _validate_name("bad name")
    with pytest.raises(ValueError):
        _validate_name("bad/slash")
    with pytest.raises(ValueError):
        _validate_name("")
    with pytest.raises(ValueError):
        _validate_name("bad;semicolon")


# ------------------------------------------------------------------
# Tests: link header parsing
# ------------------------------------------------------------------

def test_parse_link_next_empty():
    assert _parse_link_next("") is None


def test_parse_link_next_single():
    hdr = '<https://api.github.com/repos?page=2>; rel="next"'
    assert _parse_link_next(hdr) == "https://api.github.com/repos?page=2"


def test_parse_link_next_with_prev():
    hdr = '<https://x.com/?page=1>; rel="prev", <https://x.com/?page=3>; rel="next"'
    assert _parse_link_next(hdr) == "https://x.com/?page=3"


def test_parse_link_next_no_next():
    hdr = '<https://x.com/?page=1>; rel="prev", <https://x.com/?page=2>; rel="last"'
    assert _parse_link_next(hdr) is None


# ------------------------------------------------------------------
# Tests: convenience methods
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_branch_protection_success(client: GitHubClient, mock_router):
    """get_branch_protection returns parsed protection when it exists."""
    mock_router.get("/repos/org/repo/branches/main/protection").mock(
        return_value=httpx.Response(
            200,
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 2,
                    "dismiss_stale_reviews": True,
                },
                "enforce_admins": {"enabled": True},
            },
            headers=_rl_headers(),
        )
    )
    result = await client.get_branch_protection("org", "repo", "main")
    assert result is not None
    assert "required_pull_request_reviews" in result


@pytest.mark.asyncio
async def test_list_collaborators(client: GitHubClient, mock_router):
    mock_router.get("/repos/org/repo/collaborators").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"login": "alice", "id": 1, "permissions": {"admin": True}},
                {"login": "bob", "id": 2, "permissions": {"push": True}},
            ],
            headers=_rl_headers(),
        )
    )
    result = await client.list_collaborators("org", "repo")
    assert len(result) == 2
    assert result[0]["login"] == "alice"


@pytest.mark.asyncio
async def test_get_raw_returns_text(client: GitHubClient, mock_router):
    """get_raw returns string content (for YAML files)."""
    yaml_content = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest"
    mock_router.get("/repos/org/repo/contents/.github/workflows/ci.yml").mock(
        return_value=httpx.Response(
            200,
            text=yaml_content,
            headers=_rl_headers(),
        )
    )
    result = await client.get_workflow_content("org", "repo", ".github/workflows/ci.yml")
    assert "name: CI" in result
    assert isinstance(result, str)
