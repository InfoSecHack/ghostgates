"""
ghostgates/client/github_client.py

Async GitHub REST API client with rate limiting, pagination, and retry.

Security invariants:
  - The PAT is NEVER logged, stored, or included in exceptions.
  - All error messages are scrubbed before propagation.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

from ghostgates.client.rate_limiter import RateLimiter
from ghostgates.config import (
    API_BASE_URL,
    API_VERSION,
    MAX_CONCURRENT_DEFAULT,
    ORG_NAME_PATTERN,
    USER_AGENT,
)

logger = logging.getLogger("ghostgates.client")

_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 1.0  # seconds — doubled on each retry

# Matches rel="next" in Link headers
_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


class GitHubClientError(Exception):
    """Raised for non-retryable GitHub API errors."""


class GitHubClient:
    """Rate-limited async GitHub API client.

    Usage::

        async with GitHubClient(token="ghp_...") as client:
            repos = await client.list_org_repos("my-org")
    """

    def __init__(
        self,
        token: str,
        base_url: str = API_BASE_URL,
        max_concurrent: int = MAX_CONCURRENT_DEFAULT,
    ) -> None:
        if not token:
            raise ValueError("GitHub token must not be empty")
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._rate_limiter = RateLimiter(max_concurrent=max_concurrent)
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": USER_AGENT,
            },
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=True,
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> GitHubClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying httpx client."""
        await self._client.aclose()

    # ------------------------------------------------------------------
    # repr — NEVER expose the token
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"GitHubClient(base_url={self._base_url!r}, token=***)"

    # ------------------------------------------------------------------
    # Core request methods
    # ------------------------------------------------------------------

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> dict | list:
        """GET a single page and return parsed JSON.

        Rate-limiting and retries are handled transparently.
        """
        return await self._request("GET", path, params=params)

    async def get_paginated(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        per_page: int = 100,
    ) -> list[dict]:
        """GET with automatic pagination — follows ``Link: rel="next"`` headers.

        Returns a flat list aggregated from all pages.
        """
        params = dict(params or {})
        params.setdefault("per_page", per_page)

        results: list[dict] = []
        url: str | None = path

        while url is not None:
            # For absolute URLs (from Link header), use _request_url
            if url.startswith("http"):
                data, next_url = await self._request_url_paginated(url)
            else:
                data, next_url = await self._request_paginated(url, params)
                # After the first page, params are embedded in the Link URL
                params = None  # type: ignore[assignment]

            if isinstance(data, list):
                results.extend(data)
            elif isinstance(data, dict):
                # Some endpoints wrap results: {"total_count": N, "items": [...]}
                for key in ("items", "repositories", "environments", "workflow_runs"):
                    if key in data and isinstance(data[key], list):
                        results.extend(data[key])
                        break
                else:
                    # Single object, not paginated — shouldn't happen but be safe
                    results.append(data)

            url = next_url

        return results

    async def get_raw(self, path: str) -> str:
        """GET and return the response body as raw text (for YAML files)."""
        response = await self._raw_request("GET", path, accept="application/vnd.github.raw+json")
        return response.text

    # ------------------------------------------------------------------
    # Convenience methods (thin wrappers)
    # ------------------------------------------------------------------

    async def list_org_repos(self, org: str) -> list[dict]:
        """List all repositories in an organization."""
        _validate_name(org)
        return await self.get_paginated(f"/orgs/{org}/repos", {"type": "all"})

    async def get_branch_protection(
        self, owner: str, repo: str, branch: str
    ) -> dict | None:
        """Get branch protection rules. Returns ``None`` if unprotected (404)."""
        _validate_name(owner)
        _validate_name(repo)
        try:
            result = await self.get(f"/repos/{owner}/{repo}/branches/{branch}/protection")
            return result if isinstance(result, dict) else None
        except GitHubClientError as exc:
            if "404" in str(exc):
                return None
            raise

    async def list_environments(self, owner: str, repo: str) -> list[dict]:
        """List all environments for a repository."""
        _validate_name(owner)
        _validate_name(repo)
        try:
            data = await self.get(f"/repos/{owner}/{repo}/environments")
            if isinstance(data, dict) and "environments" in data:
                return data["environments"]
            if isinstance(data, list):
                return data
            return []
        except GitHubClientError as exc:
            if "404" in str(exc):
                return []
            raise

    async def get_environment(self, owner: str, repo: str, env_name: str) -> dict:
        """Get a specific environment's configuration."""
        _validate_name(owner)
        _validate_name(repo)
        result = await self.get(f"/repos/{owner}/{repo}/environments/{env_name}")
        return result if isinstance(result, dict) else {}

    async def list_collaborators(self, owner: str, repo: str) -> list[dict]:
        """List collaborators with their permission levels."""
        _validate_name(owner)
        _validate_name(repo)
        return await self.get_paginated(
            f"/repos/{owner}/{repo}/collaborators", {"affiliation": "all"}
        )

    async def get_workflow_content(self, owner: str, repo: str, path: str) -> str:
        """Fetch raw workflow YAML content from the default branch."""
        _validate_name(owner)
        _validate_name(repo)
        return await self.get_raw(f"/repos/{owner}/{repo}/contents/{path}")

    async def list_workflow_files(self, owner: str, repo: str) -> list[dict]:
        """List files in .github/workflows/ directory."""
        _validate_name(owner)
        _validate_name(repo)
        try:
            result = await self.get(f"/repos/{owner}/{repo}/contents/.github/workflows")
            if isinstance(result, list):
                return result
            return []
        except GitHubClientError as exc:
            if "404" in str(exc):
                return []  # No workflows directory
            raise

    async def get_org_actions_permissions(self, org: str) -> dict:
        """Get organization-level Actions permissions."""
        _validate_name(org)
        result = await self.get(f"/orgs/{org}/actions/permissions")
        return result if isinstance(result, dict) else {}

    async def get_repo_actions_permissions(self, owner: str, repo: str) -> dict:
        """Get repository-level Actions permissions (general + workflow).

        Merges two endpoints:
          /repos/{owner}/{repo}/actions/permissions → enabled, allowed_actions
          /repos/{owner}/{repo}/actions/permissions/workflow → default_workflow_permissions, can_approve_pull_request_reviews
        """
        _validate_name(owner)
        _validate_name(repo)
        merged: dict = {}
        # General actions permissions
        try:
            general = await self.get(f"/repos/{owner}/{repo}/actions/permissions")
            if isinstance(general, dict):
                merged.update(general)
        except GitHubClientError as exc:
            if "403" not in str(exc):
                raise
        # Workflow-specific permissions (separate endpoint)
        try:
            workflow = await self.get(f"/repos/{owner}/{repo}/actions/permissions/workflow")
            if isinstance(workflow, dict):
                merged.update(workflow)
        except GitHubClientError as exc:
            if "403" not in str(exc):
                raise
        return merged

    async def list_rulesets(self, owner: str, repo: str) -> list[dict]:
        """List repository rulesets. Returns empty list if not available."""
        _validate_name(owner)
        _validate_name(repo)
        try:
            return await self.get_paginated(f"/repos/{owner}/{repo}/rulesets")
        except GitHubClientError as exc:
            if "404" in str(exc):
                return []
            raise

    async def get_oidc_template(self, org: str) -> dict | None:
        """Get OIDC subject claim customization template. None if not configured."""
        _validate_name(org)
        try:
            result = await self.get(
                f"/orgs/{org}/actions/oidc/customization/sub"
            )
            return result if isinstance(result, dict) else None
        except GitHubClientError as exc:
            if "404" in str(exc):
                return None
            raise

    # ------------------------------------------------------------------
    # Internal: request with retries + rate limiting
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> dict | list:
        """Execute a request with rate limiting and retry logic."""
        last_exc: Exception | None = None

        for attempt in range(1, _MAX_RETRIES + 1):
            await self._rate_limiter.acquire()
            try:
                response = await self._client.request(method, path, params=params)
                self._rate_limiter.update_from_headers(dict(response.headers))

                # Rate-limited — back off and retry
                if response.status_code in (403, 429):
                    retry_after_hdr = response.headers.get("retry-after", "")
                    # Distinguish between rate limit 403 and permission 403
                    if response.status_code == 403 and not retry_after_hdr:
                        body = _safe_json(response)
                        msg = body.get("message", "") if isinstance(body, dict) else ""
                        if "rate limit" not in msg.lower() and "abuse" not in msg.lower():
                            # Real 403 (permission denied), not rate limit
                            raise GitHubClientError(
                                f"403 Forbidden: {_scrub(msg)} (path={path})"
                            )
                    await self._rate_limiter.handle_rate_limit(
                        response.status_code, dict(response.headers)
                    )
                    self._rate_limiter.release()
                    continue

                # 404 — raise so callers that expect None can catch it
                if response.status_code == 404:
                    self._rate_limiter.release()
                    raise GitHubClientError(f"404 Not Found (path={path})")

                # 5xx — retry
                if response.status_code >= 500:
                    wait = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                    logger.warning(
                        "Server error %d on %s (attempt %d/%d), retrying in %.1fs",
                        response.status_code, path, attempt, _MAX_RETRIES, wait,
                    )
                    self._rate_limiter.release()
                    last_exc = GitHubClientError(
                        f"{response.status_code} Server Error (path={path})"
                    )
                    await asyncio.sleep(wait)
                    continue

                # Other client errors
                if response.status_code >= 400:
                    body = _safe_json(response)
                    msg = body.get("message", "") if isinstance(body, dict) else ""
                    self._rate_limiter.release()
                    raise GitHubClientError(
                        f"{response.status_code} {_scrub(msg)} (path={path})"
                    )

                # Success
                self._rate_limiter.release()
                # Reset secondary hit count on success
                self._rate_limiter._secondary_hit_count = 0
                return response.json()

            except httpx.HTTPError as exc:
                self._rate_limiter.release()
                last_exc = GitHubClientError(f"HTTP error: {_scrub(str(exc))} (path={path})")
                if attempt < _MAX_RETRIES:
                    wait = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                    logger.warning(
                        "HTTP error on %s (attempt %d/%d): %s, retrying in %.1fs",
                        path, attempt, _MAX_RETRIES, _scrub(str(exc)), wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise last_exc from None

        raise last_exc or GitHubClientError(f"Max retries exceeded (path={path})")

    async def _request_paginated(
        self,
        path: str,
        params: dict[str, Any] | None,
    ) -> tuple[dict | list, str | None]:
        """Single page request that also returns the next URL from Link header."""
        last_exc: Exception | None = None

        for attempt in range(1, _MAX_RETRIES + 1):
            await self._rate_limiter.acquire()
            try:
                response = await self._client.request("GET", path, params=params)
                self._rate_limiter.update_from_headers(dict(response.headers))

                if response.status_code in (403, 429):
                    await self._rate_limiter.handle_rate_limit(
                        response.status_code, dict(response.headers)
                    )
                    self._rate_limiter.release()
                    continue

                if response.status_code == 404:
                    self._rate_limiter.release()
                    raise GitHubClientError(f"404 Not Found (path={path})")

                if response.status_code >= 500:
                    wait = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                    self._rate_limiter.release()
                    last_exc = GitHubClientError(
                        f"{response.status_code} Server Error (path={path})"
                    )
                    await asyncio.sleep(wait)
                    continue

                if response.status_code >= 400:
                    body = _safe_json(response)
                    msg = body.get("message", "") if isinstance(body, dict) else ""
                    self._rate_limiter.release()
                    raise GitHubClientError(
                        f"{response.status_code} {_scrub(msg)} (path={path})"
                    )

                self._rate_limiter.release()
                self._rate_limiter._secondary_hit_count = 0
                next_url = _parse_link_next(response.headers.get("link", ""))
                return response.json(), next_url

            except httpx.HTTPError as exc:
                self._rate_limiter.release()
                last_exc = GitHubClientError(f"HTTP error: {_scrub(str(exc))} (path={path})")
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(_RETRY_BACKOFF_BASE * (2 ** (attempt - 1)))
                    continue
                raise last_exc from None

        raise last_exc or GitHubClientError(f"Max retries exceeded (path={path})")

    async def _request_url_paginated(
        self,
        url: str,
    ) -> tuple[dict | list, str | None]:
        """Like _request_paginated but for absolute URLs from Link headers."""
        last_exc: Exception | None = None

        for attempt in range(1, _MAX_RETRIES + 1):
            await self._rate_limiter.acquire()
            try:
                # Use httpx directly with absolute URL
                response = await self._client.request("GET", url)
                self._rate_limiter.update_from_headers(dict(response.headers))

                if response.status_code in (403, 429):
                    await self._rate_limiter.handle_rate_limit(
                        response.status_code, dict(response.headers)
                    )
                    self._rate_limiter.release()
                    continue

                if response.status_code >= 500:
                    wait = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                    self._rate_limiter.release()
                    last_exc = GitHubClientError(
                        f"{response.status_code} Server Error (url={url})"
                    )
                    await asyncio.sleep(wait)
                    continue

                if response.status_code >= 400:
                    self._rate_limiter.release()
                    raise GitHubClientError(f"{response.status_code} (url={url})")

                self._rate_limiter.release()
                self._rate_limiter._secondary_hit_count = 0
                next_url = _parse_link_next(response.headers.get("link", ""))
                return response.json(), next_url

            except httpx.HTTPError as exc:
                self._rate_limiter.release()
                last_exc = GitHubClientError(f"HTTP error: {_scrub(str(exc))}")
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(_RETRY_BACKOFF_BASE * (2 ** (attempt - 1)))
                    continue
                raise last_exc from None

        raise last_exc or GitHubClientError(f"Max retries exceeded (url={url})")

    async def _raw_request(
        self,
        method: str,
        path: str,
        accept: str = "application/vnd.github.raw+json",
    ) -> httpx.Response:
        """Low-level request that returns the raw Response (for non-JSON content)."""
        last_exc: Exception | None = None

        for attempt in range(1, _MAX_RETRIES + 1):
            await self._rate_limiter.acquire()
            try:
                response = await self._client.request(
                    method, path, headers={"Accept": accept}
                )
                self._rate_limiter.update_from_headers(dict(response.headers))

                if response.status_code in (403, 429):
                    await self._rate_limiter.handle_rate_limit(
                        response.status_code, dict(response.headers)
                    )
                    self._rate_limiter.release()
                    continue

                if response.status_code == 404:
                    self._rate_limiter.release()
                    raise GitHubClientError(f"404 Not Found (path={path})")

                if response.status_code >= 500:
                    wait = _RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                    self._rate_limiter.release()
                    last_exc = GitHubClientError(
                        f"{response.status_code} Server Error (path={path})"
                    )
                    await asyncio.sleep(wait)
                    continue

                if response.status_code >= 400:
                    self._rate_limiter.release()
                    raise GitHubClientError(
                        f"{response.status_code} (path={path})"
                    )

                self._rate_limiter.release()
                self._rate_limiter._secondary_hit_count = 0
                return response

            except httpx.HTTPError as exc:
                self._rate_limiter.release()
                last_exc = GitHubClientError(f"HTTP error: {_scrub(str(exc))} (path={path})")
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(_RETRY_BACKOFF_BASE * (2 ** (attempt - 1)))
                    continue
                raise last_exc from None

        raise last_exc or GitHubClientError(f"Max retries exceeded (path={path})")


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _validate_name(name: str) -> None:
    """Validate an org or repo name against the allowed pattern."""
    if not ORG_NAME_PATTERN.match(name):
        raise ValueError(f"Invalid name (must match {ORG_NAME_PATTERN.pattern!r}): {name!r}")


def _parse_link_next(link_header: str) -> str | None:
    """Extract the ``rel="next"`` URL from a GitHub ``Link`` header."""
    if not link_header:
        return None
    match = _LINK_NEXT_RE.search(link_header)
    return match.group(1) if match else None


def _safe_json(response: httpx.Response) -> dict | list | str:
    """Try to parse JSON body; return empty dict on failure."""
    try:
        return response.json()
    except Exception:
        return {}


def _scrub(message: str) -> str:
    """Remove anything that looks like a token from an error message.

    Catches patterns: ghp_*, gho_*, github_pat_*, Bearer *, token=*
    """
    scrubbed = re.sub(
        r"(gh[psoua]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)", "***", message
    )
    scrubbed = re.sub(r"(Bearer\s+)\S+", r"\1***", scrubbed)
    scrubbed = re.sub(r"(token[=:]\s*)\S+", r"\1***", scrubbed)
    return scrubbed
