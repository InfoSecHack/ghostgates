"""
ghostgates/collectors/repos.py

Collect repository-level data: repo list, branch protections, collaborators,
and rulesets.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ghostgates.config import DEFAULT_BRANCHES_TO_CHECK
from ghostgates.models.gates import BranchProtection, Collaborator, Ruleset

if TYPE_CHECKING:
    from ghostgates.client.github_client import GitHubClient

logger = logging.getLogger("ghostgates.collectors.repos")


# ------------------------------------------------------------------
# Repo listing
# ------------------------------------------------------------------

async def collect_repos(client: GitHubClient, org: str) -> list[dict]:
    """List all repositories in an org, excluding archived repos.

    Returns raw GitHub API repo dicts (not model objects) because
    the caller needs multiple fields for routing to other collectors.
    """
    all_repos = await client.list_org_repos(org)

    active_repos = [
        r for r in all_repos
        if not r.get("archived", False) and not r.get("disabled", False)
    ]

    skipped = len(all_repos) - len(active_repos)
    if skipped > 0:
        logger.info(
            "Org '%s': %d repos found, %d archived/disabled skipped, %d active",
            org, len(all_repos), skipped, len(active_repos),
        )
    else:
        logger.info("Org '%s': %d active repos found", org, len(active_repos))

    return active_repos


# ------------------------------------------------------------------
# Branch protections
# ------------------------------------------------------------------

async def collect_branch_protections(
    client: GitHubClient,
    owner: str,
    repo: str,
    default_branch: str,
) -> list[BranchProtection]:
    """Collect branch protection rules for the default branch + common branches.

    Checks the default branch first, then other well-known branch names.
    Branches that return 404 (no protection) are silently skipped.
    Duplicate branch names are deduplicated.
    """
    branches_to_check: list[str] = _unique_branches(default_branch)
    protections: list[BranchProtection] = []
    seen: set[str] = set()

    for branch in branches_to_check:
        if branch in seen:
            continue
        seen.add(branch)

        try:
            raw = await client.get_branch_protection(owner, repo, branch)
        except Exception as exc:
            logger.debug(
                "Error checking branch protection for %s/%s:%s — %s",
                owner, repo, branch, exc,
            )
            continue

        if raw is None:
            # No protection on this branch — that's normal
            continue

        bp = _parse_branch_protection(branch, raw)
        protections.append(bp)
        logger.debug(
            "Collected branch protection for %s/%s:%s (reviews=%d, enforce_admins=%s)",
            owner, repo, branch,
            bp.required_approving_review_count,
            bp.enforce_admins,
        )

    return protections


def _unique_branches(default_branch: str) -> list[str]:
    """Build deduplicated list of branches to check, default first."""
    branches = [default_branch]
    for b in DEFAULT_BRANCHES_TO_CHECK:
        if b not in branches:
            branches.append(b)
    return branches


def _parse_branch_protection(branch: str, raw: dict) -> BranchProtection:
    """Parse a GitHub branch protection API response into our model.

    GitHub's response structure (abbreviated):
    {
      "required_pull_request_reviews": {
        "required_approving_review_count": 2,
        "dismiss_stale_reviews": true,
        "require_code_owner_reviews": false,
        "dismissal_restrictions": {...},
        "bypass_pull_request_allowances": {...}
      },
      "enforce_admins": {"enabled": true},
      "required_status_checks": {
        "strict": true,
        "contexts": ["ci/build"]
      },
      "restrictions": {
        "users": [...],
        "teams": [...]
      },
      "required_linear_history": {"enabled": false},
      "allow_force_pushes": {"enabled": false},
      "allow_deletions": {"enabled": false},
      "lock_branch": {"enabled": false},
      "required_signatures": {"enabled": false}
    }
    """
    # -- Pull request reviews --
    pr_reviews = raw.get("required_pull_request_reviews") or {}
    required_review_count = pr_reviews.get("required_approving_review_count", 0)
    dismiss_stale = pr_reviews.get("dismiss_stale_reviews", False)
    require_codeowners = pr_reviews.get("require_code_owner_reviews", False)

    # Bypass allowances: extract actor logins
    bypass_raw = pr_reviews.get("bypass_pull_request_allowances") or {}
    bypass_actors = _extract_actor_logins(bypass_raw)

    # -- Enforce admins --
    enforce_admins_section = raw.get("enforce_admins") or {}
    enforce_admins = enforce_admins_section.get("enabled", False)

    # -- Status checks --
    status_checks_section = raw.get("required_status_checks") or {}
    status_checks = status_checks_section.get("contexts", [])
    status_checks_strict = status_checks_section.get("strict", False)

    # -- Push restrictions --
    restrictions = raw.get("restrictions")
    restrict_pushes = restrictions is not None
    push_allowances = _extract_actor_logins(restrictions or {})

    # -- Boolean flags --
    def _bool_section(key: str) -> bool:
        section = raw.get(key) or {}
        return section.get("enabled", False)

    return BranchProtection(
        branch=branch,
        enabled=True,
        required_approving_review_count=required_review_count,
        dismiss_stale_reviews=dismiss_stale,
        require_code_owner_reviews=require_codeowners,
        required_status_checks=status_checks,
        require_status_checks_strict=status_checks_strict,
        enforce_admins=enforce_admins,
        restrict_pushes=restrict_pushes,
        push_allowances=push_allowances,
        bypass_pull_request_allowances=bypass_actors,
        require_linear_history=_bool_section("required_linear_history"),
        allow_force_pushes=_bool_section("allow_force_pushes"),
        allow_deletions=_bool_section("allow_deletions"),
        lock_branch=_bool_section("lock_branch"),
        required_signatures=_bool_section("required_signatures"),
        raw=raw,
    )


def _extract_actor_logins(section: dict) -> list[str]:
    """Extract login strings from a users/teams/apps allowances section.

    GitHub returns: {"users": [{"login": "x"}], "teams": [{"slug": "y"}], "apps": [{"slug": "z"}]}
    We flatten to a list of identifier strings.
    """
    logins: list[str] = []
    for user in section.get("users", []):
        login = user.get("login", "")
        if login:
            logins.append(f"user:{login}")
    for team in section.get("teams", []):
        slug = team.get("slug", "")
        if slug:
            logins.append(f"team:{slug}")
    for app in section.get("apps", []):
        slug = app.get("slug", "")
        if slug:
            logins.append(f"app:{slug}")
    return logins


# ------------------------------------------------------------------
# Collaborators
# ------------------------------------------------------------------

async def collect_collaborators(
    client: GitHubClient,
    owner: str,
    repo: str,
) -> list[Collaborator]:
    """Collect all collaborators with their permission levels.

    GitHub API returns permissions as a dict of booleans:
      {"admin": true, "maintain": false, "push": true, "triage": true, "pull": true}
    We convert to the highest applicable permission string.
    """
    raw_collabs = await client.list_collaborators(owner, repo)
    collaborators: list[Collaborator] = []

    for raw in raw_collabs:
        login = raw.get("login", "")
        cid = raw.get("id", 0)
        permissions = raw.get("permissions", {})
        role_name = raw.get("role_name", "")

        # Determine highest permission level
        permission = _highest_permission(permissions, role_name)

        collaborators.append(Collaborator(
            login=login,
            id=cid,
            permission=permission,
        ))

    logger.debug(
        "Collected %d collaborators for %s/%s", len(collaborators), owner, repo
    )
    return collaborators


def _highest_permission(permissions: dict, role_name: str = "") -> str:
    """Determine the highest permission level from GitHub's permissions dict.

    Check from highest to lowest: admin > maintain > write (push) > triage > read (pull).
    Falls back to role_name if the permissions dict is empty.
    """
    if permissions.get("admin"):
        return "admin"
    if permissions.get("maintain"):
        return "maintain"
    if permissions.get("push"):
        return "write"
    if permissions.get("triage"):
        return "triage"
    if permissions.get("pull"):
        return "read"
    # Fallback to role_name if permissions dict was empty
    if role_name:
        return role_name
    return "read"


# ------------------------------------------------------------------
# Rulesets
# ------------------------------------------------------------------

async def collect_rulesets(
    client: GitHubClient,
    owner: str,
    repo: str,
) -> list[Ruleset]:
    """Collect repository rulesets. Returns empty list if not available."""
    try:
        raw_rulesets = await client.list_rulesets(owner, repo)
    except Exception as exc:
        logger.debug("Error collecting rulesets for %s/%s: %s", owner, repo, exc)
        return []

    rulesets: list[Ruleset] = []
    for raw in raw_rulesets:
        try:
            rs = Ruleset(
                id=raw.get("id", 0),
                name=raw.get("name", ""),
                enforcement=raw.get("enforcement", "disabled"),
                target=raw.get("target", "branch"),
                conditions=raw.get("conditions", {}),
                rules=raw.get("rules", []),
                bypass_actors=raw.get("bypass_actors", []),
                raw=raw,
            )
            rulesets.append(rs)
        except Exception as exc:
            logger.warning(
                "Failed to parse ruleset %s for %s/%s: %s",
                raw.get("name", "?"), owner, repo, exc,
            )

    logger.debug("Collected %d rulesets for %s/%s", len(rulesets), owner, repo)
    return rulesets
