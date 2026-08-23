"""
ghostgates/collectors/repos.py

Collect repository-level data: repo list, branch protections, and rulesets.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ghostgates.models.gates import BranchProtection, Ruleset

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
    """Collect the default branch's classic branch-protection rule.

    The repository API response identifies the default branch. GhostGates does
    not enumerate all branches, so probing guessed branch names would not
    establish either branch existence or complete protection coverage.
    """
    raw = await client.get_branch_protection(owner, repo, default_branch)
    if raw is None:
        return []

    bp = _parse_branch_protection(default_branch, raw)
    logger.debug(
        "Collected branch protection for %s/%s:%s (reviews=%d, enforce_admins=%s)",
        owner, repo, default_branch,
        bp.required_approving_review_count,
        bp.enforce_admins,
    )
    return [bp]



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
# Rulesets
# ------------------------------------------------------------------

async def collect_rulesets(
    client: GitHubClient,
    owner: str,
    repo: str,
) -> list[Ruleset]:
    """Collect repository rulesets."""
    raw_rulesets = await client.list_rulesets(owner, repo)

    rulesets = [
        Ruleset(
            id=raw.get("id", 0),
            name=raw.get("name", ""),
            enforcement=raw.get("enforcement", "disabled"),
            target=raw.get("target", "branch"),
            conditions=raw.get("conditions", {}),
            rules=raw.get("rules", []),
            bypass_actors=raw.get("bypass_actors", []),
            raw=raw,
        )
        for raw in raw_rulesets
    ]

    logger.debug("Collected %d rulesets for %s/%s", len(rulesets), owner, repo)
    return rulesets
