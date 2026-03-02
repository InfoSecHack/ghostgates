"""
ghostgates/collectors/environments.py

Collect environment protection rules for a repository:
  - deployment branch policies
  - required reviewers (with team member counts)
  - wait timers
  - custom deployment protection rules
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ghostgates.models.gates import (
    CustomProtectionRule,
    EnvironmentConfig,
    EnvironmentProtection,
    EnvironmentReviewer,
)

if TYPE_CHECKING:
    from ghostgates.client.github_client import GitHubClient

logger = logging.getLogger("ghostgates.collectors.environments")


async def collect_environments(
    client: GitHubClient,
    owner: str,
    repo: str,
) -> list[EnvironmentConfig]:
    """Collect all environments and their protection rules for a repo.

    Returns an empty list if the repo has no environments (not an error).
    Individual environment parsing failures are logged and skipped.
    """
    try:
        raw_envs = await client.list_environments(owner, repo)
    except Exception as exc:
        logger.debug("Error listing environments for %s/%s: %s", owner, repo, exc)
        return []

    if not raw_envs:
        return []

    environments: list[EnvironmentConfig] = []
    for raw in raw_envs:
        try:
            env = _parse_environment(raw)
            environments.append(env)
        except Exception as exc:
            env_name = raw.get("name", "?")
            logger.warning(
                "Failed to parse environment '%s' for %s/%s: %s",
                env_name, owner, repo, exc,
            )

    logger.debug(
        "Collected %d environments for %s/%s", len(environments), owner, repo
    )
    return environments


def _parse_environment(raw: dict) -> EnvironmentConfig:
    """Parse a GitHub environment API response into our model.

    GitHub response structure (abbreviated):
    {
      "name": "production",
      "protection_rules": [
        {"type": "required_reviewers", "reviewers": [
          {"type": "User", "reviewer": {"login": "alice", "id": 1}},
          {"type": "Team", "reviewer": {"slug": "security", "id": 42}}
        ]},
        {"type": "wait_timer", "wait_timer": 30},
        {"type": "branch_policy"},
      ],
      "deployment_branch_policy": {
        "protected_branches": true,
        "custom_branch_policies": false
      },
      // or for custom branch policies:
      "deployment_branch_policy": {
        "protected_branches": false,
        "custom_branch_policies": true
      }
    }
    """
    name = raw.get("name", "")
    protection_rules_raw = raw.get("protection_rules", [])

    # --- Parse reviewers ---
    reviewers: list[EnvironmentReviewer] = []
    wait_timer: int = 0
    custom_rules: list[CustomProtectionRule] = []

    for rule in protection_rules_raw:
        rule_type = rule.get("type", "")

        if rule_type == "required_reviewers":
            for reviewer_entry in rule.get("reviewers", []):
                reviewer = _parse_reviewer(reviewer_entry)
                if reviewer:
                    reviewers.append(reviewer)

        elif rule_type == "wait_timer":
            wait_timer = rule.get("wait_timer", 0)

        elif rule_type == "branch_policy":
            # This just indicates branch policy is active; the actual
            # policy is in deployment_branch_policy at the top level
            pass

        else:
            # Custom deployment protection rules (external webhooks)
            # These have an "app" field with the webhook app info
            app_info = rule.get("app", {})
            if app_info:
                custom_rules.append(CustomProtectionRule(
                    id=rule.get("id", 0),
                    app_slug=app_info.get("slug", "unknown"),
                    timeout_minutes=_infer_timeout(rule),
                ))

    # --- Parse deployment branch policy ---
    deployment_policy = _parse_deployment_branch_policy(
        raw.get("deployment_branch_policy")
    )

    # --- Detect if environment has secrets ---
    # The environments API doesn't directly tell us about secrets.
    # We flag has_secrets=False and let the assembly layer or a
    # separate call update this if needed.
    has_secrets = False

    return EnvironmentConfig(
        name=name,
        protection_rules=protection_rules_raw,
        deployment_branch_policy=deployment_policy,
        reviewers=reviewers,
        wait_timer=wait_timer,
        custom_rules=custom_rules,
        has_secrets=has_secrets,
        raw=raw,
    )


def _parse_reviewer(entry: dict) -> EnvironmentReviewer | None:
    """Parse a single reviewer entry from the protection rules.

    Entry format:
      {"type": "User", "reviewer": {"login": "alice", "id": 1}}
      {"type": "Team", "reviewer": {"slug": "security", "id": 42, "members_count": 15}}
    """
    reviewer_type = entry.get("type", "")
    reviewer_data = entry.get("reviewer", {})

    if not reviewer_data:
        return None

    if reviewer_type == "User":
        return EnvironmentReviewer(
            type="User",
            id=reviewer_data.get("id", 0),
            login=reviewer_data.get("login", ""),
            member_count=None,
        )
    elif reviewer_type == "Team":
        return EnvironmentReviewer(
            type="Team",
            id=reviewer_data.get("id", 0),
            login=reviewer_data.get("slug", reviewer_data.get("name", "")),
            member_count=reviewer_data.get("members_count"),
        )

    return None


def _parse_deployment_branch_policy(
    raw_policy: dict | None,
) -> EnvironmentProtection:
    """Parse the deployment_branch_policy section.

    GitHub returns:
      null → no restriction (all branches can deploy)
      {"protected_branches": true, "custom_branch_policies": false} → only protected branches
      {"protected_branches": false, "custom_branch_policies": true} → custom patterns

    For custom patterns, the actual branch name patterns come from a
    separate API call. For MVP we flag it as "selected" and note that
    patterns would need to be fetched separately.
    """
    if raw_policy is None:
        return EnvironmentProtection(type="all", patterns=[])

    protected_branches = raw_policy.get("protected_branches", False)
    custom_policies = raw_policy.get("custom_branch_policies", False)

    if protected_branches:
        return EnvironmentProtection(type="protected", patterns=[])
    elif custom_policies:
        # Custom branch policies exist but we'd need a separate API call
        # to get the actual patterns. For MVP, mark as "selected" with
        # empty patterns (the rule engine treats empty patterns on
        # "selected" as potentially overly broad).
        return EnvironmentProtection(type="selected", patterns=[])
    else:
        return EnvironmentProtection(type="none", patterns=[])


def _infer_timeout(rule: dict) -> int:
    """Infer custom protection rule timeout.

    GitHub's default is 30 minutes — if the external check doesn't
    respond within this window, the deployment is auto-approved.
    The API doesn't always expose this directly.
    """
    # Some custom rules expose a timeout field
    timeout = rule.get("timeout", rule.get("timeout_minutes"))
    if timeout is not None:
        try:
            return int(timeout)
        except (ValueError, TypeError):
            pass
    # Default to GitHub's documented 30-minute timeout
    return 30
