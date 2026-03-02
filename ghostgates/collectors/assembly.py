"""
ghostgates/collectors/assembly.py

Orchestrates all collectors to build a complete GateModel for each repository.
This is the main entry point for the collection phase.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ghostgates.models.gates import (
    GateModel,
    OIDCConfig,
    WorkflowPermissions,
)
from ghostgates.collectors.org import collect_org_metadata
from ghostgates.collectors.repos import (
    collect_repos,
    collect_branch_protections,
    collect_collaborators,
    collect_rulesets,
)
from ghostgates.collectors.environments import collect_environments
from ghostgates.collectors.workflows import collect_workflows

if TYPE_CHECKING:
    from ghostgates.client.github_client import GitHubClient

logger = logging.getLogger("ghostgates.collectors.assembly")


async def collect_org_gate_models(
    client: GitHubClient,
    org: str,
    *,
    include_forks: bool = False,
    repo_filter: list[str] | None = None,
) -> tuple[list[GateModel], list[str]]:
    """Collect GateModels for all repos in an organization.

    Args:
        client: Authenticated GitHub API client.
        org: Organization name.
        include_forks: Whether to include forked repos (default: skip).
        repo_filter: If set, only collect these repo names.

    Returns:
        Tuple of (gate_models, errors).
        Errors are non-fatal — individual repo failures don't stop the scan.
    """
    errors: list[str] = []

    # --- Org-level metadata (shared across all repos) ---
    org_meta = await collect_org_metadata(client, org)

    # --- List repos ---
    try:
        raw_repos = await collect_repos(client, org)
    except Exception as exc:
        return [], [f"Failed to list repos for org '{org}': {exc}"]

    # --- Filter repos ---
    repos_to_scan = _filter_repos(raw_repos, include_forks, repo_filter)
    skipped = len(raw_repos) - len(repos_to_scan)

    logger.info(
        "Scanning %d repos for org '%s' (%d skipped)",
        len(repos_to_scan), org, skipped,
    )

    # --- Collect gate models concurrently ---
    tasks = [
        _collect_single_repo(client, org, repo_data, org_meta)
        for repo_data in repos_to_scan
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    gate_models: list[GateModel] = []
    for repo_data, result in zip(repos_to_scan, results):
        repo_name = repo_data.get("name", "?")
        if isinstance(result, Exception):
            errors.append(f"Failed to collect {org}/{repo_name}: {result}")
            logger.warning("Failed to collect %s/%s: %s", org, repo_name, result)
        elif isinstance(result, GateModel):
            gate_models.append(result)
        else:
            errors.append(f"Unexpected result type for {org}/{repo_name}")

    logger.info(
        "Collection complete: %d gate models, %d errors",
        len(gate_models), len(errors),
    )

    return gate_models, errors


async def _collect_single_repo(
    client: GitHubClient,
    org: str,
    repo_data: dict,
    org_meta: dict,
) -> GateModel:
    """Build a complete GateModel for a single repository.

    Runs all sub-collectors concurrently where possible.
    """
    repo_name = repo_data["name"]
    default_branch = repo_data.get("default_branch", "main")

    logger.debug("Collecting gate model for %s/%s", org, repo_name)

    # Run independent collectors concurrently
    bp_task = collect_branch_protections(client, org, repo_name, default_branch)
    env_task = collect_environments(client, org, repo_name)
    wf_task = collect_workflows(client, org, repo_name)
    collab_task = collect_collaborators(client, org, repo_name)
    ruleset_task = collect_rulesets(client, org, repo_name)
    repo_perms_task = _collect_repo_actions_permissions(client, org, repo_name)

    (
        branch_protections,
        environments,
        workflows,
        collaborators,
        rulesets,
        repo_actions_perms,
    ) = await asyncio.gather(
        bp_task, env_task, wf_task, collab_task, ruleset_task, repo_perms_task
    )

    # --- Build workflow permissions from org + repo level ---
    workflow_permissions = _build_workflow_permissions(
        org_meta.get("actions_permissions", {}),
        repo_actions_perms,
    )

    # --- Build OIDC config ---
    oidc = _build_oidc_config(org_meta.get("oidc_template"))

    return GateModel(
        org=org,
        repo=repo_name,
        full_name=f"{org}/{repo_name}",
        default_branch=default_branch,
        visibility=repo_data.get("visibility", "private"),
        is_fork=repo_data.get("fork", False),
        is_archived=repo_data.get("archived", False),
        branch_protections=branch_protections,
        rulesets=rulesets,
        environments=environments,
        workflow_permissions=workflow_permissions,
        workflows=workflows,
        oidc=oidc,
        collaborators=collaborators,
        collected_at=datetime.now(timezone.utc),
    )


async def _collect_repo_actions_permissions(
    client: GitHubClient,
    owner: str,
    repo: str,
) -> dict:
    """Fetch repo-level Actions permissions. Returns empty dict on failure."""
    try:
        return await client.get_repo_actions_permissions(owner, repo)
    except Exception as exc:
        logger.debug(
            "Error collecting repo Actions permissions for %s/%s: %s",
            owner, repo, exc,
        )
        return {}


def _filter_repos(
    raw_repos: list[dict],
    include_forks: bool,
    repo_filter: list[str] | None,
) -> list[dict]:
    """Filter repos based on user criteria."""
    filtered = raw_repos

    if not include_forks:
        filtered = [r for r in filtered if not r.get("fork", False)]

    if repo_filter:
        filter_set = set(repo_filter)
        filtered = [r for r in filtered if r.get("name") in filter_set]

    return filtered


def _build_workflow_permissions(
    org_perms: dict,
    repo_perms: dict,
) -> WorkflowPermissions:
    """Merge org-level and repo-level Actions permissions.

    Repo-level overrides org-level where both are present.
    """
    # Start with org defaults
    default_wf_perms = org_perms.get(
        "default_workflow_permissions",
        repo_perms.get("default_workflow_permissions", "read"),
    )
    can_approve = repo_perms.get(
        "can_approve_pull_request_reviews",
        org_perms.get("can_approve_pull_request_reviews", False),
    )
    allowed_actions = repo_perms.get(
        "allowed_actions",
        org_perms.get("allowed_actions", "all"),
    )
    enabled = repo_perms.get(
        "enabled",
        org_perms.get("enabled", True),
    )

    return WorkflowPermissions(
        default_workflow_permissions=str(default_wf_perms),
        can_approve_pull_request_reviews=bool(can_approve),
        allowed_actions=str(allowed_actions),
        enabled=bool(enabled),
    )


def _build_oidc_config(oidc_template: dict | None) -> OIDCConfig:
    """Build OIDC config from org-level template."""
    if oidc_template is None:
        return OIDCConfig()

    return OIDCConfig(
        org_level_template=oidc_template.get("include_claim_keys", []),
        raw=oidc_template,
    )
