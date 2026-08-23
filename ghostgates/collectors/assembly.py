"""
ghostgates/collectors/assembly.py

Orchestrates all collectors to build a complete GateModel for each repository.
This is the main entry point for the collection phase.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ghostgates.models.findings import ScanScope
from ghostgates.models.gates import (
    CollectionError,
    GateModel,
    OIDCConfig,
    WorkflowPermissions,
)
from ghostgates.collectors.org import collect_org_metadata
from ghostgates.collectors.repos import (
    collect_repos,
    collect_branch_protections,
    collect_rulesets,
)
from ghostgates.collectors.environments import collect_environments
from ghostgates.collectors.workflows import collect_workflows

if TYPE_CHECKING:
    from ghostgates.client.github_client import GitHubClient

logger = logging.getLogger("ghostgates.collectors.assembly")


@dataclass
class CollectionResult:
    """Gate models plus explicit completeness and collection scope."""

    gate_models: list[GateModel]
    errors: list[CollectionError]
    scope: ScanScope


async def collect_org_gate_models(
    client: GitHubClient,
    org: str,
    *,
    include_forks: bool = False,
    repo_filter: list[str] | None = None,
) -> CollectionResult:
    """Collect GateModels without treating inaccessible evidence as absent."""
    requested = (
        [f"{org}/{name}" for name in repo_filter]
        if repo_filter is not None
        else None
    )

    org_meta = await collect_org_metadata(client, org)
    org_errors: list[CollectionError] = list(
        org_meta.get("collection_errors", [])
    )
    errors = list(org_errors)

    try:
        raw_repos = await collect_repos(client, org)
    except Exception as exc:
        scope = ScanScope(
            requested_repositories=requested,
            enumeration_complete=False,
        )
        return CollectionResult(
            gate_models=[],
            errors=[*errors, CollectionError(
                collector="repositories",
                message=str(exc),
            )],
            scope=scope,
        )

    discovered = [f"{org}/{repo['name']}" for repo in raw_repos]
    repos_to_scan = _filter_repos(raw_repos, include_forks, repo_filter)
    selected = [f"{org}/{repo['name']}" for repo in repos_to_scan]
    skipped = len(raw_repos) - len(repos_to_scan)

    if requested is not None:
        for missing_repo in sorted(set(requested) - set(selected)):
            errors.append(CollectionError(
                collector="repository_filter",
                repo=missing_repo,
                message="requested repository was not selected for evaluation",
            ))

    logger.info(
        "Scanning %d repos for org '%s' (%d skipped)",
        len(repos_to_scan), org, skipped,
    )

    tasks = [
        _collect_single_repo(client, org, repo_data, org_meta, org_errors)
        for repo_data in repos_to_scan
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    gate_models: list[GateModel] = []
    for repo_data, result in zip(repos_to_scan, results):
        repo_name = repo_data.get("name", "?")
        full_name = f"{org}/{repo_name}"
        if isinstance(result, Exception):
            errors.append(CollectionError(
                collector="repository",
                repo=full_name,
                message=str(result),
            ))
            logger.warning("Failed to collect %s: %s", full_name, result)
        elif isinstance(result, GateModel):
            gate_models.append(result)
            errors.extend(
                error for error in result.collection_errors if error.repo
            )
        else:
            errors.append(CollectionError(
                collector="repository",
                repo=full_name,
                message=f"unexpected result type: {type(result).__name__}",
            ))

    scope = ScanScope(
        requested_repositories=requested,
        discovered_repositories=discovered,
        selected_repositories=selected,
        evaluated_repositories=[model.full_name for model in gate_models],
        enumeration_complete=True,
    )
    logger.info(
        "Collection complete: %d gate models, %d errors",
        len(gate_models), len(errors),
    )
    return CollectionResult(gate_models=gate_models, errors=errors, scope=scope)


async def _collect_single_repo(
    client: GitHubClient,
    org: str,
    repo_data: dict,
    org_meta: dict,
    shared_errors: list[CollectionError] | None = None,
) -> GateModel:
    """Build a complete GateModel for a single repository.

    Runs all sub-collectors concurrently where possible.
    """
    repo_name = repo_data["name"]
    default_branch = repo_data.get("default_branch", "main")

    logger.debug("Collecting gate model for %s/%s", org, repo_name)

    collector_names = (
        "branch_protections",
        "environments",
        "workflows",
        "rulesets",
        "actions_permissions",
    )
    empty_values = ([], [], [], [], {})
    results = await asyncio.gather(
        collect_branch_protections(client, org, repo_name, default_branch),
        collect_environments(client, org, repo_name),
        collect_workflows(client, org, repo_name),
        collect_rulesets(client, org, repo_name),
        _collect_repo_actions_permissions(client, org, repo_name),
        return_exceptions=True,
    )

    values: list = []
    collection_errors = list(shared_errors or [])
    for collector, result, empty_value in zip(
        collector_names, results, empty_values
    ):
        if isinstance(result, Exception):
            collection_errors.append(CollectionError(
                collector=collector,
                repo=f"{org}/{repo_name}",
                message=str(result),
            ))
            values.append(empty_value)
        else:
            values.append(result)

    (
        branch_protections,
        environments,
        workflows,
        rulesets,
        repo_actions_perms,
    ) = values

    for workflow in workflows:
        for parse_error in workflow.parse_errors:
            collection_errors.append(CollectionError(
                collector="workflows",
                repo=f"{org}/{repo_name}",
                message=f"{workflow.path}: {parse_error}",
            ))

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
        collection_errors=collection_errors,
        collected_at=datetime.now(timezone.utc),
    )


async def _collect_repo_actions_permissions(
    client: GitHubClient,
    owner: str,
    repo: str,
) -> dict:
    """Fetch repo-level Actions permissions."""
    return await client.get_repo_actions_permissions(owner, repo)


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
    default_wf_perms = repo_perms.get(
        "default_workflow_permissions",
        org_perms.get("default_workflow_permissions", "read"),
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
