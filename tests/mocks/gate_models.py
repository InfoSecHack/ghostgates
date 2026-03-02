"""
tests/mocks/gate_models.py

Factory functions for building GateModels with specific configurations.
Used by all rule tests. Each factory returns a GateModel with sensible
defaults that can be overridden for specific test scenarios.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ghostgates.models.gates import (
    BranchProtection,
    Collaborator,
    CustomProtectionRule,
    EnvironmentConfig,
    EnvironmentProtection,
    EnvironmentReviewer,
    GateModel,
    OIDCConfig,
    Ruleset,
    WorkflowDefinition,
    WorkflowJob,
    WorkflowPermissions,
    WorkflowStep,
    WorkflowTrigger,
)


def make_gate(
    org: str = "test-org",
    repo: str = "test-repo",
    *,
    default_branch: str = "main",
    visibility: str = "private",
    is_fork: bool = False,
    branch_protections: list[BranchProtection] | None = None,
    rulesets: list[Ruleset] | None = None,
    environments: list[EnvironmentConfig] | None = None,
    workflow_permissions: WorkflowPermissions | None = None,
    workflows: list[WorkflowDefinition] | None = None,
    oidc: OIDCConfig | None = None,
    collaborators: list[Collaborator] | None = None,
) -> GateModel:
    """Build a GateModel with defaults. Override any field."""
    return GateModel(
        org=org,
        repo=repo,
        full_name=f"{org}/{repo}",
        default_branch=default_branch,
        visibility=visibility,
        is_fork=is_fork,
        branch_protections=branch_protections or [],
        rulesets=rulesets or [],
        environments=environments or [],
        workflow_permissions=workflow_permissions or WorkflowPermissions(),
        workflows=workflows or [],
        oidc=oidc or OIDCConfig(),
        collaborators=collaborators or [],
        collected_at=datetime.now(timezone.utc),
    )


# ------------------------------------------------------------------
# Branch protection factories
# ------------------------------------------------------------------

def make_bp(
    branch: str = "main",
    *,
    reviews: int = 0,
    dismiss_stale: bool = False,
    codeowners: bool = False,
    enforce_admins: bool = False,
    status_checks: list[str] | None = None,
    strict: bool = False,
    restrict_pushes: bool = False,
    push_allowances: list[str] | None = None,
    bypass_allowances: list[str] | None = None,
    allow_force_pushes: bool = False,
    allow_deletions: bool = False,
    required_signatures: bool = False,
) -> BranchProtection:
    """Build a BranchProtection with specific settings."""
    return BranchProtection(
        branch=branch,
        enabled=True,
        required_approving_review_count=reviews,
        dismiss_stale_reviews=dismiss_stale,
        require_code_owner_reviews=codeowners,
        required_status_checks=status_checks or [],
        require_status_checks_strict=strict,
        enforce_admins=enforce_admins,
        restrict_pushes=restrict_pushes,
        push_allowances=push_allowances or [],
        bypass_pull_request_allowances=bypass_allowances or [],
        allow_force_pushes=allow_force_pushes,
        allow_deletions=allow_deletions,
        required_signatures=required_signatures,
        raw={"_test": True},
    )


# ------------------------------------------------------------------
# Ruleset factories
# ------------------------------------------------------------------

def make_ruleset(
    name: str = "default-ruleset",
    *,
    enforcement: str = "active",
    target: str = "branch",
    bypass_actors: list[dict] | None = None,
    rules: list[dict] | None = None,
) -> Ruleset:
    """Build a Ruleset."""
    return Ruleset(
        id=1,
        name=name,
        enforcement=enforcement,
        target=target,
        conditions={"ref_name": {"include": ["~DEFAULT_BRANCH"]}},
        rules=rules or [],
        bypass_actors=bypass_actors or [],
        raw={"_test": True},
    )


# ------------------------------------------------------------------
# Environment factories
# ------------------------------------------------------------------

def make_environment(
    name: str = "production",
    *,
    wait_timer: int = 0,
    reviewers: list[EnvironmentReviewer] | None = None,
    deployment_policy_type: str = "all",
    deployment_patterns: list[str] | None = None,
    custom_rules: list[CustomProtectionRule] | None = None,
    has_secrets: bool = False,
) -> EnvironmentConfig:
    """Build an EnvironmentConfig."""
    return EnvironmentConfig(
        name=name,
        wait_timer=wait_timer,
        reviewers=reviewers or [],
        deployment_branch_policy=EnvironmentProtection(
            type=deployment_policy_type,
            patterns=deployment_patterns or [],
        ),
        custom_rules=custom_rules or [],
        has_secrets=has_secrets,
        raw={"_test": True},
    )


def make_reviewer(
    login: str = "reviewer",
    *,
    reviewer_type: str = "User",
    reviewer_id: int = 1,
    member_count: int | None = None,
) -> EnvironmentReviewer:
    """Build an EnvironmentReviewer."""
    return EnvironmentReviewer(
        type=reviewer_type,
        id=reviewer_id,
        login=login,
        member_count=member_count,
    )


# ------------------------------------------------------------------
# Workflow factories
# ------------------------------------------------------------------

def make_workflow(
    path: str = ".github/workflows/ci.yml",
    name: str = "CI",
    *,
    triggers: list[WorkflowTrigger] | None = None,
    permissions: dict | None = None,
    jobs: list[WorkflowJob] | None = None,
) -> WorkflowDefinition:
    """Build a WorkflowDefinition."""
    return WorkflowDefinition(
        path=path,
        name=name,
        triggers=triggers or [],
        permissions=permissions or {},
        jobs=jobs or [],
        raw_yaml="",
    )


def make_trigger(
    event: str = "push",
    *,
    branches: list[str] | None = None,
    types: list[str] | None = None,
    inputs: dict | None = None,
) -> WorkflowTrigger:
    """Build a WorkflowTrigger."""
    return WorkflowTrigger(
        event=event,
        branches=branches or [],
        types=types or [],
        inputs=inputs or {},
    )


def make_job(
    name: str = "build",
    *,
    runs_on: str | list[str] = "ubuntu-latest",
    environment: str | dict | None = None,
    permissions: dict | None = None,
    steps: list[WorkflowStep] | None = None,
    secrets: str | dict | None = None,
    uses: str = "",
) -> WorkflowJob:
    """Build a WorkflowJob."""
    return WorkflowJob(
        name=name,
        runs_on=runs_on,
        environment=environment,
        permissions=permissions or {},
        steps=steps or [],
        secrets=secrets,
        uses=uses,
    )


def make_step(
    *,
    name: str = "",
    uses: str = "",
    run: str = "",
    with_: dict | None = None,
    env: dict | None = None,
) -> WorkflowStep:
    """Build a WorkflowStep."""
    return WorkflowStep(
        name=name,
        uses=uses,
        run=run,
        with_=with_ or {},
        env=env or {},
    )
