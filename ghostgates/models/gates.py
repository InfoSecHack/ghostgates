"""GhostGates — gate models.

Section 4 of ARCHITECTURE.md.

These represent the collected state of a repository's security gates.
Collectors produce these; the rule engine consumes them.
No I/O, no HTTP, no async.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Sub-models (building blocks)
# ---------------------------------------------------------------------------


class BranchProtection(BaseModel):
    """Branch protection rule as returned by GitHub API, normalized."""

    branch: str                                                              # e.g. "main"
    enabled: bool = True
    required_approving_review_count: int = 0
    dismiss_stale_reviews: bool = False
    require_code_owner_reviews: bool = False
    required_status_checks: list[str] = Field(default_factory=list)
    require_status_checks_strict: bool = False                               # require up-to-date branch
    enforce_admins: bool = False                                             # admins subject to rules
    restrict_pushes: bool = False
    push_allowances: list[str] = Field(default_factory=list)                # actors who can push
    bypass_pull_request_allowances: list[str] = Field(default_factory=list)
    require_linear_history: bool = False
    allow_force_pushes: bool = False
    allow_deletions: bool = False
    lock_branch: bool = False
    required_signatures: bool = False
    raw: dict = Field(default_factory=dict)                                  # full API response for evidence


class Ruleset(BaseModel):
    """GitHub repository ruleset (newer replacement for branch protections)."""

    id: int
    name: str
    enforcement: str                                                         # "active", "evaluate", "disabled"
    target: str                                                              # "branch", "tag"
    conditions: dict = Field(default_factory=dict)                           # ref_name include/exclude patterns
    rules: list[dict] = Field(default_factory=list)                          # rule objects
    bypass_actors: list[dict] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class EnvironmentProtection(BaseModel):
    """Deployment branch policy within an environment."""

    type: str = "all"                                                        # "all", "protected", "selected", "none"
    patterns: list[str] = Field(default_factory=list)                        # branch name patterns for "selected"


class EnvironmentReviewer(BaseModel):
    """Required reviewer for an environment."""

    type: str                                                                # "User" or "Team"
    id: int
    login: str = ""                                                          # username or team slug
    member_count: int | None = None                                          # for teams: how many members


class CustomProtectionRule(BaseModel):
    """Custom deployment protection rule (external webhook)."""

    id: int
    app_slug: str
    timeout_minutes: int = 30                                                # GitHub default: 30 min, auto-approve if no response


class EnvironmentConfig(BaseModel):
    """Complete environment configuration."""

    name: str
    protection_rules: list[dict] = Field(default_factory=list)              # raw wait_timer, reviewers
    deployment_branch_policy: EnvironmentProtection = Field(
        default_factory=lambda: EnvironmentProtection()
    )
    reviewers: list[EnvironmentReviewer] = Field(default_factory=list)
    wait_timer: int = 0                                                      # minutes
    custom_rules: list[CustomProtectionRule] = Field(default_factory=list)
    has_secrets: bool = False                                                # whether env has secrets configured
    raw: dict = Field(default_factory=dict)


class WorkflowTrigger(BaseModel):
    """Parsed workflow trigger configuration."""

    event: str                                                               # push, pull_request, pull_request_target, etc.
    branches: list[str] = Field(default_factory=list)
    branches_ignore: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    types: list[str] = Field(default_factory=list)
    inputs: dict = Field(default_factory=dict)                               # for workflow_dispatch


class WorkflowStep(BaseModel):
    """Minimal parsed step — enough for bypass analysis."""

    name: str = ""
    uses: str = ""                                                           # action reference
    run: str = ""                                                            # shell command
    with_: dict = Field(default_factory=dict, alias="with")
    env: dict = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class WorkflowJob(BaseModel):
    """Parsed job from workflow YAML."""

    name: str
    runs_on: str | list[str] = "ubuntu-latest"
    environment: str | dict | None = None                                    # environment name or {name, url}
    permissions: dict = Field(default_factory=dict)
    steps: list[WorkflowStep] = Field(default_factory=list)
    secrets: str | dict | None = None                                        # "inherit" or specific secrets
    uses: str = ""                                                           # reusable workflow ref
    if_condition: str = ""                                                   # if: expression


class WorkflowDefinition(BaseModel):
    """Complete parsed workflow file."""

    path: str                                                                # .github/workflows/deploy.yml
    name: str = ""
    triggers: list[WorkflowTrigger] = Field(default_factory=list)
    permissions: dict = Field(default_factory=dict)                          # top-level permissions
    jobs: list[WorkflowJob] = Field(default_factory=list)
    raw_yaml: str = ""                                                       # original YAML for evidence
    parse_errors: list[str] = Field(default_factory=list)


class WorkflowPermissions(BaseModel):
    """Org/repo-level Actions permission settings."""

    default_workflow_permissions: str = "read"                               # "read" or "write"
    can_approve_pull_request_reviews: bool = False
    allowed_actions: str = "all"                                             # "all", "local_only", "selected"
    enabled: bool = True


class OIDCConfig(BaseModel):
    """OIDC subject claim customization."""

    org_level_template: list[str] = Field(default_factory=list)             # claim keys
    repo_level_overrides: dict = Field(default_factory=dict)
    raw: dict = Field(default_factory=dict)


class Collaborator(BaseModel):
    """Repository collaborator with permission level."""

    login: str
    id: int
    permission: str                                                          # "admin", "maintain", "write", "triage", "read"
    is_team: bool = False
    team_slug: str = ""


# ---------------------------------------------------------------------------
# Top-level Gate Model
# ---------------------------------------------------------------------------


class GateModel(BaseModel):
    """
    Complete security gate model for a single repository.

    This is the PRIMARY INPUT to the rule engine.
    Collectors build these.  Rules consume these.
    """

    org: str
    repo: str
    full_name: str                                                           # "org/repo"
    default_branch: str = "main"
    visibility: str = "private"                                              # "public", "private", "internal"
    is_fork: bool = False
    is_archived: bool = False
    branch_protections: list[BranchProtection] = Field(default_factory=list)
    rulesets: list[Ruleset] = Field(default_factory=list)
    environments: list[EnvironmentConfig] = Field(default_factory=list)
    workflow_permissions: WorkflowPermissions = Field(
        default_factory=lambda: WorkflowPermissions()
    )
    workflows: list[WorkflowDefinition] = Field(default_factory=list)
    oidc: OIDCConfig = Field(default_factory=lambda: OIDCConfig())
    collaborators: list[Collaborator] = Field(default_factory=list)
    collected_at: datetime | None = None
