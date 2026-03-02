"""
ghostgates/policy/schema.py

Pydantic models for the ghostgates-policy.yml file.
Only fields that are explicitly set in the policy are enforced.
"""

from __future__ import annotations

from pathlib import Path

from ruamel.yaml import YAML
from pydantic import BaseModel, Field


class BranchProtectionPolicy(BaseModel):
    """Expected branch protection settings."""

    enforce_admins: bool | None = None
    dismiss_stale_reviews: bool | None = None
    min_reviewers: int | None = None
    require_codeowners: bool | None = None
    require_status_checks: bool | None = None          # at least one status check
    require_signatures: bool | None = None
    block_force_pushes: bool | None = None


class EnvironmentPolicy(BaseModel):
    """Expected settings for a named environment pattern."""

    required_reviewers: bool | None = None
    restrict_branches: bool | None = None
    min_wait_timer: int | None = None                   # minutes


class WorkflowPolicy(BaseModel):
    """Expected workflow-level settings."""

    max_default_permissions: str | None = None          # "read" or "write"
    block_pull_request_target: bool | None = None
    block_secrets_inherit: bool | None = None
    block_write_all: bool | None = None
    block_pr_approval: bool | None = None               # can_approve_pull_request_reviews


class OIDCPolicy(BaseModel):
    """Expected OIDC configuration."""

    require_environment_claim: bool | None = None
    require_custom_template: bool | None = None


class ScopeConfig(BaseModel):
    """Which repos the policy applies to (regex patterns)."""

    include: list[str] = Field(default_factory=lambda: [".*"])
    exclude: list[str] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    """Top-level policy model."""

    branch_protection: BranchProtectionPolicy = Field(
        default_factory=BranchProtectionPolicy
    )
    environments: dict[str, EnvironmentPolicy] = Field(default_factory=dict)
    workflows: WorkflowPolicy = Field(default_factory=WorkflowPolicy)
    oidc: OIDCPolicy = Field(default_factory=OIDCPolicy)


class GhostGatesPolicy(BaseModel):
    """Root of the policy YAML."""

    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)


def load_policy(path: str | Path) -> GhostGatesPolicy:
    """Load and validate a policy YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    yml = YAML(typ="safe")
    with open(path) as f:
        raw = yml.load(f)

    if raw is None:
        raise ValueError(f"Empty policy file: {path}")

    return GhostGatesPolicy.model_validate(raw)
