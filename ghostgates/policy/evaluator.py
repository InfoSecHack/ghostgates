"""
ghostgates/policy/evaluator.py

Evaluate gate models against a GhostGates policy.
Produces structured PolicyGap records for each violation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from ghostgates.models.gates import GateModel
from ghostgates.policy.schema import GhostGatesPolicy, ScopeConfig


class GapCategory(StrEnum):
    BRANCH_PROTECTION = "branch_protection"
    ENVIRONMENT = "environment"
    WORKFLOW = "workflow"
    OIDC = "oidc"


@dataclass
class PolicyGap:
    """A single policy violation for a repo."""

    repo: str
    category: GapCategory
    check: str                  # e.g. "enforce_admins", "min_reviewers"
    expected: str               # what the policy requires
    actual: str                 # what the repo has
    context: str = ""           # e.g. branch name, environment name


@dataclass
class RepoAuditResult:
    """Audit result for a single repo."""

    repo: str
    gaps: list[PolicyGap] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        return len(self.gaps) == 0


@dataclass
class PolicyAuditResult:
    """Complete audit result."""

    policy_path: str
    total_repos: int            # in scope
    excluded_repos: int
    repo_results: list[RepoAuditResult] = field(default_factory=list)

    @property
    def compliant_count(self) -> int:
        return sum(1 for r in self.repo_results if r.compliant)

    @property
    def noncompliant_count(self) -> int:
        return sum(1 for r in self.repo_results if not r.compliant)

    @property
    def compliance_pct(self) -> float:
        if not self.repo_results:
            return 100.0
        return (self.compliant_count / len(self.repo_results)) * 100

    @property
    def total_gaps(self) -> int:
        return sum(len(r.gaps) for r in self.repo_results)


# ── Scope filtering ──────────────────────────────────────────────

def _repo_in_scope(repo_name: str, scope: ScopeConfig) -> bool:
    """Check if a repo matches the scope include/exclude patterns."""
    # Must match at least one include pattern
    included = any(re.search(pat, repo_name) for pat in scope.include)
    if not included:
        return False
    # Must not match any exclude pattern
    excluded = any(re.search(pat, repo_name) for pat in scope.exclude)
    return not excluded


# ── Per-category evaluators ──────────────────────────────────────

def _check_branch_protection(gate: GateModel, policy: GhostGatesPolicy) -> list[PolicyGap]:
    """Check branch protection policy against default branch."""
    bp_policy = policy.policy.branch_protection
    gaps: list[PolicyGap] = []

    # Find protection for default branch
    default_bp = None
    for bp in gate.branch_protections:
        if bp.branch == gate.default_branch:
            default_bp = bp
            break

    # If any BP policy is set but no protection exists
    has_any_bp_policy = any(
        v is not None for v in bp_policy.model_dump().values()
    )
    if has_any_bp_policy and default_bp is None:
        gaps.append(PolicyGap(
            repo=gate.full_name,
            category=GapCategory.BRANCH_PROTECTION,
            check="branch_protection_exists",
            expected="enabled",
            actual="no branch protection on default branch",
            context=gate.default_branch,
        ))
        return gaps  # no point checking individual fields

    if default_bp is None:
        return gaps

    if bp_policy.enforce_admins is not None:
        if default_bp.enforce_admins != bp_policy.enforce_admins:
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.BRANCH_PROTECTION,
                check="enforce_admins",
                expected=str(bp_policy.enforce_admins).lower(),
                actual=str(default_bp.enforce_admins).lower(),
                context=default_bp.branch,
            ))

    if bp_policy.dismiss_stale_reviews is not None:
        if default_bp.dismiss_stale_reviews != bp_policy.dismiss_stale_reviews:
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.BRANCH_PROTECTION,
                check="dismiss_stale_reviews",
                expected=str(bp_policy.dismiss_stale_reviews).lower(),
                actual=str(default_bp.dismiss_stale_reviews).lower(),
                context=default_bp.branch,
            ))

    if bp_policy.min_reviewers is not None:
        if default_bp.required_approving_review_count < bp_policy.min_reviewers:
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.BRANCH_PROTECTION,
                check="min_reviewers",
                expected=str(bp_policy.min_reviewers),
                actual=str(default_bp.required_approving_review_count),
                context=default_bp.branch,
            ))

    if bp_policy.require_codeowners is not None:
        if default_bp.require_code_owner_reviews != bp_policy.require_codeowners:
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.BRANCH_PROTECTION,
                check="require_codeowners",
                expected=str(bp_policy.require_codeowners).lower(),
                actual=str(default_bp.require_code_owner_reviews).lower(),
                context=default_bp.branch,
            ))

    if bp_policy.require_status_checks is not None:
        has_checks = len(default_bp.required_status_checks) > 0
        if has_checks != bp_policy.require_status_checks:
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.BRANCH_PROTECTION,
                check="require_status_checks",
                expected=str(bp_policy.require_status_checks).lower(),
                actual=str(has_checks).lower(),
                context=default_bp.branch,
            ))

    if bp_policy.require_signatures is not None:
        if default_bp.required_signatures != bp_policy.require_signatures:
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.BRANCH_PROTECTION,
                check="require_signatures",
                expected=str(bp_policy.require_signatures).lower(),
                actual=str(default_bp.required_signatures).lower(),
                context=default_bp.branch,
            ))

    if bp_policy.block_force_pushes is not None:
        # policy says block_force_pushes=true → allow_force_pushes must be false
        if bp_policy.block_force_pushes and default_bp.allow_force_pushes:
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.BRANCH_PROTECTION,
                check="block_force_pushes",
                expected="true (force pushes blocked)",
                actual="false (force pushes allowed)",
                context=default_bp.branch,
            ))

    return gaps


def _check_environments(gate: GateModel, policy: GhostGatesPolicy) -> list[PolicyGap]:
    """Check environment policies against configured environments."""
    gaps: list[PolicyGap] = []

    for env_pattern, env_policy in policy.policy.environments.items():
        # Find matching environments
        matching_envs = [
            e for e in gate.environments
            if re.search(env_pattern, e.name, re.IGNORECASE)
        ]

        for env in matching_envs:
            if env_policy.required_reviewers is not None:
                has_reviewers = len(env.reviewers) > 0
                if has_reviewers != env_policy.required_reviewers:
                    gaps.append(PolicyGap(
                        repo=gate.full_name,
                        category=GapCategory.ENVIRONMENT,
                        check="required_reviewers",
                        expected=str(env_policy.required_reviewers).lower(),
                        actual=str(has_reviewers).lower(),
                        context=f"environment: {env.name}",
                    ))

            if env_policy.restrict_branches is not None:
                restricts = env.deployment_branch_policy.type != "all"
                if restricts != env_policy.restrict_branches:
                    gaps.append(PolicyGap(
                        repo=gate.full_name,
                        category=GapCategory.ENVIRONMENT,
                        check="restrict_branches",
                        expected=str(env_policy.restrict_branches).lower(),
                        actual=str(restricts).lower(),
                        context=f"environment: {env.name}",
                    ))

            if env_policy.min_wait_timer is not None:
                if env.wait_timer < env_policy.min_wait_timer:
                    gaps.append(PolicyGap(
                        repo=gate.full_name,
                        category=GapCategory.ENVIRONMENT,
                        check="min_wait_timer",
                        expected=f">= {env_policy.min_wait_timer} min",
                        actual=f"{env.wait_timer} min",
                        context=f"environment: {env.name}",
                    ))

    return gaps


def _check_workflows(gate: GateModel, policy: GhostGatesPolicy) -> list[PolicyGap]:
    """Check workflow policies."""
    wf_policy = policy.policy.workflows
    gaps: list[PolicyGap] = []

    if wf_policy.max_default_permissions is not None:
        actual = gate.workflow_permissions.default_workflow_permissions
        if wf_policy.max_default_permissions == "read" and actual == "write":
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.WORKFLOW,
                check="max_default_permissions",
                expected="read",
                actual=actual,
            ))

    if wf_policy.block_pr_approval is not None:
        if wf_policy.block_pr_approval and gate.workflow_permissions.can_approve_pull_request_reviews:
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.WORKFLOW,
                check="block_pr_approval",
                expected="false (workflows cannot approve PRs)",
                actual="true (workflows can approve PRs)",
            ))

    if wf_policy.block_pull_request_target is not None and wf_policy.block_pull_request_target:
        for wf in gate.workflows:
            for trigger in wf.triggers:
                if trigger.event == "pull_request_target":
                    gaps.append(PolicyGap(
                        repo=gate.full_name,
                        category=GapCategory.WORKFLOW,
                        check="block_pull_request_target",
                        expected="no pull_request_target triggers",
                        actual=f"pull_request_target in {wf.path}",
                        context=wf.path,
                    ))

    if wf_policy.block_secrets_inherit is not None and wf_policy.block_secrets_inherit:
        for wf in gate.workflows:
            for job in wf.jobs:
                if job.secrets == "inherit":
                    gaps.append(PolicyGap(
                        repo=gate.full_name,
                        category=GapCategory.WORKFLOW,
                        check="block_secrets_inherit",
                        expected="no secrets: inherit",
                        actual=f"secrets: inherit in {wf.path}#{job.name}",
                        context=f"{wf.path}#{job.name}",
                    ))

    if wf_policy.block_write_all is not None and wf_policy.block_write_all:
        for wf in gate.workflows:
            # Top-level write-all
            if wf.permissions.get("__all__") == "write-all":
                gaps.append(PolicyGap(
                    repo=gate.full_name,
                    category=GapCategory.WORKFLOW,
                    check="block_write_all",
                    expected="no write-all permissions",
                    actual=f"permissions: write-all in {wf.path}",
                    context=wf.path,
                ))
            # Job-level write-all
            for job in wf.jobs:
                if job.permissions.get("__all__") == "write-all":
                    gaps.append(PolicyGap(
                        repo=gate.full_name,
                        category=GapCategory.WORKFLOW,
                        check="block_write_all",
                        expected="no write-all permissions",
                        actual=f"permissions: write-all in {wf.path}#{job.name}",
                        context=f"{wf.path}#{job.name}",
                    ))

    return gaps


def _check_oidc(gate: GateModel, policy: GhostGatesPolicy) -> list[PolicyGap]:
    """Check OIDC policies."""
    oidc_policy = policy.policy.oidc
    gaps: list[PolicyGap] = []

    if oidc_policy.require_custom_template is not None and oidc_policy.require_custom_template:
        if not gate.oidc.org_level_template:
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.OIDC,
                check="require_custom_template",
                expected="custom OIDC template configured",
                actual="using default template",
            ))

    if oidc_policy.require_environment_claim is not None and oidc_policy.require_environment_claim:
        template = gate.oidc.org_level_template
        if template and "environment" not in template:
            gaps.append(PolicyGap(
                repo=gate.full_name,
                category=GapCategory.OIDC,
                check="require_environment_claim",
                expected="'environment' in OIDC subject claim",
                actual=f"template: {template}",
            ))
        # Also check workflows that use OIDC without environment
        for wf in gate.workflows:
            for job in wf.jobs:
                has_id_token = job.permissions.get("id-token") == "write"
                has_env = job.environment is not None
                if has_id_token and not has_env:
                    gaps.append(PolicyGap(
                        repo=gate.full_name,
                        category=GapCategory.OIDC,
                        check="require_environment_claim",
                        expected="OIDC job runs in a named environment",
                        actual=f"id-token: write without environment in {wf.path}#{job.name}",
                        context=f"{wf.path}#{job.name}",
                    ))

    return gaps


# ── Main evaluator ───────────────────────────────────────────────

def evaluate_policy(
    gate_models: list[GateModel],
    policy: GhostGatesPolicy,
    policy_path: str = "",
) -> PolicyAuditResult:
    """Evaluate all gate models against a policy. Returns structured results."""
    in_scope: list[GateModel] = []
    excluded = 0

    for gate in gate_models:
        # Use repo name (without org prefix) for scope matching
        repo_name = gate.repo
        if _repo_in_scope(repo_name, policy.scope):
            in_scope.append(gate)
        else:
            excluded += 1

    repo_results: list[RepoAuditResult] = []

    for gate in in_scope:
        gaps: list[PolicyGap] = []
        gaps.extend(_check_branch_protection(gate, policy))
        gaps.extend(_check_environments(gate, policy))
        gaps.extend(_check_workflows(gate, policy))
        gaps.extend(_check_oidc(gate, policy))
        repo_results.append(RepoAuditResult(repo=gate.full_name, gaps=gaps))

    # Sort: noncompliant repos first (by gap count desc), then compliant
    repo_results.sort(key=lambda r: (-len(r.gaps), r.repo))

    return PolicyAuditResult(
        policy_path=policy_path,
        total_repos=len(in_scope),
        excluded_repos=excluded,
        repo_results=repo_results,
    )
