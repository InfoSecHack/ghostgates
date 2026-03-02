"""
ghostgates/engine/rules/branch_protection.py

Branch protection bypass rules (GHOST-BP-001 through GHOST-BP-006).

Each rule checks for a specific structural bypass in branch protection
configuration. Rules only fire when the gate model shows the bypass
is actually present — no guessing.
"""

from __future__ import annotations

from ghostgates.engine.registry import registry
from ghostgates.engine.urls import actions_url, branches_url, rulesets_url
from ghostgates.models.enums import (
    AttackerLevel,
    Confidence,
    GateType,
    Severity,
)
from ghostgates.models.gates import GateModel
from ghostgates.models.findings import BypassFinding


# ==================================================================
# GHOST-BP-001: Admin bypass of required reviews
# ==================================================================

@registry.rule(
    rule_id="GHOST-BP-001",
    name="Admin bypass of required reviews",
    gate_type=GateType.BRANCH_PROTECTION,
    min_privilege=AttackerLevel.REPO_ADMIN,
    tags=("branch-protection", "review-bypass"),
)
def bp_001_admin_bypass_reviews(gate: GateModel) -> list[BypassFinding]:
    """Detects branches where required reviews exist but enforce_admins is disabled.

    Impact: A repo admin can push directly to the protected branch,
    bypassing all required review checks.

    This is the single most common branch protection misconfiguration.
    GitHub defaults enforce_admins to False when creating protections.
    """
    findings: list[BypassFinding] = []

    for bp in gate.branch_protections:
        if bp.required_approving_review_count > 0 and not bp.enforce_admins:
            findings.append(BypassFinding(
                rule_id="GHOST-BP-001",
                rule_name="Admin bypass of required reviews",
                repo=gate.full_name,
                gate_type=GateType.BRANCH_PROTECTION,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                min_privilege=AttackerLevel.REPO_ADMIN,
                summary=(
                    f"Branch '{bp.branch}' requires {bp.required_approving_review_count} "
                    f"review(s) but enforce_admins is disabled — repo admins can push directly."
                ),
                bypass_path=(
                    f"1. Attacker has admin access to {gate.full_name}\n"
                    f"2. Branch '{bp.branch}' has {bp.required_approving_review_count} required review(s)\n"
                    f"3. enforce_admins is False — admins are exempt from branch protection\n"
                    f"4. Attacker pushes directly to '{bp.branch}', bypassing all reviews"
                ),
                evidence={
                    "branch": bp.branch,
                    "required_approving_review_count": bp.required_approving_review_count,
                    "enforce_admins": bp.enforce_admins,
                },
                gating_conditions=[
                    "Attacker must have admin access to the repository",
                ],
                remediation=(
                    f"Enable 'Include administrators' (enforce_admins) on branch protection "
                    f"for '{bp.branch}'. This ensures admins are subject to the same review "
                    f"requirements as other contributors.\n"
                    f"→ {branches_url(gate.full_name)}"
                ),
                settings_url=branches_url(gate.full_name),
                references=[
                    "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule/managing-a-branch-protection-rule",
                ],
            ))

    return findings


# ==================================================================
# GHOST-BP-002: Stale review approval persistence
# ==================================================================

@registry.rule(
    rule_id="GHOST-BP-002",
    name="Stale review approval persistence",
    gate_type=GateType.BRANCH_PROTECTION,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("branch-protection", "review-bypass"),
)
def bp_002_stale_reviews(gate: GateModel) -> list[BypassFinding]:
    """Detects branches where reviews are required but stale approvals persist.

    Impact: An attacker with write access can:
      1. Submit a benign PR, get it approved
      2. Push malicious commits after approval
      3. Merge with the stale approval still valid

    This is the classic "bait-and-switch" PR attack.
    """
    findings: list[BypassFinding] = []

    for bp in gate.branch_protections:
        if bp.required_approving_review_count > 0 and not bp.dismiss_stale_reviews:
            findings.append(BypassFinding(
                rule_id="GHOST-BP-002",
                rule_name="Stale review approval persistence",
                repo=gate.full_name,
                gate_type=GateType.BRANCH_PROTECTION,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Branch '{bp.branch}' requires reviews but dismiss_stale_reviews "
                    f"is disabled — approvals persist after new commits."
                ),
                bypass_path=(
                    f"1. Attacker submits a clean PR to '{bp.branch}'\n"
                    f"2. PR receives {bp.required_approving_review_count} approval(s)\n"
                    f"3. Attacker pushes malicious commits to the PR branch\n"
                    f"4. Stale approvals are NOT dismissed — PR remains approved\n"
                    f"5. Attacker merges the PR with malicious code"
                ),
                evidence={
                    "branch": bp.branch,
                    "required_approving_review_count": bp.required_approving_review_count,
                    "dismiss_stale_reviews": bp.dismiss_stale_reviews,
                },
                gating_conditions=[
                    "Attacker must have write access to push to PR branches",
                    "At least one reviewer must approve the initial clean PR",
                ],
                remediation=(
                    f"Enable 'Dismiss stale pull request approvals when new commits are pushed' "
                    f"on branch protection for '{bp.branch}'.\n"
                    f"→ {branches_url(gate.full_name)}"
                ),
                settings_url=branches_url(gate.full_name),
                references=[
                    "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule/managing-a-branch-protection-rule",
                ],
            ))

    return findings


# ==================================================================
# GHOST-BP-003: Required reviews without CODEOWNERS enforcement
# ==================================================================

@registry.rule(
    rule_id="GHOST-BP-003",
    name="Required reviews without CODEOWNERS enforcement",
    gate_type=GateType.BRANCH_PROTECTION,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("branch-protection", "review-bypass", "codeowners"),
)
def bp_003_no_codeowners(gate: GateModel) -> list[BypassFinding]:
    """Detects branches where reviews are required but CODEOWNERS review is not.

    Impact: Any authorized reviewer can approve changes to any file,
    even files that CODEOWNERS designates to a specific team. This
    means a friendly reviewer outside the owning team can approve
    changes to sensitive paths (deploy configs, CI, infra).

    Only fires when reviews are required (>0) because CODEOWNERS
    enforcement without required reviews is meaningless.
    """
    findings: list[BypassFinding] = []

    for bp in gate.branch_protections:
        if bp.required_approving_review_count > 0 and not bp.require_code_owner_reviews:
            findings.append(BypassFinding(
                rule_id="GHOST-BP-003",
                rule_name="Required reviews without CODEOWNERS enforcement",
                repo=gate.full_name,
                gate_type=GateType.BRANCH_PROTECTION,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Branch '{bp.branch}' requires {bp.required_approving_review_count} "
                    f"review(s) but does not require CODEOWNERS approval — any reviewer "
                    f"can approve changes to any file."
                ),
                bypass_path=(
                    f"1. Attacker submits PR modifying sensitive files "
                    f"(deploy configs, CI workflows, infra code)\n"
                    f"2. CODEOWNERS file designates a specific team for these paths\n"
                    f"3. require_code_owner_reviews is False\n"
                    f"4. Any collaborator with write access can approve the PR\n"
                    f"5. Changes to sensitive files merge without domain owner review"
                ),
                evidence={
                    "branch": bp.branch,
                    "required_approving_review_count": bp.required_approving_review_count,
                    "require_code_owner_reviews": bp.require_code_owner_reviews,
                },
                gating_conditions=[
                    "Repository must have a CODEOWNERS file for this to be meaningful",
                    "Attacker needs a willing or compromised reviewer outside the owning team",
                ],
                remediation=(
                    f"Enable 'Require review from Code Owners' on branch protection "
                    f"for '{bp.branch}'. This ensures that changes to paths defined in "
                    f"CODEOWNERS must be approved by the designated owners.\n"
                    f"→ {branches_url(gate.full_name)}"
                ),
                settings_url=branches_url(gate.full_name),
            ))

    return findings


# ==================================================================
# GHOST-BP-004: Default branch protected but deploy branches not
# ==================================================================

@registry.rule(
    rule_id="GHOST-BP-004",
    name="Deployment branches lack protection",
    gate_type=GateType.BRANCH_PROTECTION,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("branch-protection", "deployment"),
)
def bp_004_unprotected_deploy_branches(gate: GateModel) -> list[BypassFinding]:
    """Detects when the default branch is protected but deployment-related
    branches are not.

    Impact: If deployment workflows trigger on branches like release/*,
    deploy/*, staging, or production, an attacker with write access can
    push directly to those branches, triggering deployments without review.

    This rule checks if the default branch has protection while known
    deployment branch patterns are missing from branch_protections.
    """
    findings: list[BypassFinding] = []

    # Find default branch protection
    default_bp = None
    for bp in gate.branch_protections:
        if bp.branch == gate.default_branch:
            default_bp = bp
            break

    if default_bp is None:
        return []  # No default branch protection — separate concern

    if default_bp.required_approving_review_count == 0:
        return []  # Default branch has no review requirement — not a gap

    # Check which deployment-relevant branches lack protection
    protected_branches = {bp.branch for bp in gate.branch_protections}

    # Check for environments that reference specific branches
    deploy_branches = _detect_deploy_branches(gate)

    unprotected = [b for b in deploy_branches if b not in protected_branches]

    if unprotected:
        findings.append(BypassFinding(
            rule_id="GHOST-BP-004",
            rule_name="Deployment branches lack protection",
            repo=gate.full_name,
            gate_type=GateType.BRANCH_PROTECTION,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Default branch '{gate.default_branch}' is protected with "
                f"{default_bp.required_approving_review_count} required review(s), "
                f"but deployment-related branches are unprotected: "
                f"{', '.join(unprotected)}"
            ),
            bypass_path=(
                f"1. Default branch '{gate.default_branch}' requires "
                f"{default_bp.required_approving_review_count} review(s)\n"
                f"2. Deployment-related branches lack protection: {', '.join(unprotected)}\n"
                f"3. Attacker pushes directly to an unprotected deployment branch\n"
                f"4. Deployment workflows triggered by push to these branches execute "
                f"without review"
            ),
            evidence={
                "default_branch": gate.default_branch,
                "default_branch_reviews": default_bp.required_approving_review_count,
                "protected_branches": sorted(protected_branches),
                "unprotected_deploy_branches": sorted(unprotected),
            },
            gating_conditions=[
                "Attacker must have write access to push to unprotected branches",
                "Deployment workflows must trigger on the unprotected branches",
            ],
            remediation=(
                f"Apply branch protection rules to deployment-related branches: "
                f"{', '.join(unprotected)}. At minimum, require the same number of "
                f"reviews as the default branch.\n"
                f"→ {branches_url(gate.full_name)}"
            ),
            settings_url=branches_url(gate.full_name),
        ))

    return findings


def _detect_deploy_branches(gate: GateModel) -> list[str]:
    """Detect branches that are likely deployment targets.

    Sources:
      1. Environment deployment branch policies
      2. Workflow trigger branches that target environment jobs
      3. Well-known deployment branch names
    """
    branches: set[str] = set()

    # Check environments for deployment branch references
    for env in gate.environments:
        policy = env.deployment_branch_policy
        if policy.type == "selected" and policy.patterns:
            for pattern in policy.patterns:
                # Only add concrete branch names, not wildcards
                if "*" not in pattern and "?" not in pattern:
                    branches.add(pattern)

    # Check workflows for deployment-like jobs with branch triggers
    for wf in gate.workflows:
        has_deploy_job = any(
            j.environment is not None for j in wf.jobs
        )
        if has_deploy_job:
            for trigger in wf.triggers:
                if trigger.event in ("push", "pull_request"):
                    for b in trigger.branches:
                        if b != gate.default_branch and "*" not in b:
                            branches.add(b)

    # Always check well-known deployment branches
    well_known = {"staging", "production", "release", "deploy"}
    branches.update(well_known)

    # Remove the default branch (it's already protected)
    branches.discard(gate.default_branch)

    return sorted(branches)


# ==================================================================
# GHOST-BP-005: Workflows can approve own PRs
# ==================================================================

@registry.rule(
    rule_id="GHOST-BP-005",
    name="Workflows can approve their own PRs",
    gate_type=GateType.BRANCH_PROTECTION,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("branch-protection", "review-bypass", "actions"),
)
def bp_005_workflow_self_approve(gate: GateModel) -> list[BypassFinding]:
    """Detects when GitHub Actions workflows can approve PRs they create.

    Impact: If can_approve_pull_request_reviews is enabled at the
    org or repo level, a workflow with write permissions to pull-requests
    can approve its own PRs. Combined with auto-merge, this allows
    fully automated code changes without human review.

    This is dangerous when workflows are triggered by external events
    (e.g., dependabot, renovate, or attacker-controlled workflow_dispatch).
    """
    findings: list[BypassFinding] = []

    if not gate.workflow_permissions.can_approve_pull_request_reviews:
        return []

    # Only report if there are branches with required reviews
    branches_with_reviews = [
        bp for bp in gate.branch_protections
        if bp.required_approving_review_count > 0
    ]

    if not branches_with_reviews:
        return []

    branch_list = ", ".join(bp.branch for bp in branches_with_reviews)

    findings.append(BypassFinding(
        rule_id="GHOST-BP-005",
        rule_name="Workflows can approve their own PRs",
        repo=gate.full_name,
        gate_type=GateType.BRANCH_PROTECTION,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        min_privilege=AttackerLevel.REPO_WRITE,
        summary=(
            f"can_approve_pull_request_reviews is enabled — GitHub Actions "
            f"workflows can approve PRs targeting protected branches ({branch_list})."
        ),
        bypass_path=(
            f"1. can_approve_pull_request_reviews is enabled for {gate.full_name}\n"
            f"2. Protected branches require reviews: {branch_list}\n"
            f"3. If any workflow with pull-requests: write is attacker-triggerable "
            f"(push, PR, workflow_dispatch, or reusable workflow call), "
            f"it can approve PRs to protected branches\n"
            f"4. Combined with auto-merge, code changes merge without human review"
        ),
        evidence={
            "can_approve_pull_request_reviews": True,
            "branches_with_reviews": [
                {"branch": bp.branch, "reviews": bp.required_approving_review_count}
                for bp in branches_with_reviews
            ],
        },
        gating_conditions=[
            "A workflow must exist with pull-requests: write permission",
            "That workflow must be triggerable by the attacker (push, PR, dispatch, or dependency update)",
            "The workflow must perform an approval action (e.g., gh pr review --approve)",
        ],
        remediation=(
            "Disable 'Allow GitHub Actions to create and approve pull requests' "
            "in repository or organization Actions settings. If auto-approve is "
            "needed for specific bots, use a dedicated GitHub App with scoped permissions.\n"
            f"→ {actions_url(gate.full_name)}"
        ),
        settings_url=actions_url(gate.full_name),
        references=[
            "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests",
        ],
    ))

    return findings


# ==================================================================
# GHOST-BP-006: Ruleset in "evaluate" mode (false enforcement)
# ==================================================================

@registry.rule(
    rule_id="GHOST-BP-006",
    name="Ruleset in evaluate mode (not enforced)",
    gate_type=GateType.RULESET,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("ruleset", "false-enforcement"),
)
def bp_006_evaluate_mode_ruleset(gate: GateModel) -> list[BypassFinding]:
    """Detects rulesets in "evaluate" mode that appear to protect branches
    but don't actually enforce anything.

    Impact: Rulesets in evaluate mode log violations but do NOT block
    pushes or merges. Organizations may believe a ruleset is protecting
    a branch when it's only auditing. This creates a false sense of
    security.

    This is particularly dangerous when evaluate mode rulesets are the
    ONLY protection on a branch (no branch protection rules either).
    """
    findings: list[BypassFinding] = []

    protected_branches = {bp.branch for bp in gate.branch_protections}

    for rs in gate.rulesets:
        if rs.enforcement != "evaluate":
            continue

        # Determine which branches this ruleset targets
        target_branches = _ruleset_target_branches(rs, gate.default_branch)

        # Higher severity if this is the only "protection" on the branch
        has_real_protection = any(b in protected_branches for b in target_branches)
        severity = Severity.MEDIUM if has_real_protection else Severity.HIGH

        branch_desc = ", ".join(target_branches) if target_branches else "configured branches"

        findings.append(BypassFinding(
            rule_id="GHOST-BP-006",
            rule_name="Ruleset in evaluate mode (not enforced)",
            repo=gate.full_name,
            gate_type=GateType.RULESET,
            severity=severity,
            confidence=Confidence.HIGH,
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Ruleset '{rs.name}' is in evaluate mode — it logs violations "
                f"but does not enforce rules on {branch_desc}."
            ),
            bypass_path=(
                f"1. Ruleset '{rs.name}' targets {branch_desc}\n"
                f"2. Enforcement mode is 'evaluate' (audit only)\n"
                f"3. Pushes and merges that violate the ruleset are logged but NOT blocked\n"
                f"4. Attacker pushes directly or merges PRs that violate ruleset rules"
                + (
                    f"\n5. No other branch protection exists for these branches — "
                    f"ruleset is the only 'protection'"
                    if not has_real_protection else ""
                )
            ),
            evidence={
                "ruleset_name": rs.name,
                "ruleset_id": rs.id,
                "enforcement": rs.enforcement,
                "target_branches": target_branches,
                "has_branch_protection": has_real_protection,
                "rules": [r.get("type", "unknown") for r in rs.rules],
            },
            gating_conditions=[
                "Attacker must have write access to push or merge",
            ],
            remediation=(
                f"Change ruleset '{rs.name}' enforcement from 'evaluate' to 'active'. "
                f"If evaluate mode is intentional for testing, ensure branch protection "
                f"rules are also in place as a backstop.\n"
                f"→ {rulesets_url(gate.full_name)}"
            ),
            settings_url=rulesets_url(gate.full_name),
            references=[
                "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/managing-rulesets-for-a-repository",
            ],
        ))

    return findings


def _ruleset_target_branches(rs, default_branch: str) -> list[str]:
    """Extract target branch names from a ruleset's conditions."""
    branches: list[str] = []
    conditions = rs.conditions or {}
    ref_name = conditions.get("ref_name", {})
    includes = ref_name.get("include", [])

    for pattern in includes:
        if pattern == "~DEFAULT_BRANCH":
            branches.append(default_branch)
        elif pattern == "~ALL":
            branches.append("*all*")
        elif "*" not in pattern and "?" not in pattern:
            # Strip refs/heads/ prefix if present
            clean = pattern.replace("refs/heads/", "")
            branches.append(clean)
        else:
            branches.append(pattern)

    return branches
