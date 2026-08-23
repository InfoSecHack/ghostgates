"""
ghostgates/engine/rules/branch_protection.py

Branch and ruleset checks (GHOST-BP-001–003 and GHOST-BP-005–006).

Each rule records an observed configuration and a conditional security
inference. Findings do not demonstrate that the prerequisite actors or
downstream behavior exist.
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
    """Detect branches where required reviews do not apply to administrators."""
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
    """Detect branches where new commits do not dismiss existing approvals."""
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

    A security consequence exists only if CODEOWNERS is present and an
    otherwise eligible reviewer approves a change outside their ownership area.
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
                    f"review(s) but does not require approval from code owners."
                ),
                bypass_path=(
                    f"Observed: branch '{bp.branch}' requires reviews but "
                    f"require_code_owner_reviews is false\n"
                    f"Unobserved prerequisite: CODEOWNERS assigns the changed path and "
                    f"an eligible non-owner reviewer approves the pull request\n"
                    f"Potential consequence: the change can satisfy the collected review "
                    f"setting without code-owner approval"
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
# GHOST-BP-005: Workflows can approve own PRs
# ==================================================================

@registry.rule(
    rule_id="GHOST-BP-005",
    name="Actions pull-request approval setting enabled",
    gate_type=GateType.BRANCH_PROTECTION,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("branch-protection", "review-bypass", "actions"),
)
def bp_005_workflow_self_approve(gate: GateModel) -> list[BypassFinding]:
    """Flag an approval capability that can weaken review separation.

    The setting alone does not prove that a workflow has pull-requests:write,
    performs an approval, or can merge a change. Those remain prerequisites.
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
        rule_name="Actions pull-request approval setting enabled",
        repo=gate.full_name,
        gate_type=GateType.BRANCH_PROTECTION,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        min_privilege=AttackerLevel.REPO_WRITE,
        summary=(
            f"can_approve_pull_request_reviews is enabled while protected branches "
            f"require reviews ({branch_list}); review workflow permissions and behavior."
        ),
        bypass_path=(
            f"Observed: can_approve_pull_request_reviews is enabled for {gate.full_name}\n"
            f"Observed: protected branches require reviews: {branch_list}\n"
            f"Inference: a workflow could approve a pull request only if it also has "
            f"pull-requests: write and executes an approval action\n"
            f"Potential consequence: automated approval may weaken the intended "
            f"human-review gate"
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
    """Detect rulesets configured to evaluate rather than enforce their rules."""
    findings: list[BypassFinding] = []

    for rs in gate.rulesets:
        if rs.enforcement != "evaluate":
            continue

        # Determine which branches this ruleset targets
        target_branches = _ruleset_target_branches(rs, gate.default_branch)

        branch_desc = ", ".join(target_branches) if target_branches else "configured branches"

        findings.append(BypassFinding(
            rule_id="GHOST-BP-006",
            rule_name="Ruleset in evaluate mode (not enforced)",
            repo=gate.full_name,
            gate_type=GateType.RULESET,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Ruleset '{rs.name}' is in evaluate mode, so this ruleset does "
                f"not enforce its configured rules on {branch_desc}."
            ),
            bypass_path=(
                f"Observed: ruleset '{rs.name}' targets {branch_desc}\n"
                f"Observed: enforcement mode is 'evaluate'\n"
                f"Inference: an operation that violates these rules is not blocked by "
                f"this ruleset\n"
                f"Unobserved prerequisite: no other branch protection or active ruleset "
                f"blocks the operation"
            ),
            evidence={
                "ruleset_name": rs.name,
                "ruleset_id": rs.id,
                "enforcement": rs.enforcement,
                "target_branches": target_branches,
                "rules": [r.get("type", "unknown") for r in rs.rules],
            },
            gating_conditions=[
                "Attacker must have write access to push or merge",
                "Other collected or uncollected controls must not block the operation",
            ],
            remediation=(
                f"Change ruleset '{rs.name}' enforcement from 'evaluate' to 'active'. "
                f"If evaluate mode is intentional, verify that other required controls enforce the policy.\n"
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
