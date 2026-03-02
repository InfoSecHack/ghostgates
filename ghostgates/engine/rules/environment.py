"""
ghostgates/engine/rules/environment.py

Environment protection bypass rules (GHOST-ENV-001 through GHOST-ENV-003).
"""

from __future__ import annotations

from ghostgates.engine.registry import registry
from ghostgates.engine.urls import environment_url
from ghostgates.models.enums import (
    AttackerLevel,
    Confidence,
    GateType,
    Severity,
)
from ghostgates.models.gates import GateModel
from ghostgates.models.findings import BypassFinding


# ==================================================================
# GHOST-ENV-001: Environment with no required reviewers
# ==================================================================

@registry.rule(
    rule_id="GHOST-ENV-001",
    name="Environment with no required reviewers",
    gate_type=GateType.ENVIRONMENT,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("environment", "deployment"),
)
def env_001_no_reviewers(gate: GateModel) -> list[BypassFinding]:
    """Detects environments that have no required reviewers.

    Impact: Any workflow that references this environment can deploy
    without human approval. If the environment holds secrets or
    controls production access, this is a direct path to unreviewed
    deployment.

    Only fires for environments that appear security-relevant:
    production, staging, or environments with secrets/custom rules.
    """
    findings: list[BypassFinding] = []

    for env in gate.environments:
        if env.reviewers:
            continue  # has reviewers — fine

        # Only flag environments that look security-relevant
        if not _is_security_relevant_env(env):
            continue

        findings.append(BypassFinding(
            rule_id="GHOST-ENV-001",
            rule_name="Environment with no required reviewers",
            repo=gate.full_name,
            gate_type=GateType.ENVIRONMENT,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Environment '{env.name}' has no required reviewers — "
                f"deployments proceed without human approval."
            ),
            bypass_path=(
                f"1. Environment '{env.name}' in {gate.full_name} has zero required reviewers\n"
                f"2. Any workflow referencing this environment deploys without approval\n"
                f"3. Attacker with write access triggers workflow targeting '{env.name}'\n"
                f"4. Deployment executes immediately with no human gate"
            ),
            evidence={
                "environment": env.name,
                "reviewer_count": 0,
                "wait_timer": env.wait_timer,
                "deployment_branch_policy": env.deployment_branch_policy.type,
                "has_custom_rules": len(env.custom_rules) > 0,
            },
            gating_conditions=[
                "Attacker must have write access to trigger a workflow",
                f"A workflow must reference the '{env.name}' environment",
            ],
            remediation=(
                f"Add required reviewers to the '{env.name}' environment. "
                f"At minimum, add a security or platform team as reviewers "
                f"for production-tier environments.\n"
                f"→ {environment_url(gate.full_name)}"
            ),
            settings_url=environment_url(gate.full_name),
            references=[
                "https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment",
            ],
        ))

    return findings


# ==================================================================
# GHOST-ENV-002: Environment deploys from any branch
# ==================================================================

@registry.rule(
    rule_id="GHOST-ENV-002",
    name="Environment allows deployment from any branch",
    gate_type=GateType.ENVIRONMENT,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("environment", "deployment", "branch-policy"),
)
def env_002_any_branch_deploy(gate: GateModel) -> list[BypassFinding]:
    """Detects environments where deployment_branch_policy allows all branches.

    Impact: An attacker with write access can create a branch with
    malicious code and deploy it to the environment, bypassing any
    branch protection on main/develop. This is the most common
    environment misconfiguration.

    Only fires for environments with reviewers (if no reviewers,
    ENV-001 already covers it as higher severity).
    """
    findings: list[BypassFinding] = []

    for env in gate.environments:
        if env.deployment_branch_policy.type != "all":
            continue  # has some branch restriction

        # Only flag if environment has reviewers (otherwise ENV-001 fires)
        if not env.reviewers:
            continue

        if not _is_security_relevant_env(env):
            continue

        findings.append(BypassFinding(
            rule_id="GHOST-ENV-002",
            rule_name="Environment allows deployment from any branch",
            repo=gate.full_name,
            gate_type=GateType.ENVIRONMENT,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Environment '{env.name}' has required reviewers but allows "
                f"deployment from any branch — attacker can deploy from an "
                f"unprotected branch."
            ),
            bypass_path=(
                f"1. Environment '{env.name}' requires {len(env.reviewers)} reviewer(s)\n"
                f"2. deployment_branch_policy is 'all' — any branch can deploy\n"
                f"3. Attacker creates a feature branch with malicious code\n"
                f"4. Attacker triggers workflow from that branch targeting '{env.name}'\n"
                f"5. Reviewer sees the deployment request but may not review "
                f"the source branch (which has no protection rules)"
            ),
            evidence={
                "environment": env.name,
                "deployment_branch_policy": "all",
                "reviewer_count": len(env.reviewers),
                "reviewers": [r.login for r in env.reviewers],
            },
            gating_conditions=[
                "Attacker must have write access to create branches",
                "Reviewer must approve the deployment (social engineering or inattention)",
            ],
            remediation=(
                f"Set deployment_branch_policy on '{env.name}' to "
                f"'protected_branches' to only allow deployment from branches "
                f"with branch protection rules, or use 'selected' to restrict "
                f"to specific branches.\n"
                f"→ {environment_url(gate.full_name)}"
            ),
            settings_url=environment_url(gate.full_name),
        ))

    return findings


# ==================================================================
# GHOST-ENV-003: Wait timer as only protection (auto-approve)
# ==================================================================

@registry.rule(
    rule_id="GHOST-ENV-003",
    name="Wait timer as only environment protection",
    gate_type=GateType.ENVIRONMENT,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("environment", "deployment", "wait-timer"),
)
def env_003_wait_timer_only(gate: GateModel) -> list[BypassFinding]:
    """Detects environments where a wait timer is the only protection.

    Impact: Wait timers delay deployment but don't require human approval.
    After the timer expires, the deployment proceeds automatically.
    If no reviewers are configured, the wait timer creates a false
    sense of security — it's a speed bump, not a gate.
    """
    findings: list[BypassFinding] = []

    for env in gate.environments:
        if env.wait_timer == 0:
            continue

        if env.reviewers:
            continue  # has real reviewers — wait timer is additive

        if not _is_security_relevant_env(env):
            continue

        findings.append(BypassFinding(
            rule_id="GHOST-ENV-003",
            rule_name="Wait timer as only environment protection",
            repo=gate.full_name,
            gate_type=GateType.ENVIRONMENT,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Environment '{env.name}' has a {env.wait_timer}-minute wait timer "
                f"but no required reviewers — deployment auto-approves after the timer."
            ),
            bypass_path=(
                f"1. Environment '{env.name}' has a {env.wait_timer}-minute wait timer\n"
                f"2. No required reviewers are configured\n"
                f"3. Attacker triggers deployment workflow\n"
                f"4. After {env.wait_timer} minutes, deployment proceeds automatically\n"
                f"5. No human ever reviews or approves the deployment"
            ),
            evidence={
                "environment": env.name,
                "wait_timer": env.wait_timer,
                "reviewer_count": 0,
            },
            gating_conditions=[
                "Attacker must have write access to trigger a workflow",
                f"Attacker must wait {env.wait_timer} minutes for auto-approval",
            ],
            remediation=(
                f"Add required reviewers to the '{env.name}' environment. "
                f"Wait timers are useful as an additional safety delay but "
                f"should not be the sole protection mechanism.\n"
                f"→ {environment_url(gate.full_name)}"
            ),
            settings_url=environment_url(gate.full_name),
        ))

    return findings


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_SECURITY_RELEVANT_NAMES = {
    "production", "prod", "prd",
    "staging", "stage", "stg",
    "pre-production", "preprod",
    "release",
    "live",
}


def _is_security_relevant_env(env) -> bool:
    """Determine if an environment name suggests security relevance.

    Returns True for:
      - Names matching known patterns (production, staging, etc.)
      - Environments with custom protection rules
      - Environments with secrets
    """
    name_lower = env.name.lower().strip()

    # Direct name match
    if name_lower in _SECURITY_RELEVANT_NAMES:
        return True

    # Partial match (e.g., "aws-production", "gcp-staging")
    for pattern in _SECURITY_RELEVANT_NAMES:
        if pattern in name_lower:
            return True

    # Has custom protection rules → probably important
    if env.custom_rules:
        return True

    # Has secrets → probably important
    if env.has_secrets:
        return True

    return False
