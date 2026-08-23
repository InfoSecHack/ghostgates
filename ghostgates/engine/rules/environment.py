"""
ghostgates/engine/rules/environment.py

Environment protection bypass rules (GHOST-ENV-001 through GHOST-ENV-003).
"""

from __future__ import annotations
import re


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
    """Detect relevant environments with no reviewer or other collected gate."""
    findings: list[BypassFinding] = []

    for env in gate.environments:
        # Custom protection rule behavior is not collected, so its presence
        # cannot prove equivalence to reviewer approval.
        if env.reviewers or env.wait_timer:
            continue

        # Only flag environments that look security-relevant
        if not _is_security_relevant_env(env):
            continue

        custom_rule_observation = (
            f"Observed: {len(env.custom_rules)} custom protection rule(s); "
            "their behavior is unmodeled"
            if env.custom_rules
            else "Observed: no custom protection rules"
        )
        findings.append(BypassFinding(
            rule_id="GHOST-ENV-001",
            rule_name="Environment with no required reviewers",
            repo=gate.full_name,
            gate_type=GateType.ENVIRONMENT,
            severity=Severity.MEDIUM,
            confidence=(Confidence.MEDIUM if env.custom_rules else Confidence.HIGH),
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Environment '{env.name}' has no required reviewers; "
                f"GitHub reviewer approval is not configured."
            ),
            bypass_path=(
                f"Observed: environment '{env.name}' has no required reviewers "
                f"or wait timer\n"
                f"{custom_rule_observation}\n"
                f"Unobserved prerequisite: a reachable workflow job uses this environment\n"
                f"Potential consequence: that job has no approval step supplied by the "
                f"GitHub environment"
            ),
            evidence={
                "environment": env.name,
                "reviewer_count": 0,
                "wait_timer": env.wait_timer,
                "deployment_branch_policy": env.deployment_branch_policy.type,
                "has_custom_rules": len(env.custom_rules) > 0,
            },
            gating_conditions=[
                "Attacker must be able to trigger the relevant workflow job",
                f"A workflow must reference the '{env.name}' environment",
                "Any custom protection rule must not independently enforce equivalent approval",
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
    """Detect reviewer-gated environments that accept jobs from any branch."""
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
            confidence=Confidence.MEDIUM,
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Environment '{env.name}' has required reviewers but allows "
                f"deployment jobs from any branch; branch protection is not itself "
                f"a source restriction."
            ),
            bypass_path=(
                f"Observed: environment '{env.name}' requires {len(env.reviewers)} reviewer(s)\n"
                f"Observed: deployment_branch_policy is 'all'\n"
                f"Unobserved prerequisite: a reachable workflow permits this environment "
                f"from an attacker-controlled branch\n"
                f"Potential consequence: environment approval can be requested from a "
                f"branch outside the intended protected-branch flow"
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
                "A relevant workflow must be triggerable from the attacker's branch",
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
# GHOST-ENV-003: Wait timer without required reviewers
# ==================================================================

@registry.rule(
    rule_id="GHOST-ENV-003",
    name="Wait timer without reviewer approval",
    gate_type=GateType.ENVIRONMENT,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("environment", "deployment", "wait-timer"),
)
def env_003_wait_timer_only(gate: GateModel) -> list[BypassFinding]:
    """Detect relevant environments with a timer but no reviewer approval."""
    findings: list[BypassFinding] = []

    for env in gate.environments:
        if env.wait_timer == 0:
            continue

        if env.reviewers:
            continue

        if not _is_security_relevant_env(env):
            continue

        custom_rule_observation = (
            f"Observed: {len(env.custom_rules)} custom protection rule(s); "
            "their behavior is unmodeled"
            if env.custom_rules
            else "Observed: no custom protection rules"
        )
        findings.append(BypassFinding(
            rule_id="GHOST-ENV-003",
            rule_name="Wait timer without reviewer approval",
            repo=gate.full_name,
            gate_type=GateType.ENVIRONMENT,
            severity=Severity.MEDIUM,
            confidence=(Confidence.MEDIUM if env.custom_rules else Confidence.HIGH),
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Environment '{env.name}' has a {env.wait_timer}-minute wait timer "
                f"but no required reviewers."
            ),
            bypass_path=(
                f"Observed: environment '{env.name}' has a {env.wait_timer}-minute wait timer\n"
                f"Observed: no required reviewers are configured\n"
                f"{custom_rule_observation}\n"
                f"Unobserved prerequisite: a reachable workflow job uses this environment\n"
                f"Potential consequence: after the timer, the environment supplies no "
                f"human approval step"
            ),
            evidence={
                "environment": env.name,
                "wait_timer": env.wait_timer,
                "reviewer_count": 0,
                "has_custom_rules": bool(env.custom_rules),
            },
            gating_conditions=[
                "Attacker must be able to trigger the relevant workflow job",
                f"The job must remain eligible through the {env.wait_timer}-minute wait",
                "Any custom protection rule must not independently enforce equivalent approval",
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

    Names are matched as tokens to avoid treating names such as ``livereload``
    or ``stagecoach`` as production-like environments.
    """
    name_lower = env.name.lower().strip()

    # Direct name match
    if name_lower in _SECURITY_RELEVANT_NAMES:
        return True

    tokens = set(re.split(r"[^a-z0-9]+", name_lower))
    if tokens & _SECURITY_RELEVANT_NAMES:
        return True

    # Has custom protection rules → probably important
    if env.custom_rules:
        return True

    return False
