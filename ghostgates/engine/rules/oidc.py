"""
ghostgates/engine/rules/oidc.py

OIDC subject claim bypass rules (GHOST-OIDC-001 through GHOST-OIDC-002).

GitHub Actions OIDC tokens allow workflows to authenticate to cloud
providers without static credentials. GhostGates observes GitHub-side
configuration only; it does not collect or validate the cloud provider's
trust policy.
"""

from __future__ import annotations

from ghostgates.engine.registry import registry
from ghostgates.engine.urls import environment_url, oidc_org_url, workflow_file_url
from ghostgates.models.enums import (
    AttackerLevel,
    Confidence,
    GateType,
    Severity,
)
from ghostgates.models.gates import GateModel
from ghostgates.models.findings import BypassFinding


# ==================================================================
# GHOST-OIDC-001: Default/broad OIDC subject claim
# ==================================================================

@registry.rule(
    rule_id="GHOST-OIDC-001",
    name="OIDC subject template requires trust-policy review",
    gate_type=GateType.OIDC,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("oidc", "cloud-access", "lateral-movement"),
)
def oidc_001_default_subject(gate: GateModel) -> list[BypassFinding]:
    """Flag GitHub OIDC subject configuration for paired trust-policy review.

    A finding is not proof that a cloud role can be assumed. That conclusion
    requires the external provider's trust policy, which is not collected.
    """
    findings: list[BypassFinding] = []

    oidc = gate.oidc

    # Check if OIDC is actually used (any workflow with id-token: write)
    uses_oidc = _repo_uses_oidc(gate)
    if not uses_oidc:
        return []  # repo doesn't use OIDC — not relevant

    # Check if org has customized the subject template
    if not oidc.org_level_template:
        findings.append(BypassFinding(
            rule_id="GHOST-OIDC-001",
            rule_name="OIDC subject template requires trust-policy review",
            repo=gate.full_name,
            gate_type=GateType.OIDC,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Repository {gate.full_name} uses OIDC for cloud access "
                f"and the org uses GitHub's default subject format; the external "
                f"cloud trust policy was not collected."
            ),
            bypass_path=(
                f"Observed: a workflow in {gate.full_name} requests id-token: write\n"
                f"Observed: the org has no custom OIDC subject template\n"
                f"Unobserved prerequisite: the cloud trust policy accepts a subject "
                f"broader than intended\n"
                f"Potential consequence: unintended workflow contexts may receive cloud access"
            ),
            evidence={
                "org_oidc_template": None,
                "uses_oidc": True,
                "oidc_workflows": _oidc_workflow_paths(gate),
            },
            gating_conditions=[
                "Cloud provider trust policy must not restrict the subject sufficiently",
                "Attacker must have write access to trigger a workflow with id-token: write",
            ],
            remediation=(
                "Customize the org OIDC subject template to include 'environment':\n"
                "  include_claim_keys: [repo, environment, ref]\n"
                "Then update cloud trust policies to check all three claims. "
                "This ensures only specific repos + environments + branches "
                "can assume specific cloud roles.\n"
                f"→ {oidc_org_url(gate.org)}"
            ),
            settings_url=oidc_org_url(gate.org),
            references=[
                "https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#customizing-the-subject-claims",
            ],
        ))
    else:
        # Org has a template — check if it includes environment
        if "environment" not in oidc.org_level_template:
            findings.append(BypassFinding(
                rule_id="GHOST-OIDC-001",
                rule_name="OIDC subject template requires trust-policy review",
                repo=gate.full_name,
                gate_type=GateType.OIDC,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Repository {gate.full_name} uses OIDC but the org subject "
                    f"template does not include 'environment'; whether this broadens "
                    f"access depends on the external cloud trust policy."
                ),
                bypass_path=(
                    f"Observed template: {oidc.org_level_template}\n"
                    f"Observed: 'environment' is not included\n"
                    f"Unobserved prerequisite: a cloud trust policy relies on the "
                    f"missing environment distinction"
                ),
                evidence={
                    "org_oidc_template": oidc.org_level_template,
                    "missing_claim": "environment",
                    "oidc_workflows": _oidc_workflow_paths(gate),
                },
                gating_conditions=[
                    "Cloud trust policy must not independently check environment",
                    "Attacker must have write access to trigger a workflow",
                ],
                remediation=(
                    "Add 'environment' to the org OIDC subject template:\n"
                    "  include_claim_keys: "
                    f"{sorted(set(oidc.org_level_template + ['environment']))}\n"
                    "Then update cloud trust policies to check the environment claim.\n"
                    f"→ {oidc_org_url(gate.org)}"
                ),
                settings_url=oidc_org_url(gate.org),
            ))

    return findings


# ==================================================================
# GHOST-OIDC-002: OIDC token used without environment gate
# ==================================================================

@registry.rule(
    rule_id="GHOST-OIDC-002",
    name="OIDC token used without environment gate",
    gate_type=GateType.OIDC,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("oidc", "environment", "cloud-access"),
)
def oidc_002_no_environment_gate(gate: GateModel) -> list[BypassFinding]:
    """Detect OIDC permission without an observed reviewer-gated environment.

    Cloud access remains conditional on the external provider accepting the
    issued token for a role; that trust policy is not collected.
    """
    findings: list[BypassFinding] = []

    # Get environments that have reviewers (actual gates)
    gated_envs = {env.name for env in gate.environments if env.reviewers}

    for wf in gate.workflows:
        # Check if workflow has id-token: write
        wf_has_oidc = _permissions_include_id_token_write(wf.permissions)

        for job in wf.jobs:
            job_has_oidc = _permissions_include_id_token_write(job.permissions)

            if not (wf_has_oidc or job_has_oidc):
                continue

            # Check if job has an environment gate
            env_name = _get_env_name(job.environment)

            if env_name and env_name in gated_envs:
                continue  # has a real environment gate — fine

            findings.append(BypassFinding(
                rule_id="GHOST-OIDC-002",
                rule_name="OIDC token used without environment gate",
                repo=gate.full_name,
                gate_type=GateType.OIDC,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Job '{job.name}' in '{wf.path}' requests OIDC token "
                    f"(id-token: write) but runs without a reviewer-gated environment."
                ),
                bypass_path=(
                    f"Observed: workflow '{wf.path}' job '{job.name}' has id-token: write\n"
                    f"Observed: job {'has no environment' if not env_name else f'uses environment {env_name!r} which has no reviewers'}\n"
                    f"Inference: an authorized workflow run can request an OIDC token "
                    f"without reviewer approval\n"
                    f"Unobserved prerequisite: a cloud provider trust policy accepts "
                    f"that token for a role"
                ),
                evidence={
                    "workflow": wf.path,
                    "job": job.name,
                    "environment": env_name,
                    "id_token_source": "workflow" if wf_has_oidc else "job",
                    "gated_environments": sorted(gated_envs),
                },
                gating_conditions=[
                    "Attacker must have write access to trigger the workflow",
                    "Cloud provider must accept the OIDC token",
                ],
                remediation=(
                    f"Add a reviewer-gated environment to job '{job.name}' in "
                    f"'{wf.path}'. This ensures OIDC tokens are only issued after "
                    f"human approval. Example:\n"
                    f"  jobs:\n"
                    f"    {job.name}:\n"
                    f"      environment: production\n"
                    f"      permissions:\n"
                    f"        id-token: write\n"
                    f"→ {workflow_file_url(gate.full_name, wf.path)}\n"
                    f"→ {environment_url(gate.full_name)}"
                ),
                settings_url=workflow_file_url(gate.full_name, wf.path),
            ))

    return findings


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _repo_uses_oidc(gate: GateModel) -> bool:
    """Check if any workflow in the repo requests id-token: write."""
    for wf in gate.workflows:
        if _permissions_include_id_token_write(wf.permissions):
            return True
        for job in wf.jobs:
            if _permissions_include_id_token_write(job.permissions):
                return True
    return False


def _permissions_include_id_token_write(permissions: dict) -> bool:
    """Check if a permissions dict includes id-token: write."""
    if not permissions:
        return False
    # Explicit id-token: write
    if permissions.get("id-token") == "write":
        return True
    # write-all shorthand includes id-token: write
    shorthand = permissions.get("_shorthand", "")
    if shorthand in ("write-all", "write"):
        return True
    return False


def _oidc_workflow_paths(gate: GateModel) -> list[str]:
    """Get paths of workflows that use OIDC."""
    paths = []
    for wf in gate.workflows:
        if _permissions_include_id_token_write(wf.permissions):
            paths.append(wf.path)
            continue
        for job in wf.jobs:
            if _permissions_include_id_token_write(job.permissions):
                paths.append(wf.path)
                break
    return paths


def _get_env_name(environment) -> str | None:
    """Extract environment name from string or dict."""
    if environment is None:
        return None
    if isinstance(environment, str):
        return environment
    if isinstance(environment, dict):
        return environment.get("name")
    return None
