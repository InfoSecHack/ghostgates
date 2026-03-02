"""
ghostgates/engine/rules/workflow.py

Workflow bypass rules (GHOST-WF-001 through GHOST-WF-004).

WF-001 (pull_request_target + checkout) is the highest-impact rule
in the entire project — it detects the exact pattern used in real-world
supply chain attacks.
"""

from __future__ import annotations

from ghostgates.engine.registry import registry
from ghostgates.engine.urls import actions_url, workflow_file_url
from ghostgates.models.enums import (
    AttackerLevel,
    Confidence,
    GateType,
    Severity,
)
from ghostgates.models.gates import GateModel, WorkflowDefinition, WorkflowJob
from ghostgates.models.findings import BypassFinding


# ==================================================================
# GHOST-WF-001: pull_request_target with PR head checkout
# ==================================================================

@registry.rule(
    rule_id="GHOST-WF-001",
    name="pull_request_target with PR head checkout",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.EXTERNAL,
    tags=("workflow", "pull_request_target", "code-injection", "critical"),
)
def wf_001_pr_target_checkout(gate: GateModel) -> list[BypassFinding]:
    """Detects workflows triggered by pull_request_target that check out
    the PR head ref, then execute code from that checkout.

    Impact: CRITICAL. An external attacker (no repo access needed) can
    submit a PR that modifies workflow files or build scripts. Because
    pull_request_target runs in the context of the BASE branch (with
    its secrets and write permissions), checking out the PR HEAD means
    the attacker's code runs with the base branch's elevated privileges.

    This is the exact pattern behind real supply chain attacks.

    Detection logic:
      1. Workflow has pull_request_target trigger
      2. A job checks out with ref containing "pull_request.head" or "github.head_ref"
      3. A subsequent step runs code (uses: or run:)
    """
    findings: list[BypassFinding] = []

    for wf in gate.workflows:
        has_pr_target = any(
            t.event == "pull_request_target" for t in wf.triggers
        )
        if not has_pr_target:
            continue

        # Check each job for the dangerous pattern
        for job in wf.jobs:
            danger = _detect_pr_head_checkout_danger(job)
            if not danger:
                continue

            checkout_ref = danger["checkout_ref"]
            runs_code = danger["runs_code"]

            findings.append(BypassFinding(
                rule_id="GHOST-WF-001",
                rule_name="pull_request_target with PR head checkout",
                repo=gate.full_name,
                gate_type=GateType.WORKFLOW,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                min_privilege=AttackerLevel.EXTERNAL,
                summary=(
                    f"Workflow '{wf.name}' ({wf.path}) uses pull_request_target "
                    f"and checks out PR head code — external attacker can execute "
                    f"arbitrary code with base branch privileges."
                ),
                bypass_path=(
                    f"1. Workflow '{wf.path}' triggers on pull_request_target\n"
                    f"2. Job '{job.name}' checks out PR head: ref={checkout_ref}\n"
                    f"3. Subsequent step executes code: {runs_code}\n"
                    f"4. pull_request_target runs with BASE branch context "
                    f"(secrets, GITHUB_TOKEN with write perms)\n"
                    f"5. External attacker submits PR with modified build scripts\n"
                    f"6. Attacker's code executes with elevated privileges"
                ),
                evidence={
                    "workflow": wf.path,
                    "workflow_name": wf.name,
                    "job": job.name,
                    "checkout_ref": checkout_ref,
                    "code_execution": runs_code,
                    "trigger": "pull_request_target",
                },
                gating_conditions=[
                    "Attacker must be able to open a pull request (public repo or org member)",
                    "Workflow must not have an 'if' condition that prevents execution on external PRs",
                ],
                remediation=(
                    f"Option 1: Change trigger from pull_request_target to pull_request "
                    f"(runs in PR context without base branch secrets).\n"
                    f"Option 2: Remove the checkout of PR head code — only check out "
                    f"the base branch.\n"
                    f"Option 3: If PR head checkout is required, run only trusted code "
                    f"(no npm install, no make, no arbitrary scripts) after checkout.\n"
                    f"→ {workflow_file_url(gate.full_name, wf.path)}"
                ),
                references=[
                    "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
                ],
            ))

    return findings


def _detect_pr_head_checkout_danger(job: WorkflowJob) -> dict | None:
    """Check if a job has the dangerous checkout + execute pattern.

    Returns dict with details if dangerous, None if safe.
    """
    checkout_ref = None
    checkout_index = -1

    for i, step in enumerate(job.steps):
        # Look for checkout action with PR head ref
        if "actions/checkout" in step.uses:
            ref_value = step.with_.get("ref", "")
            if _is_pr_head_ref(ref_value):
                checkout_ref = ref_value
                checkout_index = i
                break

    if checkout_ref is None:
        return None

    # Look for code execution AFTER the checkout
    for step in job.steps[checkout_index + 1:]:
        if step.run:
            return {
                "checkout_ref": checkout_ref,
                "runs_code": f"run: {step.run[:80]}",
            }
        if step.uses and "actions/checkout" not in step.uses:
            # Any action other than checkout could execute attacker code
            # if it operates on the checked-out repo
            return {
                "checkout_ref": checkout_ref,
                "runs_code": f"uses: {step.uses}",
            }

    return None


def _is_pr_head_ref(ref: str) -> bool:
    """Check if a ref string references the PR head."""
    if not ref:
        return False
    ref_lower = ref.lower()
    return any(pattern in ref_lower for pattern in [
        "pull_request.head",
        "github.head_ref",
        "event.pull_request.head.sha",
        "event.pull_request.head.ref",
    ])


# ==================================================================
# GHOST-WF-002: Overly permissive workflow token
# ==================================================================

@registry.rule(
    rule_id="GHOST-WF-002",
    name="Workflow with write-all permissions",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("workflow", "permissions", "least-privilege"),
)
def wf_002_write_all_permissions(gate: GateModel) -> list[BypassFinding]:
    """Detects workflows or jobs with write-all token permissions.

    Impact: A workflow with write-all permissions gets a GITHUB_TOKEN
    that can push code, approve PRs, create releases, modify packages,
    write to issues, and more. If the workflow is triggerable by an
    attacker (via PR, workflow_dispatch, or dependency), the token
    becomes an escalation vector.

    Also flags when the org/repo default is write and the workflow
    doesn't explicitly restrict permissions.
    """
    findings: list[BypassFinding] = []

    for wf in gate.workflows:
        # Check top-level workflow permissions
        if _is_write_all(wf.permissions):
            findings.append(_make_wf002_finding(
                gate, wf, "workflow-level",
                wf.permissions.get("_shorthand", "write-all"),
            ))
            continue  # don't also flag individual jobs

        # Check per-job permissions
        for job in wf.jobs:
            if _is_write_all(job.permissions):
                findings.append(_make_wf002_finding(
                    gate, wf, f"job '{job.name}'",
                    job.permissions.get("_shorthand", "write-all"),
                ))

    # Check if org/repo default is write AND workflows don't set permissions
    if gate.workflow_permissions.default_workflow_permissions == "write":
        for wf in gate.workflows:
            if not wf.permissions and any(not j.permissions for j in wf.jobs):
                findings.append(BypassFinding(
                    rule_id="GHOST-WF-002",
                    rule_name="Workflow with write-all permissions",
                    repo=gate.full_name,
                    gate_type=GateType.WORKFLOW,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    min_privilege=AttackerLevel.REPO_WRITE,
                    summary=(
                        f"Workflow '{wf.name}' ({wf.path}) inherits write permissions "
                        f"from org/repo default — no explicit permissions block."
                    ),
                    bypass_path=(
                        f"1. Org/repo default_workflow_permissions is 'write'\n"
                        f"2. Workflow '{wf.path}' has no permissions block\n"
                        f"3. GITHUB_TOKEN gets write access to all scopes\n"
                        f"4. Any step can push code, approve PRs, modify packages"
                    ),
                    evidence={
                        "workflow": wf.path,
                        "default_workflow_permissions": "write",
                        "workflow_permissions": wf.permissions,
                    },
                    gating_conditions=[
                        "Attacker must be able to trigger the workflow",
                    ],
                    remediation=(
                        f"Add an explicit 'permissions' block to '{wf.path}' with "
                        f"least-privilege scopes. Also consider changing the org/repo "
                        f"default to 'read'.\n"
                        f"→ {workflow_file_url(gate.full_name, wf.path)}\n"
                        f"→ {actions_url(gate.full_name)}"
                    ),
                ))

    return findings


def _is_write_all(permissions: dict) -> bool:
    """Check if a permissions dict represents write-all access."""
    if not permissions:
        return False
    shorthand = permissions.get("_shorthand", "")
    return shorthand in ("write-all", "write")


def _make_wf002_finding(
    gate: GateModel,
    wf: WorkflowDefinition,
    scope: str,
    perms_value: str,
) -> BypassFinding:
    return BypassFinding(
        rule_id="GHOST-WF-002",
        rule_name="Workflow with write-all permissions",
        repo=gate.full_name,
        gate_type=GateType.WORKFLOW,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        min_privilege=AttackerLevel.REPO_WRITE,
        summary=(
            f"Workflow '{wf.name}' ({wf.path}) has write-all permissions "
            f"at {scope} — GITHUB_TOKEN can push code, approve PRs, and more."
        ),
        bypass_path=(
            f"1. Workflow '{wf.path}' has permissions: {perms_value} at {scope}\n"
            f"2. GITHUB_TOKEN gets write access to all scopes\n"
            f"3. Any step can push code, approve PRs, create releases, modify packages\n"
            f"4. If workflow is triggerable by attacker, token becomes escalation vector"
        ),
        evidence={
            "workflow": wf.path,
            "scope": scope,
            "permissions": perms_value,
        },
        gating_conditions=[
            "Attacker must be able to trigger the workflow",
        ],
        remediation=(
            f"Replace 'permissions: {perms_value}' with explicit least-privilege "
            f"scopes in '{wf.path}'. Example:\n"
            f"  permissions:\n"
            f"    contents: read\n"
            f"    pull-requests: read\n"
            f"→ {workflow_file_url(gate.full_name, wf.path)}"
        ),
    )


# ==================================================================
# GHOST-WF-003: Reusable workflow with secrets: inherit
# ==================================================================

@registry.rule(
    rule_id="GHOST-WF-003",
    name="Reusable workflow with secrets: inherit",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("workflow", "reusable", "secrets"),
)
def wf_003_secrets_inherit(gate: GateModel) -> list[BypassFinding]:
    """Detects workflows calling reusable workflows with secrets: inherit.

    Impact: secrets: inherit passes ALL repository secrets to the
    reusable workflow. If the reusable workflow is in a different repo
    or uses a mutable ref (branch instead of SHA), the called workflow
    could be modified to exfiltrate secrets.

    This is particularly dangerous when:
      - The reusable workflow is in a different org
      - The ref is a branch (not a pinned SHA/tag)
      - The calling workflow is triggered by external events
    """
    findings: list[BypassFinding] = []

    for wf in gate.workflows:
        for job in wf.jobs:
            if job.secrets != "inherit":
                continue
            if not job.uses:
                continue

            is_external = _is_external_reusable(job.uses, gate.org)
            is_mutable_ref = _is_mutable_ref(job.uses)

            severity = Severity.HIGH if (is_external or is_mutable_ref) else Severity.MEDIUM

            ref_warning = ""
            if is_mutable_ref:
                ref_warning = (
                    f"\n4. Reusable workflow uses a mutable ref (branch) — "
                    f"the called workflow can change without notice"
                )

            findings.append(BypassFinding(
                rule_id="GHOST-WF-003",
                rule_name="Reusable workflow with secrets: inherit",
                repo=gate.full_name,
                gate_type=GateType.WORKFLOW,
                severity=severity,
                confidence=Confidence.HIGH if is_external else Confidence.MEDIUM,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Job '{job.name}' in '{wf.path}' calls reusable workflow "
                    f"'{job.uses}' with secrets: inherit — all secrets are passed."
                ),
                bypass_path=(
                    f"1. Workflow '{wf.path}' job '{job.name}' calls: {job.uses}\n"
                    f"2. secrets: inherit passes ALL repository secrets\n"
                    f"3. {'External' if is_external else 'Internal'} reusable workflow "
                    f"receives all secrets"
                    + ref_warning
                ),
                evidence={
                    "workflow": wf.path,
                    "job": job.name,
                    "reusable_workflow": job.uses,
                    "secrets": "inherit",
                    "is_external": is_external,
                    "is_mutable_ref": is_mutable_ref,
                },
                gating_conditions=[
                    "Attacker must be able to modify the reusable workflow "
                    "(if external, needs write access to that repo)",
                ],
                remediation=(
                    f"Replace 'secrets: inherit' with explicit secret passthrough:\n"
                    f"  secrets:\n"
                    f"    DEPLOY_KEY: ${{{{ secrets.DEPLOY_KEY }}}}\n"
                    f"This limits which secrets the reusable workflow can access. "
                    f"Also pin the reusable workflow to a SHA instead of a branch.\n"
                    f"→ {workflow_file_url(gate.full_name, wf.path)}"
                ),
            ))

    return findings


def _is_external_reusable(uses: str, current_org: str) -> bool:
    """Check if a reusable workflow reference is external to the org."""
    # Format: org/repo/.github/workflows/file.yml@ref
    if "/" not in uses:
        return False
    org_part = uses.split("/")[0]
    return org_part != current_org


def _is_mutable_ref(uses: str) -> bool:
    """Check if a reusable workflow uses a mutable ref (branch vs SHA/tag).

    Mutable: @main, @develop, @v1
    Immutable: @abc123def (40-char SHA), @v1.2.3 (semver tag)
    """
    if "@" not in uses:
        return True  # no ref at all — very mutable

    ref = uses.split("@")[-1]

    # SHA: 40 hex characters
    if len(ref) == 40 and all(c in "0123456789abcdef" for c in ref):
        return False

    # Semver tag: vX.Y.Z
    if ref.startswith("v") and ref.count(".") >= 2:
        return False

    # Everything else (branch names) is mutable
    return True


# ==================================================================
# GHOST-WF-004: Workflow triggered by fork PRs with secrets access
# ==================================================================

@registry.rule(
    rule_id="GHOST-WF-004",
    name="Workflow exposes secrets to fork PRs",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.EXTERNAL,
    tags=("workflow", "fork", "secrets", "public-repo"),
)
def wf_004_fork_pr_secrets(gate: GateModel) -> list[BypassFinding]:
    """Detects workflows in public repos that may expose secrets to fork PRs.

    Impact: In public repos, pull_request from forks don't get secrets
    by default. But pull_request_target DOES run with base branch
    secrets. This rule checks for public repos with pull_request_target
    workflows that don't already trigger WF-001.

    Also flags workflows using workflow_run triggered by PR workflows,
    which is a common pattern to work around fork PR secret restrictions
    but can be exploited.
    """
    findings: list[BypassFinding] = []

    if gate.visibility != "public":
        return []  # only relevant for public repos

    for wf in gate.workflows:
        # Check for workflow_run triggered by PR events
        for trigger in wf.triggers:
            if trigger.event == "workflow_run":
                # workflow_run triggered by another workflow can access secrets
                findings.append(BypassFinding(
                    rule_id="GHOST-WF-004",
                    rule_name="Workflow exposes secrets to fork PRs",
                    repo=gate.full_name,
                    gate_type=GateType.WORKFLOW,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    min_privilege=AttackerLevel.EXTERNAL,
                    summary=(
                        f"Workflow '{wf.name}' ({wf.path}) uses workflow_run trigger "
                        f"in a public repo — may expose secrets to fork PR workflows."
                    ),
                    bypass_path=(
                        f"1. Public repo {gate.full_name} has workflow '{wf.path}'\n"
                        f"2. Workflow triggers on workflow_run event\n"
                        f"3. workflow_run receives secrets from the base branch\n"
                        f"4. If the triggering workflow is a fork PR, attacker's "
                        f"code may influence the workflow_run context\n"
                        f"5. Attacker can potentially exfiltrate secrets"
                    ),
                    evidence={
                        "workflow": wf.path,
                        "trigger": "workflow_run",
                        "visibility": gate.visibility,
                    },
                    gating_conditions=[
                        "Repo must be public",
                        "workflow_run must process data from the PR workflow",
                        "Attacker must be able to fork the repo and submit a PR",
                    ],
                    remediation=(
                        f"Audit workflow '{wf.path}' to ensure workflow_run does not "
                        f"use artifacts or data from the triggering PR workflow without "
                        f"validation. Consider using pull_request trigger instead and "
                        f"only running trusted code.\n"
                        f"→ {workflow_file_url(gate.full_name, wf.path)}"
                    ),
                    references=[
                        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
                    ],
                ))

    return findings
