"""
ghostgates/engine/rules/workflow.py

Workflow configuration rules (GHOST-WF-001 through GHOST-WF-008).
"""

from __future__ import annotations

import re

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

    The base-branch context may have sensitive credentials, but their
    availability and scopes are separate configuration prerequisites.

    Detection logic:
      1. Workflow has pull_request_target trigger
      2. A job checks out with ref containing "pull_request.head" or "github.head_ref"
      3. A subsequent shell step or local action runs checked-out code
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
            execution_is_certain = danger["execution_is_certain"]
            min_privilege = (
                AttackerLevel.EXTERNAL if gate.visibility == "public"
                else AttackerLevel.ORG_MEMBER
            )

            findings.append(BypassFinding(
                rule_id="GHOST-WF-001",
                rule_name="pull_request_target with PR head checkout",
                repo=gate.full_name,
                gate_type=GateType.WORKFLOW,
                severity=Severity.CRITICAL,
                confidence=(
                    Confidence.HIGH if execution_is_certain else Confidence.MEDIUM
                ),
                min_privilege=min_privilege,
                summary=(
                    f"Workflow '{wf.name}' ({wf.path}) uses pull_request_target "
                    f"and {'executes' if execution_is_certain else 'may execute'} "
                    f"checked-out PR head code in the base-branch workflow context."
                ),
                bypass_path=(
                    f"Observed: workflow '{wf.path}' triggers on pull_request_target\n"
                    f"Observed: job '{job.name}' checks out PR head: ref={checkout_ref}\n"
                    f"{'Observed' if execution_is_certain else 'Inference'}: a later "
                    f"step {'executes' if execution_is_certain else 'may execute'} "
                    f"checked-out code: {runs_code}\n"
                    f"Inference: a PR author may influence code running in the "
                    f"base-branch workflow context\n"
                    f"Potential consequence: credentials granted to that job may be exposed"
                ),
                evidence={
                    "workflow": wf.path,
                    "workflow_name": wf.name,
                    "job": job.name,
                    "checkout_ref": checkout_ref,
                    "code_execution": runs_code,
                    "trigger": "pull_request_target",
                    "execution_is_certain": execution_is_certain,
                },
                gating_conditions=[
                    "Attacker must be able to open a pull request",
                    "Workflow must not have an 'if' condition that prevents execution on external PRs",
                    "Sensitive impact requires secrets or a privileged GITHUB_TOKEN to be available",
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
                settings_url=workflow_file_url(gate.full_name, wf.path),
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

    # Certain evidence dominates an earlier ambiguous remote-action signal.
    inferred_danger = None
    for step in job.steps[checkout_index + 1:]:
        if step.run:
            return {
                "checkout_ref": checkout_ref,
                "runs_code": f"run: {step.run[:80]}",
                "execution_is_certain": True,
            }
        if step.uses.startswith("./"):
            return {
                "checkout_ref": checkout_ref,
                "runs_code": f"local action: {step.uses}",
                "execution_is_certain": True,
            }
        execution_input = _remote_execution_input(step.uses, step.with_)
        if execution_input and inferred_danger is None:
            inferred_danger = {
                "checkout_ref": checkout_ref,
                "runs_code": execution_input,
                "execution_is_certain": False,
            }

    return inferred_danger


_EXECUTION_INPUT_KEYS = {
    "args", "arguments", "cmd", "command", "goals", "script", "tasks",
}
_EXECUTION_TERMS = {
    "assemble", "build", "check", "deploy", "gradle", "install", "make",
    "mvn", "npm", "package", "pip", "publish", "run", "test", "yarn",
}


def _execution_tokens(value: object) -> set[str]:
    """Normalize scalar or list action inputs without substring matching."""
    if isinstance(value, (list, tuple, set)):
        tokens: set[str] = set()
        for item in value:
            tokens.update(_execution_tokens(item))
        return tokens
    if not isinstance(value, (str, int, float, bool)):
        return set()
    return set(re.findall(r"[a-z0-9_.-]+", str(value).lower()))


def _remote_execution_input(uses: str, inputs: dict) -> str | None:
    """Describe a remote action input that plausibly runs repository code.

    A remote action reference alone does not demonstrate code execution, so
    setup-only actions are not reported merely because they follow checkout.
    """
    if not uses or uses.startswith("./"):
        return None
    for key, value in inputs.items():
        if key.lower() not in _EXECUTION_INPUT_KEYS:
            continue
        if _execution_tokens(value) & _EXECUTION_TERMS:
            return f"remote action: {uses} with {key}={str(value)[:80]}"
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

    The permission is observed. A security consequence also requires an
    attacker-reachable workflow and steps that use a granted write scope.
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
                        f"Observed: org/repo default_workflow_permissions is 'write'\n"
                        f"Observed: workflow '{wf.path}' has no permissions block\n"
                        f"Inference: jobs without narrower permissions inherit token write scopes\n"
                        f"Potential consequence depends on reachable triggers, workflow steps, "
                        f"and other repository controls"
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
                    settings_url=workflow_file_url(gate.full_name, wf.path),
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
            f"Workflow '{wf.name}' ({wf.path}) requests write-all permissions "
            f"at {scope}."
        ),
        bypass_path=(
            f"Observed: workflow '{wf.path}' has permissions: {perms_value} at {scope}\n"
            f"Inference: its jobs can receive token write scopes\n"
            f"Unobserved prerequisites: an attacker-reachable trigger and steps that use "
            f"a security-sensitive write scope"
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
        settings_url=workflow_file_url(gate.full_name, wf.path),
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

    The called workflow receives secrets made available by the caller.
    A cross-repository call or mutable ref expands the trust boundary.
    """
    findings: list[BypassFinding] = []

    for wf in gate.workflows:
        for job in wf.jobs:
            if job.secrets != "inherit":
                continue
            if not job.uses:
                continue

            is_external = _is_external_reusable(job.uses, gate.org)
            is_mutable_ref = not job.uses.startswith("./") and _is_mutable_ref(job.uses)

            ref_warning = ""
            if is_mutable_ref:
                ref_warning = (
                    f"\nObserved: the reusable workflow uses a mutable ref, so "
                    f"the called workflow can change without notice"
                )

            findings.append(BypassFinding(
                rule_id="GHOST-WF-003",
                rule_name="Reusable workflow with secrets: inherit",
                repo=gate.full_name,
                gate_type=GateType.WORKFLOW,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Job '{job.name}' in '{wf.path}' calls reusable workflow "
                    f"'{job.uses}' with secrets: inherit."
                ),
                bypass_path=(
                    f"Observed: workflow '{wf.path}' job '{job.name}' calls: {job.uses}\n"
                    f"Observed: the call uses secrets: inherit\n"
                    f"Inference: the {'external' if is_external else 'internal'} reusable "
                    f"workflow may receive caller secrets that are eligible for inheritance\n"
                    f"Unobserved prerequisite: the caller has eligible secrets and the called workflow uses them"
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
                    "Caller must have secrets eligible for inheritance",
                    "The called workflow must consume an inherited secret",
                    "A hostile consequence requires attacker influence over the called workflow or its inputs",
                ],
                remediation=(
                    f"Replace 'secrets: inherit' with explicit secret passthrough:\n"
                    f"  secrets:\n"
                    f"    DEPLOY_KEY: ${{{{ secrets.DEPLOY_KEY }}}}\n"
                    f"This limits which secrets the reusable workflow can access."
                    + (
                        " Pin cross-repository reusable workflows to a full commit SHA."
                        if not job.uses.startswith("./") else ""
                    )
                    + "\n"
                    f"→ {workflow_file_url(gate.full_name, wf.path)}"
                ),
                settings_url=workflow_file_url(gate.full_name, wf.path),
            ))

    return findings


def _is_external_reusable(uses: str, current_org: str) -> bool:
    """Check if a reusable workflow reference is external to the org."""
    # Format: org/repo/.github/workflows/file.yml@ref
    if "/" not in uses:
        return False
    org_part = uses.split("/")[0]
    return org_part.lower() != current_org.lower()


def _is_mutable_ref(uses: str) -> bool:
    """Only a full commit SHA is treated as immutable."""
    if "@" not in uses:
        return True

    ref = uses.split("@")[-1]
    return not (
        len(ref) == 40
        and all(c in "0123456789abcdefABCDEF" for c in ref)
    )


# ==================================================================
# GHOST-WF-004: Workflow triggered by fork PRs with secrets access
# ==================================================================

@registry.rule(
    rule_id="GHOST-WF-004",
    name="workflow_run trust-boundary review",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.EXTERNAL,
    tags=("workflow", "fork", "secrets", "public-repo"),
)
def wf_004_fork_pr_secrets(gate: GateModel) -> list[BypassFinding]:
    """Flags workflow_run usage in public repositories for trust review.

    The trigger alone does not establish that untrusted artifacts are consumed
    or that secrets are exposed.
    """
    findings: list[BypassFinding] = []

    if gate.visibility != "public":
        return []  # only relevant for public repos

    for wf in gate.workflows:
        for trigger in wf.triggers:
            if trigger.event == "workflow_run":
                findings.append(BypassFinding(
                    rule_id="GHOST-WF-004",
                    rule_name="workflow_run trust-boundary review",
                    repo=gate.full_name,
                    gate_type=GateType.WORKFLOW,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    min_privilege=AttackerLevel.EXTERNAL,
                    summary=(
                        f"Workflow '{wf.name}' ({wf.path}) uses workflow_run "
                        f"in a public repo; review whether it consumes untrusted "
                        f"artifacts or data in a privileged context."
                    ),
                    bypass_path=(
                        f"Observed: public repo {gate.full_name} has workflow '{wf.path}'\n"
                        f"Observed: workflow triggers on workflow_run\n"
                        f"Inference: data from a less-trusted triggering workflow may cross "
                        f"into a more-privileged workflow\n"
                        f"Potential consequence: unsafe artifact or input handling could "
                        f"expose credentials"
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
                        "Sensitive impact requires credentials in the workflow_run job",
                    ],
                    remediation=(
                        f"Audit workflow '{wf.path}' to ensure workflow_run does not "
                        f"use artifacts or data from the triggering PR workflow without "
                        f"validation. Consider using pull_request trigger instead and "
                        f"only running trusted code.\n"
                        f"→ {workflow_file_url(gate.full_name, wf.path)}"
                    ),
                    settings_url=workflow_file_url(gate.full_name, wf.path),
                    references=[
                        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
                    ],
                ))

    return findings


# ==================================================================
# GHOST-WF-005: Unpinned action references (mutable tags/branches)
# ==================================================================

_FIRST_PARTY_OWNERS = frozenset({"actions", "github"})


def _is_pinned_ref(uses: str) -> bool:
    """Check if an action reference is pinned to a SHA."""
    if "@" not in uses:
        return False
    ref = uses.rsplit("@", 1)[-1]
    return len(ref) == 40 and all(c in "0123456789abcdefABCDEF" for c in ref)


def _is_first_party(uses: str) -> bool:
    """Check if action is from actions/ or github/ org."""
    action_path = uses.split("@")[0] if "@" in uses else uses
    owner = action_path.split("/", 1)[0].lower()
    return owner in _FIRST_PARTY_OWNERS


def _is_third_party_ref(uses: str, current_org: str) -> bool:
    """Return whether an action/workflow reference crosses the organization boundary."""
    if uses.startswith(("./", "docker://")):
        return False
    owner = uses.split("/", 1)[0].lower()
    return owner != current_org.lower() and not _is_first_party(uses)


@registry.rule(
    rule_id="GHOST-WF-005",
    name="Mutable third-party action reference",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.EXTERNAL,
    tags=("workflow", "supply-chain", "pinning", "actions"),
)
def wf_005_unpinned_actions(gate: GateModel) -> list[BypassFinding]:
    """Detects third-party actions referenced by a mutable tag or branch.

    A mutable reference is observed. Execution of malicious code additionally
    requires compromise or malicious modification of the referenced upstream.
    """
    findings: list[BypassFinding] = []

    for wf in gate.workflows:
        unpinned: list[dict] = []

        for job in wf.jobs:
            # Reusable workflow ref
            if job.uses and _is_third_party_ref(job.uses, gate.org) and not _is_pinned_ref(job.uses):
                unpinned.append({
                    "job": job.name,
                    "ref": job.uses,
                    "type": "reusable_workflow",
                })

            for step in job.steps:
                if not step.uses or "actions/checkout" == step.uses.split("@")[0]:
                    continue
                if not _is_third_party_ref(step.uses, gate.org):
                    continue
                if _is_pinned_ref(step.uses):
                    continue

                unpinned.append({
                    "job": job.name,
                    "ref": step.uses,
                    "type": "action",
                    "step": step.name or step.uses,
                })

        if not unpinned:
            continue

        # Deduplicate by action reference
        seen_refs = set()
        unique_unpinned = []
        for u in unpinned:
            if u["ref"] not in seen_refs:
                seen_refs.add(u["ref"])
                unique_unpinned.append(u)

        refs_list = "\n".join(
            f"  - {u['ref']} ({u['type']} in job '{u['job']}')"
            for u in unique_unpinned[:10]
        )

        findings.append(BypassFinding(
            rule_id="GHOST-WF-005",
            rule_name="Mutable third-party action reference",
            repo=gate.full_name,
            gate_type=GateType.WORKFLOW,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            min_privilege=AttackerLevel.EXTERNAL,
            summary=(
                f"Workflow '{wf.name}' ({wf.path}) uses {len(unique_unpinned)} "
                f"third-party action reference(s) that are not pinned to full "
                f"commit SHAs."
            ),
            bypass_path=(
                f"Observed: workflow '{wf.path}' references third-party actions "
                f"by mutable tag or branch\n"
                f"Observed references:\n{refs_list}\n"
                f"Prerequisite: an upstream maintainer or attacker changes the "
                f"resolved reference\n"
                f"Potential consequence: a later workflow run executes the changed action "
                f"with the job's configured permissions"
            ),
            evidence={
                "workflow": wf.path,
                "unpinned_count": len(unique_unpinned),
                "unpinned_refs": [u["ref"] for u in unique_unpinned[:10]],
            },
            gating_conditions=[
                "Attacker must compromise a referenced action's repository",
                "Workflow must be triggerable (push, PR, schedule, etc.)",
            ],
            remediation=(
                f"Pin all third-party actions to full commit SHAs:\n"
                f"  # Before (vulnerable):\n"
                f"  uses: some-org/action@v3\n"
                f"  # After (pinned):\n"
                f"  uses: some-org/action@abc123...  # v3\n"
                f"Use tools like 'pinact' or Dependabot to automate SHA pinning.\n"
                f"→ {workflow_file_url(gate.full_name, wf.path)}"
            ),
            settings_url=workflow_file_url(gate.full_name, wf.path),
            references=[
                "https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-attack",
            ],
        ))

    return findings


# ==================================================================
# GHOST-WF-006: workflow_dispatch with elevated permissions
# ==================================================================

@registry.rule(
    rule_id="GHOST-WF-006",
    name="Manual workflow trigger with write permissions",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("workflow", "dispatch", "remote-trigger", "supply-chain"),
)
def wf_006_dispatch_write(gate: GateModel) -> list[BypassFinding]:
    """Flags manual workflow entry points with write permissions.

    The trigger and permission are observed; harmful behavior additionally
    depends on who can dispatch the workflow and what its steps and inputs do.
    """
    findings: list[BypassFinding] = []
    default_is_write = (
        gate.workflow_permissions.default_workflow_permissions == "write"
    )

    for wf in gate.workflows:
        has_dispatch = any(
            t.event == "workflow_dispatch" for t in wf.triggers
        )
        if not has_dispatch:
            continue

        # Check if workflow has write permissions (explicit or inherited)
        wf_has_write = _is_write_all(wf.permissions)
        inherits_write = (not wf.permissions and default_is_write)

        if not wf_has_write and not inherits_write:
            # Check per-job for specific dangerous permissions
            dangerous_jobs = []
            for job in wf.jobs:
                if _is_write_all(job.permissions):
                    dangerous_jobs.append(job.name)
                elif _has_dangerous_permissions(job.permissions):
                    dangerous_jobs.append(job.name)
            if not dangerous_jobs:
                continue

            findings.append(BypassFinding(
                rule_id="GHOST-WF-006",
                rule_name="Manual workflow trigger with write permissions",
                repo=gate.full_name,
                gate_type=GateType.WORKFLOW,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Workflow '{wf.name}' ({wf.path}) is remotely triggerable "
                    f"via workflow_dispatch with write permissions on jobs: "
                    f"{', '.join(dangerous_jobs)}."
                ),
                bypass_path=(
                    f"Observed: workflow '{wf.path}' has workflow_dispatch\n"
                    f"Observed: jobs with write permissions: {', '.join(dangerous_jobs)}\n"
                    f"Prerequisite: a caller must be authorized to dispatch the workflow\n"
                    f"Inference: the defined jobs then run with elevated token permissions\n"
                    f"Potential consequence depends on the workflow's steps and inputs"
                ),
                evidence={
                    "workflow": wf.path,
                    "trigger": "workflow_dispatch",
                    "dangerous_jobs": dangerous_jobs,
                },
                gating_conditions=[
                    "Caller needs repository write access or an equivalent authorized token",
                    "Workflow steps or inputs must expose a security-sensitive effect",
                ],
                remediation=(
                    f"Restrict permissions on workflow_dispatch workflows to "
                    f"read-only at the workflow level, then grant specific write "
                    f"scopes only to jobs that need them behind environment gates.\n"
                    f"→ {workflow_file_url(gate.full_name, wf.path)}"
                ),
                settings_url=workflow_file_url(gate.full_name, wf.path),
            ))
            continue

        perm_source = "explicit write-all" if wf_has_write else "inherited from org/repo default"

        findings.append(BypassFinding(
            rule_id="GHOST-WF-006",
            rule_name="Manual workflow trigger with write permissions",
            repo=gate.full_name,
            gate_type=GateType.WORKFLOW,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Workflow '{wf.name}' ({wf.path}) has workflow_dispatch "
                f"with {perm_source}."
            ),
            bypass_path=(
                f"Observed: workflow '{wf.path}' has workflow_dispatch\n"
                f"Observed permissions: {perm_source}\n"
                f"Prerequisite: a caller must be authorized to dispatch the workflow\n"
                f"Inference: the defined jobs run with write token permissions\n"
                f"Potential consequence depends on the workflow's steps and inputs"
            ),
            evidence={
                "workflow": wf.path,
                "trigger": "workflow_dispatch",
                "permissions_source": perm_source,
                "workflow_permissions": wf.permissions or "inherited",
            },
            gating_conditions=[
                "Caller needs repository write access or an equivalent authorized token",
                "Workflow steps or inputs must expose a security-sensitive effect",
            ],
            remediation=(
                f"Add explicit least-privilege permissions to '{wf.path}':\n"
                f"  permissions:\n"
                f"    contents: read\n"
                f"If write access is needed, gate it behind a protected environment "
                f"with required reviewers.\n"
                f"→ {workflow_file_url(gate.full_name, wf.path)}"
            ),
            settings_url=workflow_file_url(gate.full_name, wf.path),
        ))

    return findings


def _has_dangerous_permissions(perms: dict) -> bool:
    """Check if permissions dict includes write access to dangerous scopes."""
    dangerous_scopes = {"contents", "packages", "actions", "deployments"}
    for scope in dangerous_scopes:
        if perms.get(scope) == "write":
            return True
    return False


def _environment_name(environment: str | dict | None) -> str | None:
    """Extract the name from a workflow job environment value."""
    if isinstance(environment, str):
        return environment
    if isinstance(environment, dict):
        return environment.get("name")
    return None


def _reviewer_gated_environment_names(gate: GateModel) -> set[str]:
    """Return only environments with an observed required reviewer."""
    return {
        environment.name
        for environment in gate.environments
        if environment.reviewers
    }


# ==================================================================
# GHOST-WF-007: contents:write without environment gate
# ==================================================================

@registry.rule(
    rule_id="GHOST-WF-007",
    name="contents:write without environment gate",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("workflow", "permissions", "contents", "release", "supply-chain"),
)
def wf_007_contents_write_no_env(gate: GateModel) -> list[BypassFinding]:
    """Detects contents:write without an observed reviewer-gated environment.

    The permission is a capability. A harmful consequence additionally depends
    on workflow behavior and attacker reachability.
    """
    findings: list[BypassFinding] = []
    default_is_write = (
        gate.workflow_permissions.default_workflow_permissions == "write"
    )
    gated_environments = _reviewer_gated_environment_names(gate)

    for wf in gate.workflows:
        for job in wf.jobs:
            environment_name = _environment_name(job.environment)
            has_contents_write = False
            perm_source = ""

            # Explicit job permissions
            if job.permissions.get("contents") == "write":
                has_contents_write = True
                perm_source = "explicit job-level contents: write"
            elif _is_write_all(job.permissions):
                has_contents_write = True
                perm_source = "job-level write-all"
            # Inherit from workflow level
            elif not job.permissions:
                if wf.permissions.get("contents") == "write":
                    has_contents_write = True
                    perm_source = "workflow-level contents: write"
                elif _is_write_all(wf.permissions):
                    has_contents_write = True
                    perm_source = "workflow-level write-all"
                elif not wf.permissions and default_is_write:
                    has_contents_write = True
                    perm_source = "inherited from org/repo default (write)"

            if not has_contents_write or environment_name in gated_environments:
                continue

            findings.append(BypassFinding(
                rule_id="GHOST-WF-007",
                rule_name="contents:write without environment gate",
                repo=gate.full_name,
                gate_type=GateType.WORKFLOW,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Job '{job.name}' in '{wf.path}' has contents:write "
                    f"({perm_source}) without an observed reviewer-gated environment."
                ),
                bypass_path=(
                    f"Observed: workflow '{wf.path}' job '{job.name}' has {perm_source}\n"
                    f"Observed: job environment {environment_name!r} has no collected "
                    f"required reviewers\n"
                    f"Inference: the job's token permits repository-content changes "
                    f"without a reviewer approval step\n"
                    f"Potential consequence depends on how the workflow uses that token"
                ),
                evidence={
                    "workflow": wf.path,
                    "job": job.name,
                    "permissions_source": perm_source,
                    "environment": environment_name,
                },
                gating_conditions=[
                    "Attacker must be able to trigger the workflow",
                    "Workflow steps must use the token for a security-sensitive write",
                ],
                remediation=(
                    f"Add a protected environment with required reviewers to "
                    f"job '{job.name}' in '{wf.path}':\n"
                    f"  jobs:\n"
                    f"    {job.name}:\n"
                    f"      environment: production\n"
                    f"      permissions:\n"
                    f"        contents: write\n"
                    f"This ensures human approval before destructive actions.\n"
                    f"→ {workflow_file_url(gate.full_name, wf.path)}"
                ),
                settings_url=workflow_file_url(gate.full_name, wf.path),
            ))

    return findings


# ==================================================================
# GHOST-WF-008: Package/release publish without environment gate
# ==================================================================

_PUBLISH_ACTIONS = frozenset({
    "actions/create-release",
    "softprops/action-gh-release",
    "ncipollo/release-action",
    "pypa/gh-action-pypi-publish",
    "JS-DevTools/npm-publish",
    "docker/build-push-action",
})

_PUBLISH_COMMANDS = (
    "npm publish",
    "yarn publish",
    "twine upload",
    "pip upload",
    "docker push",
    "gh release create",
    "gh release upload",
    "dotnet nuget push",
    "cargo publish",
    "gem push",
    "vsce publish",
    "ovsx publish",
)


@registry.rule(
    rule_id="GHOST-WF-008",
    name="Package/release publish without environment gate",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("workflow", "publish", "supply-chain", "registry"),
)
def wf_008_publish_no_env(gate: GateModel) -> list[BypassFinding]:
    """Detects publish steps without an observed reviewer-gated environment.

    Publishing behavior is observed, while malicious use still requires
    attacker reachability and usable publish credentials.
    """
    findings: list[BypassFinding] = []
    gated_environments = _reviewer_gated_environment_names(gate)

    for wf in gate.workflows:
        for job in wf.jobs:
            environment_name = _environment_name(job.environment)
            if environment_name in gated_environments:
                continue

            publish_evidence = _detect_publish_steps(job)
            if not publish_evidence:
                continue

            findings.append(BypassFinding(
                rule_id="GHOST-WF-008",
                rule_name="Package/release publish without environment gate",
                repo=gate.full_name,
                gate_type=GateType.WORKFLOW,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Job '{job.name}' in '{wf.path}' contains a package/release publish "
                    f"registry or creates releases without an observed "
                    f"reviewer-gated environment."
                ),
                bypass_path=(
                    f"Observed: workflow '{wf.path}' job '{job.name}' has publish steps:\n"
                    + "\n".join(
                        f"   - {p}" for p in publish_evidence[:5]
                    )
                    + f"\nObserved: job environment {environment_name!r} has no "
                    f"collected required reviewers\n"
                    f"Potential consequence: a reachable workflow with usable credentials "
                    f"could publish without reviewer approval"
                ),
                evidence={
                    "workflow": wf.path,
                    "job": job.name,
                    "publish_steps": publish_evidence[:5],
                    "environment": environment_name,
                },
                gating_conditions=[
                    "Attacker must be able to trigger the workflow",
                    "Publish credentials (secrets) must be available to the job",
                ],
                remediation=(
                    f"Add a protected environment with required reviewers to "
                    f"the publish job:\n"
                    f"  jobs:\n"
                    f"    {job.name}:\n"
                    f"      environment: release\n"
                    f"This ensures human review before any package is published.\n"
                    f"→ {workflow_file_url(gate.full_name, wf.path)}"
                ),
                settings_url=workflow_file_url(gate.full_name, wf.path),
            ))

    return findings


def _detect_publish_steps(job: WorkflowJob) -> list[str]:
    """Detect steps that publish to registries or create releases."""
    evidence: list[str] = []

    for step in job.steps:
        # Check action references
        if step.uses:
            action_name = step.uses.split("@")[0]
            if action_name in _PUBLISH_ACTIONS:
                if (
                    action_name == "docker/build-push-action"
                    and str(step.with_.get("push", "")).lower() not in ("true", "1")
                ):
                    continue
                evidence.append(f"uses: {step.uses}")

        # Check run commands
        if step.run:
            run_lower = step.run.lower()
            for cmd in _PUBLISH_COMMANDS:
                if cmd in run_lower:
                    evidence.append(f"run: {cmd}")
                    break  # one match per step

    return evidence
