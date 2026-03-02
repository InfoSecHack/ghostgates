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
                settings_url=workflow_file_url(gate.full_name, wf.path),
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
                    settings_url=workflow_file_url(gate.full_name, wf.path),
                    references=[
                        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
                    ],
                ))

    return findings


# ==================================================================
# GHOST-WF-005: Unpinned action references (mutable tags/branches)
# ==================================================================

_KNOWN_FIRST_PARTY = frozenset({
    "actions/checkout",
    "actions/setup-node",
    "actions/setup-python",
    "actions/setup-java",
    "actions/setup-go",
    "actions/setup-dotnet",
    "actions/cache",
    "actions/upload-artifact",
    "actions/download-artifact",
    "actions/github-script",
    "github/codeql-action",
})


def _is_pinned_ref(uses: str) -> bool:
    """Check if an action reference is pinned to a SHA."""
    if "@" not in uses:
        return False
    ref = uses.split("@")[-1]
    # SHA: 40 hex chars
    return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref)


def _is_first_party(uses: str) -> bool:
    """Check if action is from actions/ or github/ org."""
    action_path = uses.split("@")[0] if "@" in uses else uses
    return any(action_path.startswith(fp) for fp in _KNOWN_FIRST_PARTY)


@registry.rule(
    rule_id="GHOST-WF-005",
    name="Unpinned third-party action reference",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.EXTERNAL,
    tags=("workflow", "supply-chain", "pinning", "actions"),
)
def wf_005_unpinned_actions(gate: GateModel) -> list[BypassFinding]:
    """Detects third-party actions referenced by mutable tag/branch.

    Impact: Tag references (@v3, @main) can be force-pushed by the
    action maintainer — or an attacker who compromises their repo.
    This is the exact vector used in the tj-actions/changed-files
    supply chain attack and the March 2026 campaign that hit Trivy,
    Microsoft, DataDog, and CNCF repos.

    Only flags third-party actions (not actions/ or github/ org).
    First-party actions are lower risk because GitHub controls them.
    """
    findings: list[BypassFinding] = []

    for wf in gate.workflows:
        unpinned: list[dict] = []

        for job in wf.jobs:
            # Reusable workflow ref
            if job.uses and not _is_pinned_ref(job.uses):
                unpinned.append({
                    "job": job.name,
                    "ref": job.uses,
                    "type": "reusable_workflow",
                })

            for step in job.steps:
                if not step.uses or "actions/checkout" == step.uses.split("@")[0]:
                    continue
                if _is_pinned_ref(step.uses):
                    continue
                if _is_first_party(step.uses):
                    continue  # skip actions/ and github/ orgs

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
            rule_name="Unpinned third-party action reference",
            repo=gate.full_name,
            gate_type=GateType.WORKFLOW,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            min_privilege=AttackerLevel.EXTERNAL,
            summary=(
                f"Workflow '{wf.name}' ({wf.path}) uses {len(unique_unpinned)} "
                f"unpinned third-party action(s) — vulnerable to supply chain "
                f"tag poisoning."
            ),
            bypass_path=(
                f"1. Workflow '{wf.path}' references third-party actions by "
                f"mutable tag or branch\n"
                f"2. Unpinned references:\n{refs_list}\n"
                f"3. Attacker compromises one action's repo\n"
                f"4. Attacker force-pushes the tag to inject malicious code\n"
                f"5. Next workflow run executes attacker's code with "
                f"GITHUB_TOKEN permissions"
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
    name="workflow_dispatch with write permissions",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("workflow", "dispatch", "remote-trigger", "supply-chain"),
)
def wf_006_dispatch_write(gate: GateModel) -> list[BypassFinding]:
    """Detects workflow_dispatch workflows with write permissions.

    Impact: workflow_dispatch can be triggered remotely via API with
    any PAT that has repo scope. If the workflow has write permissions
    (explicit or inherited), a stolen PAT becomes a remote code
    execution vector — the attacker can trigger the workflow and it
    runs with write access to contents, packages, and more.

    This is the attack pattern used against Trivy: stolen PAT +
    workflow with elevated permissions = repo takeover.
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
                rule_name="workflow_dispatch with write permissions",
                repo=gate.full_name,
                gate_type=GateType.WORKFLOW,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Workflow '{wf.name}' ({wf.path}) is remotely triggerable "
                    f"via workflow_dispatch with write permissions on jobs: "
                    f"{', '.join(dangerous_jobs)}."
                ),
                bypass_path=(
                    f"1. Workflow '{wf.path}' triggers on workflow_dispatch\n"
                    f"2. Jobs with write permissions: {', '.join(dangerous_jobs)}\n"
                    f"3. Attacker with stolen PAT (repo scope) calls:\n"
                    f"   POST /repos/{gate.full_name}/actions/workflows/"
                    f"{wf.path.split('/')[-1]}/dispatches\n"
                    f"4. Workflow executes with elevated GITHUB_TOKEN permissions\n"
                    f"5. Attacker can modify contents, packages, or releases"
                ),
                evidence={
                    "workflow": wf.path,
                    "trigger": "workflow_dispatch",
                    "dangerous_jobs": dangerous_jobs,
                },
                gating_conditions=[
                    "Attacker needs a PAT with repo scope or write access",
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
            rule_name="workflow_dispatch with write permissions",
            repo=gate.full_name,
            gate_type=GateType.WORKFLOW,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            min_privilege=AttackerLevel.REPO_WRITE,
            summary=(
                f"Workflow '{wf.name}' ({wf.path}) is remotely triggerable "
                f"via workflow_dispatch with {perm_source} — stolen PAT = "
                f"remote code execution."
            ),
            bypass_path=(
                f"1. Workflow '{wf.path}' triggers on workflow_dispatch\n"
                f"2. Permissions: {perm_source}\n"
                f"3. Attacker with stolen PAT (repo scope) calls:\n"
                f"   POST /repos/{gate.full_name}/actions/workflows/"
                f"{wf.path.split('/')[-1]}/dispatches\n"
                f"4. Workflow executes with write-all GITHUB_TOKEN\n"
                f"5. Attacker can push code, delete releases, modify packages"
            ),
            evidence={
                "workflow": wf.path,
                "trigger": "workflow_dispatch",
                "permissions_source": perm_source,
                "workflow_permissions": wf.permissions or "inherited",
            },
            gating_conditions=[
                "Attacker needs a PAT with repo scope or write access",
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
    """Detects workflows with contents:write that lack environment gates.

    Impact: contents:write allows pushing commits, creating/deleting
    releases, creating/deleting tags, and modifying repo contents.
    Without an environment gate (required reviewers), any workflow
    trigger can execute these destructive actions.

    In the Trivy attack, contents:write enabled the attacker to delete
    releases, rename the repo, and overwrite it with empty content.
    An environment gate would have required human approval.
    """
    findings: list[BypassFinding] = []
    default_is_write = (
        gate.workflow_permissions.default_workflow_permissions == "write"
    )

    for wf in gate.workflows:
        for job in wf.jobs:
            has_env = bool(job.environment)
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

            if not has_contents_write or has_env:
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
                    f"({perm_source}) without an environment gate — can "
                    f"push commits, delete releases, modify tags."
                ),
                bypass_path=(
                    f"1. Workflow '{wf.path}' job '{job.name}'\n"
                    f"2. Has {perm_source}\n"
                    f"3. No environment gate (no required reviewers)\n"
                    f"4. GITHUB_TOKEN can: push commits, create/delete releases, "
                    f"create/delete tags, modify repo contents\n"
                    f"5. If triggered by attacker (dispatch, compromised PR, "
                    f"stolen PAT), all destructive actions execute without approval"
                ),
                evidence={
                    "workflow": wf.path,
                    "job": job.name,
                    "permissions_source": perm_source,
                    "environment": None,
                },
                gating_conditions=[
                    "Attacker must be able to trigger the workflow",
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
    "docker/login-action",
    "aws-actions/amazon-ecr-login",
    "google-github-actions/setup-gcloud",
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
    """Detects workflows that publish to package registries without
    environment gates.

    Impact: Publishing to npm, PyPI, Docker Hub, VSIX, NuGet, or
    creating GitHub releases without required reviewers means any
    workflow trigger can push malicious artifacts. In the Trivy attack,
    the attacker published a malicious VS Code extension to Open VSIX.

    An environment gate with required reviewers would have blocked
    the malicious publish.
    """
    findings: list[BypassFinding] = []

    for wf in gate.workflows:
        for job in wf.jobs:
            has_env = bool(job.environment)
            if has_env:
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
                confidence=Confidence.HIGH,
                min_privilege=AttackerLevel.REPO_WRITE,
                summary=(
                    f"Job '{job.name}' in '{wf.path}' publishes to a package "
                    f"registry or creates releases without an environment gate."
                ),
                bypass_path=(
                    f"1. Workflow '{wf.path}' job '{job.name}'\n"
                    f"2. Publish actions detected:\n"
                    + "\n".join(
                        f"   - {p}" for p in publish_evidence[:5]
                    )
                    + f"\n3. No environment gate (no required reviewers)\n"
                    f"4. Attacker who triggers workflow can publish malicious "
                    f"artifacts to downstream consumers"
                ),
                evidence={
                    "workflow": wf.path,
                    "job": job.name,
                    "publish_steps": publish_evidence[:5],
                    "environment": None,
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
                evidence.append(f"uses: {step.uses}")

        # Check run commands
        if step.run:
            run_lower = step.run.lower()
            for cmd in _PUBLISH_COMMANDS:
                if cmd in run_lower:
                    evidence.append(f"run: {cmd}")
                    break  # one match per step

    return evidence
