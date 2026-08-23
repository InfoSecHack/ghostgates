"""
ghostgates/reporting/recon.py

Review-question view: reorganize existing findings without adding observations
or proving the inferred consequences.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ghostgates.models.enums import AttackerLevel, Severity
from ghostgates.models.findings import BypassFinding


# ── Review categories ────────────────────────────────────────────

# Each category is a (label, description, matcher) tuple.
# matcher is a function that takes a finding and returns an
# optional short description string if the finding belongs.


def _match_workflow_execution(f: BypassFinding) -> str | None:
    """Findings that warrant review of workflow execution boundaries."""
    if f.rule_id == "GHOST-WF-001":
        wf = f.evidence.get("workflow", "?")
        return f"PR head checkout in {wf.split('/')[-1]}"
    if f.rule_id == "GHOST-WF-004":
        wf = f.evidence.get("workflow", "?")
        return f"workflow_run trust boundary in {wf.split('/')[-1]}"
    if f.rule_id == "GHOST-WF-006":
        wf = f.evidence.get("workflow", "?").split("/")[-1]
        return f"workflow_dispatch + write perms ({wf})"
    return None


def _match_secrets_exposure(f: BypassFinding) -> str | None:
    """Findings that warrant review of secret or token exposure."""
    if f.rule_id == "GHOST-WF-003":
        wf = f.evidence.get("workflow", "?").split("/")[-1]
        target = f.evidence.get("reusable_workflow", "reusable workflow")
        return f"secrets: inherit → {target.split('/')[-1]} ({wf})"
    if f.rule_id == "GHOST-WF-004":
        wf = f.evidence.get("workflow", "?").split("/")[-1]
        return f"workflow_run may consume untrusted input ({wf})"
    if f.rule_id == "GHOST-WF-002" and f.evidence.get("scope") == "workflow":
        wf = f.evidence.get("workflow", "?").split("/")[-1]
        return f"write-all GITHUB_TOKEN ({wf})"
    if f.rule_id == "GHOST-WF-007":
        wf = f.evidence.get("workflow", "?").split("/")[-1]
        job = f.evidence.get("job", "?")
        return f"contents:write no env gate ({wf}#{job})"
    return None


def _match_review_controls(f: BypassFinding) -> str | None:
    """Findings about missing or weakened review controls."""
    if f.rule_id == "GHOST-BP-001":
        branch = f.evidence.get("branch", "?")
        return f"admin bypass on {branch} (enforce_admins=false)"
    if f.rule_id == "GHOST-BP-002":
        branch = f.evidence.get("branch", "?")
        return f"stale approvals persist on {branch}"
    if f.rule_id == "GHOST-ENV-001":
        env = f.evidence.get("environment", "?")
        return f"{env} env has no required reviewers"
    if f.rule_id == "GHOST-ENV-002":
        env = f.evidence.get("environment", "?")
        return f"{env} env allows deploy from any branch"
    if f.rule_id == "GHOST-BP-005":
        return "Actions PR-approval setting is enabled"
    return None


def _match_oidc_review(f: BypassFinding) -> str | None:
    """Findings that warrant OIDC and cloud trust-policy review."""
    if f.rule_id == "GHOST-OIDC-001":
        return "OIDC subject template may not include environment"
    if f.rule_id == "GHOST-OIDC-002":
        wf = f.evidence.get("workflow", "?").split("/")[-1]
        job = f.evidence.get("job", "?")
        return f"id-token: write without env gate ({wf}#{job})"
    return None


def _match_prod_deployment_paths(f: BypassFinding) -> str | None:
    """Findings associated with production-named workflows or environments."""
    ev = f.evidence
    # Environment findings for prod-like envs
    env_name = ev.get("environment", "").lower()
    is_prod = any(p in env_name for p in ("prod", "live", "release"))

    if f.rule_id in ("GHOST-ENV-001", "GHOST-ENV-002", "GHOST-ENV-003") and is_prod:
        if f.rule_id == "GHOST-ENV-001":
            return f"{ev.get('environment', '?')} — no reviewers"
        if f.rule_id == "GHOST-ENV-002":
            return f"{ev.get('environment', '?')} — any branch can deploy"
        if f.rule_id == "GHOST-ENV-003":
            return f"{ev.get('environment', '?')} — wait timer but no reviewers"

    # Write-all workflows that reference prod-like names
    if f.rule_id == "GHOST-WF-002":
        wf = ev.get("workflow", "").lower()
        if any(p in wf for p in ("prod", "deploy", "release")):
            return f"{ev.get('workflow', '?').split('/')[-1]} — write-all permissions"

    # Secrets inheritance in production-named workflows
    if f.rule_id == "GHOST-WF-003":
        wf = ev.get("workflow", "").lower()
        if any(p in wf for p in ("prod", "deploy", "release")):
            return f"{ev.get('workflow', '?').split('/')[-1]} — secrets: inherit"

    return None


def _match_review_bypass(f: BypassFinding) -> str | None:
    """Findings about branch and ruleset review controls."""
    if f.rule_id == "GHOST-BP-001":
        branch = f.evidence.get("branch", "?")
        return f"admins exempt from reviews on {branch}"
    if f.rule_id == "GHOST-BP-002":
        branch = f.evidence.get("branch", "?")
        return f"push after approval, stale review persists ({branch})"
    if f.rule_id == "GHOST-BP-003":
        branch = f.evidence.get("branch", "?")
        return f"no CODEOWNERS enforcement on {branch}"
    if f.rule_id == "GHOST-BP-005":
        return "Actions PR-approval setting is enabled"
    if f.rule_id == "GHOST-BP-006":
        rs = f.evidence.get("ruleset_name", "?")
        return f"ruleset '{rs}' in evaluate mode (not enforced)"
    return None


def _match_supply_chain(f: BypassFinding) -> str | None:
    """Findings that warrant dependency and publishing review."""
    if f.rule_id == "GHOST-WF-005":
        wf = f.evidence.get("workflow", "?").split("/")[-1]
        count = f.evidence.get("unpinned_count", "?")
        return f"{count} unpinned third-party actions ({wf})"
    if f.rule_id == "GHOST-WF-008":
        wf = f.evidence.get("workflow", "?").split("/")[-1]
        job = f.evidence.get("job", "?")
        return f"publish without env gate ({wf}#{job})"
    if f.rule_id == "GHOST-WF-003":
        wf = f.evidence.get("workflow", "?").split("/")[-1]
        if f.evidence.get("is_mutable_ref"):
            return f"secrets: inherit to mutable ref ({wf})"
    return None


# ── Category definitions ─────────────────────────────────────────

@dataclass
class ReconHit:
    """A single hit within a recon category."""
    repo: str
    description: str
    rule_id: str
    severity: Severity
    min_privilege: AttackerLevel
    settings_url: str = ""


@dataclass
class ReconCategory:
    """A security-review category with hits."""
    key: str
    title: str
    question: str
    min_privilege: AttackerLevel  # floor for this category
    hits: list[ReconHit] = field(default_factory=list)


@dataclass
class ReconResult:
    """Complete recon output."""
    org: str
    total_findings: int
    categories: list[ReconCategory] = field(default_factory=list)

    @property
    def total_hits(self) -> int:
        return sum(len(c.hits) for c in self.categories)

    @property
    def repos_represented(self) -> int:
        repos = set()
        for cat in self.categories:
            for hit in cat.hits:
                repos.add(hit.repo)
        return len(repos)


# Category registry: (key, title, question, min_privilege_floor, matcher)
_CATEGORIES = [
    (
        "workflow_exec",
        "Workflow Execution Boundaries",
        "Which findings need review for attacker-influenced workflow execution?",
        AttackerLevel.EXTERNAL,
        _match_workflow_execution,
    ),
    (
        "secrets",
        "Secrets and Token Exposure",
        "Which findings need review for secret or token exposure?",
        AttackerLevel.EXTERNAL,
        _match_secrets_exposure,
    ),
    (
        "cloud_creds",
        "OIDC Trust Boundaries",
        "Which findings need comparison with the cloud trust policy?",
        AttackerLevel.REPO_WRITE,
        _match_oidc_review,
    ),
    (
        "code_to_prod",
        "Review Controls",
        "Which observed settings may weaken a human-review boundary?",
        AttackerLevel.REPO_WRITE,
        _match_review_controls,
    ),
    (
        "prod_deploy",
        "Production-Named Configuration",
        "Which findings reference production-named workflows or environments?",
        AttackerLevel.REPO_WRITE,
        _match_prod_deployment_paths,
    ),
    (
        "review_bypass",
        "Branch and Ruleset Review",
        "Which branch or ruleset controls need review?",
        AttackerLevel.REPO_WRITE,
        _match_review_bypass,
    ),
    (
        "supply_chain",
        "Dependencies and Publishing",
        "Which findings need dependency or publish-boundary review?",
        AttackerLevel.EXTERNAL,
        _match_supply_chain,
    ),
]


# ── Builder ──────────────────────────────────────────────────────

def build_recon(findings: list[BypassFinding], org: str = "") -> ReconResult:
    """Build recon view from existing findings."""
    categories: list[ReconCategory] = []

    for key, title, question, floor, matcher in _CATEGORIES:
        cat = ReconCategory(key=key, title=title, question=question, min_privilege=floor)

        for f in findings:
            desc = matcher(f)
            if desc is not None:
                cat.hits.append(ReconHit(
                    repo=f.repo,
                    description=desc,
                    rule_id=f.rule_id,
                    severity=f.severity,
                    min_privilege=f.min_privilege,
                    settings_url=f.settings_url,
                ))

        # Sort hits: highest severity first, then by repo
        sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                     Severity.LOW: 3, Severity.INFO: 4}
        cat.hits.sort(key=lambda h: (sev_order.get(h.severity, 5), h.repo))

        categories.append(cat)

    return ReconResult(
        org=org,
        total_findings=len(findings),
        categories=categories,
    )


# ── Formatters ───────────────────────────────────────────────────

_BOLD = "\033[1m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_SEV_COLOR = {
    Severity.CRITICAL: "\033[1;31m",  # bold red
    Severity.HIGH: "\033[31m",         # red
    Severity.MEDIUM: "\033[33m",       # yellow
    Severity.LOW: "\033[2m",           # dim
    Severity.INFO: "\033[2m",
}



def format_recon_terminal(result: ReconResult) -> str:
    """Render recon view for terminal."""
    lines: list[str] = []

    lines.append("")
    lines.append(f"{_BOLD}╔══════════════════════════════════════════════════════╗{_RESET}")
    lines.append(f"{_BOLD}║  GhostGates Review Questions                         ║{_RESET}")
    lines.append(f"{_BOLD}╚══════════════════════════════════════════════════════╝{_RESET}")
    lines.append("")

    if result.org:
        lines.append(f"  Organization:  {result.org}")
    lines.append(f"  Findings:      {result.total_findings}")
    lines.append(f"  Repos represented: {result.repos_represented}")
    lines.append("")

    for cat in result.categories:
        if not cat.hits:
            continue

        # Category header
        lines.append(f"  {_BOLD}{_CYAN}── {cat.title} ──{_RESET}")
        lines.append(f"  {_DIM}{cat.question}{_RESET}")
        lines.append("")

        # Group hits by repo
        hits_by_repo: dict[str, list[ReconHit]] = {}
        for hit in cat.hits:
            hits_by_repo.setdefault(hit.repo, []).append(hit)

        for repo, hits in hits_by_repo.items():
            lines.append(f"    {_BOLD}{repo}{_RESET}")
            for hit in hits:
                sev_c = _SEV_COLOR.get(hit.severity, "")
                lines.append(
                    f"      {sev_c}→{_RESET} {hit.description}"
                    f"  {_DIM}({hit.rule_id}; prerequisite: "
                    f"{hit.min_privilege.value}){_RESET}"
                )
            lines.append("")

    # Empty categories summary
    empty = [c for c in result.categories if not c.hits]
    if empty:
        lines.append(f"  {_DIM}── No matching findings (not proof of absence) ──{_RESET}")
        for cat in empty:
            lines.append(f"    {_DIM}– {cat.title}{_RESET}")
        lines.append("")

    return "\n".join(lines)


def format_recon_json(result: ReconResult) -> str:
    """JSON recon output."""
    return json.dumps(
        {
            "org": result.org,
            "total_findings": result.total_findings,
            "repos_represented": result.repos_represented,
            "categories": [
                {
                    "key": cat.key,
                    "title": cat.title,
                    "question": cat.question,
                    "min_privilege": cat.min_privilege.value,
                    "hit_count": len(cat.hits),
                    "hits": [
                        {
                            "repo": h.repo,
                            "description": h.description,
                            "rule_id": h.rule_id,
                            "severity": h.severity.value,
                            "min_privilege": h.min_privilege.value,
                            "settings_url": h.settings_url,
                        }
                        for h in cat.hits
                    ],
                }
                for cat in result.categories
            ],
        },
        indent=2,
    )


def format_recon_markdown(result: ReconResult) -> str:
    """Markdown recon output."""
    lines: list[str] = []

    lines.append("# GhostGates Review Questions")
    lines.append("")
    if result.org:
        lines.append(f"**Organization:** {result.org}")
    lines.append(f"**Total findings:** {result.total_findings}")
    lines.append(f"**Repos represented:** {result.repos_represented}")
    lines.append("")

    for cat in result.categories:
        if not cat.hits:
            continue

        lines.append(f"## {cat.title}")
        lines.append(f"*{cat.question}*")
        lines.append("Attacker prerequisites are reported per finding.")
        lines.append("")

        lines.append("| Repo | Review note | Rule | Severity | Prerequisite |")
        lines.append("|------|-------------|------|----------|--------------|")
        for hit in cat.hits:
            lines.append(
                f"| {hit.repo} | {hit.description} | {hit.rule_id} | {hit.severity.value} | {hit.min_privilege.value} |"
            )
        lines.append("")

    return "\n".join(lines)
