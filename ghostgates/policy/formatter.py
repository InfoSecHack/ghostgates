"""
ghostgates/policy/formatter.py

Output formatters for policy audit results.
"""

from __future__ import annotations

import json

from ghostgates.policy.evaluator import PolicyAuditResult, GapCategory

_BOLD = "\033[1m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_CATEGORY_ICON = {
    GapCategory.BRANCH_PROTECTION: "🔒",
    GapCategory.ENVIRONMENT: "🌍",
    GapCategory.WORKFLOW: "⚙️",
    GapCategory.OIDC: "🔑",
}


def format_audit_terminal(result: PolicyAuditResult) -> str:
    """Render policy audit for terminal."""
    lines: list[str] = []

    lines.append("")
    lines.append(f"{_BOLD}╔══════════════════════════════════════════════════════╗{_RESET}")
    lines.append(f"{_BOLD}║  GhostGates Policy Audit                             ║{_RESET}")
    lines.append(f"{_BOLD}╚══════════════════════════════════════════════════════╝{_RESET}")
    lines.append("")

    if result.policy_path:
        lines.append(f"  Policy:      {result.policy_path}")
    lines.append(f"  Repos:       {result.total_repos} in scope ({result.excluded_repos} excluded)")

    pct = result.compliance_pct
    color = _GREEN if pct >= 80 else (_YELLOW if pct >= 50 else _RED)
    lines.append(f"  Compliant:   {color}{result.compliant_count}/{result.total_repos} ({pct:.0f}%){_RESET}")
    lines.append(f"  Total gaps:  {result.total_gaps}")
    lines.append("")

    if result.total_repos == 0:
        lines.append(f"  {_DIM}No repos in scope.{_RESET}")
        lines.append("")
        return "\n".join(lines)

    # Noncompliant repos
    noncompliant = [r for r in result.repo_results if not r.compliant]
    if noncompliant:
        lines.append(f"  {_RED}── Policy Gaps ──{_RESET}")
        lines.append("")

        for repo_result in noncompliant:
            lines.append(
                f"  {_BOLD}{repo_result.repo}{_RESET}"
                f"    {_DIM}{len(repo_result.gaps)} gap{'s' if len(repo_result.gaps) != 1 else ''}{_RESET}"
            )

            for gap in repo_result.gaps:
                icon = _CATEGORY_ICON.get(gap.category, "•")
                context = f" [{gap.context}]" if gap.context else ""
                lines.append(
                    f"    {_RED}✗{_RESET} {icon} {gap.check}: "
                    f"{_RED}{gap.actual}{_RESET} (expected: {_GREEN}{gap.expected}{_RESET})"
                    f"{_DIM}{context}{_RESET}"
                )

            lines.append("")

    # Compliant summary
    compliant = [r for r in result.repo_results if r.compliant]
    if compliant:
        lines.append(f"  {_GREEN}── Compliant ──{_RESET}")
        if len(compliant) <= 10:
            for repo_result in compliant:
                lines.append(f"    {_GREEN}✓{_RESET} {repo_result.repo}")
        else:
            for repo_result in compliant[:5]:
                lines.append(f"    {_GREEN}✓{_RESET} {repo_result.repo}")
            lines.append(f"    {_DIM}... and {len(compliant) - 5} more{_RESET}")
        lines.append("")

    return "\n".join(lines)


def format_audit_json(result: PolicyAuditResult) -> str:
    """JSON audit output."""
    return json.dumps(
        {
            "policy_path": result.policy_path,
            "total_repos": result.total_repos,
            "excluded_repos": result.excluded_repos,
            "compliant": result.compliant_count,
            "noncompliant": result.noncompliant_count,
            "compliance_pct": round(result.compliance_pct, 1),
            "total_gaps": result.total_gaps,
            "repos": [
                {
                    "repo": r.repo,
                    "compliant": r.compliant,
                    "gaps": [
                        {
                            "category": g.category.value,
                            "check": g.check,
                            "expected": g.expected,
                            "actual": g.actual,
                            "context": g.context,
                        }
                        for g in r.gaps
                    ],
                }
                for r in result.repo_results
            ],
        },
        indent=2,
    )


def format_audit_markdown(result: PolicyAuditResult) -> str:
    """Markdown audit output for reports."""
    lines: list[str] = []

    lines.append("# GhostGates Policy Audit Report")
    lines.append("")
    lines.append(f"**Policy:** {result.policy_path}")
    lines.append(f"**Repos in scope:** {result.total_repos} ({result.excluded_repos} excluded)")
    lines.append(
        f"**Compliance:** {result.compliant_count}/{result.total_repos} "
        f"({result.compliance_pct:.0f}%)"
    )
    lines.append(f"**Total gaps:** {result.total_gaps}")
    lines.append("")

    noncompliant = [r for r in result.repo_results if not r.compliant]
    if noncompliant:
        lines.append("## Policy Gaps")
        lines.append("")

        for repo_result in noncompliant:
            lines.append(f"### {repo_result.repo} ({len(repo_result.gaps)} gaps)")
            lines.append("")
            lines.append("| Check | Expected | Actual | Context |")
            lines.append("|-------|----------|--------|---------|")
            for gap in repo_result.gaps:
                ctx = gap.context or "—"
                lines.append(
                    f"| `{gap.check}` | {gap.expected} | {gap.actual} | {ctx} |"
                )
            lines.append("")

    compliant = [r for r in result.repo_results if r.compliant]
    if compliant:
        lines.append("## Compliant Repos")
        lines.append("")
        for repo_result in compliant:
            lines.append(f"- ✓ {repo_result.repo}")
        lines.append("")

    return "\n".join(lines)
