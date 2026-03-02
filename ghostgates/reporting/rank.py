"""
ghostgates/reporting/rank.py

Risk scoring and repo ranking. Aggregates findings per repo into a
weighted risk score that accounts for severity, attacker reachability,
and high-value target indicators (OIDC, production environments).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ghostgates.models.enums import AttackerLevel, Severity
from ghostgates.models.findings import BypassFinding

# ── Scoring weights ──────────────────────────────────────────────

_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 20,
    Severity.MEDIUM: 7,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

_BONUS_EXTERNAL_PATH = 25   # any finding reachable by external attacker
_BONUS_OIDC = 15            # OIDC findings → cloud credential risk
_BONUS_PROD_ENV = 10        # production environment involved


# ── Data model ───────────────────────────────────────────────────

@dataclass
class RepoRiskScore:
    """Risk score for a single repository."""

    repo: str
    score: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    has_external_path: bool
    has_oidc_finding: bool
    has_prod_env: bool
    top_finding: str = ""   # rule_id of highest-severity finding

    @property
    def tier(self) -> str:
        if self.score >= 75:
            return "CRITICAL"
        if self.score >= 40:
            return "HIGH"
        if self.score >= 15:
            return "MEDIUM"
        return "LOW"

    @property
    def finding_summary(self) -> str:
        """Compact summary like '1C 3H 2M'."""
        parts: list[str] = []
        if self.critical:
            parts.append(f"{self.critical}C")
        if self.high:
            parts.append(f"{self.high}H")
        if self.medium:
            parts.append(f"{self.medium}M")
        if self.low:
            parts.append(f"{self.low}L")
        if self.info:
            parts.append(f"{self.info}I")
        return " ".join(parts) or "0"


# ── Scoring logic ────────────────────────────────────────────────

def score_repos(findings: list[BypassFinding]) -> list[RepoRiskScore]:
    """Group findings by repo and compute risk scores. Returns sorted descending."""
    by_repo: dict[str, list[BypassFinding]] = defaultdict(list)
    for f in findings:
        by_repo[f.repo].append(f)

    scores: list[RepoRiskScore] = []

    for repo, repo_findings in by_repo.items():
        # Base score from severity weights
        base = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in repo_findings)

        # Bonus flags
        has_external = any(
            f.min_privilege == AttackerLevel.EXTERNAL for f in repo_findings
        )
        has_oidc = any(
            f.rule_id.startswith("GHOST-OI") for f in repo_findings
        )
        has_prod = any(
            "prod" in str(f.evidence.get("environment", "")).lower()
            for f in repo_findings
        )

        bonus = (
            (_BONUS_EXTERNAL_PATH if has_external else 0)
            + (_BONUS_OIDC if has_oidc else 0)
            + (_BONUS_PROD_ENV if has_prod else 0)
        )

        # Severity counts
        counts: dict[Severity, int] = defaultdict(int)
        for f in repo_findings:
            counts[f.severity] += 1

        # Top finding (highest severity, then alphabetical rule_id)
        severity_order = list(Severity)
        sorted_findings = sorted(
            repo_findings,
            key=lambda f: (severity_order.index(f.severity), f.rule_id),
        )
        top = sorted_findings[0].rule_id if sorted_findings else ""

        scores.append(RepoRiskScore(
            repo=repo,
            score=base + bonus,
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            info=counts[Severity.INFO],
            has_external_path=has_external,
            has_oidc_finding=has_oidc,
            has_prod_env=has_prod,
            top_finding=top,
        ))

    return sorted(scores, key=lambda s: s.score, reverse=True)


# ── Formatters ───────────────────────────────────────────────────

_BOLD = "\033[1m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_TIER_COLOR = {
    "CRITICAL": _RED,
    "HIGH": _YELLOW,
    "MEDIUM": _YELLOW,
    "LOW": _GREEN,
}


def format_rank_terminal(
    scores: list[RepoRiskScore],
    org: str,
    top_n: int = 20,
) -> str:
    """Render the ranking table for terminal output."""
    lines: list[str] = []

    lines.append("")
    lines.append(f"{_BOLD}╔══════════════════════════════════════════════════════╗{_RESET}")
    lines.append(f"{_BOLD}║  GhostGates Risk Ranking                             ║{_RESET}")
    lines.append(f"{_BOLD}╚══════════════════════════════════════════════════════╝{_RESET}")
    lines.append("")
    lines.append(f"  Organization:  {org}")
    lines.append(f"  Repos ranked:  {len(scores)}")
    lines.append("")

    if not scores:
        lines.append(f"  {_GREEN}No findings to rank.{_RESET}")
        lines.append("")
        return "\n".join(lines)

    # Header
    lines.append(
        f"  {_DIM}{'#':>3}  {'Repository':<40} {'Score':>5}  "
        f"{'Tier':<10} {'Findings':<12} {'Flags'}{_RESET}"
    )
    lines.append(f"  {'─' * 95}")

    for i, s in enumerate(scores[:top_n], 1):
        color = _TIER_COLOR.get(s.tier, "")
        flags: list[str] = []
        if s.has_external_path:
            flags.append("⚠ external")
        if s.has_oidc_finding:
            flags.append("⚠ OIDC")
        if s.has_prod_env:
            flags.append("⚠ prod")
        flag_str = "  ".join(flags)

        lines.append(
            f"  {i:>3}  {s.repo:<40} {color}{s.score:>5}{_RESET}  "
            f"{color}{s.tier:<10}{_RESET} {s.finding_summary:<12} {flag_str}"
        )

    if len(scores) > top_n:
        lines.append(f"  {_DIM}... and {len(scores) - top_n} more repos{_RESET}")

    # Summary
    total_score = sum(s.score for s in scores)
    crit_repos = sum(1 for s in scores if s.tier == "CRITICAL")
    high_repos = sum(1 for s in scores if s.tier == "HIGH")

    lines.append("")
    lines.append(
        f"  Total risk: {_BOLD}{total_score}{_RESET} across {len(scores)} repos"
    )
    if crit_repos:
        lines.append(f"  {_RED}{crit_repos} CRITICAL-tier repos{_RESET}")
    if high_repos:
        lines.append(f"  {_YELLOW}{high_repos} HIGH-tier repos{_RESET}")
    lines.append("")

    return "\n".join(lines)


def format_rank_json(scores: list[RepoRiskScore], org: str) -> str:
    """JSON ranking output."""
    import json

    return json.dumps(
        {
            "org": org,
            "repos_ranked": len(scores),
            "total_risk_score": sum(s.score for s in scores),
            "rankings": [
                {
                    "rank": i,
                    "repo": s.repo,
                    "score": s.score,
                    "tier": s.tier,
                    "critical": s.critical,
                    "high": s.high,
                    "medium": s.medium,
                    "low": s.low,
                    "has_external_path": s.has_external_path,
                    "has_oidc_finding": s.has_oidc_finding,
                    "has_prod_env": s.has_prod_env,
                    "top_finding": s.top_finding,
                }
                for i, s in enumerate(scores, 1)
            ],
        },
        indent=2,
    )
