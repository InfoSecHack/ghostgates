"""
ghostgates/reporting/graph.py

Kill chain visualization — Mermaid diagrams showing attack paths
from entry to impact, with bypassed gates crossed out.

Same findings, visual lens. The terminal output is for the person
who fixes it. The diagram is for the person who funds fixing it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

from ghostgates.models.enums import AttackerLevel, GateType, Severity
from ghostgates.models.findings import BypassFinding


# ── Node types ───────────────────────────────────────────────────

class NodeKind(StrEnum):
    ENTRY = "entry"
    BYPASS = "bypass"
    IMPACT = "impact"


@dataclass
class GraphNode:
    id: str
    label: str
    kind: NodeKind
    severity: Severity | None = None
    rule_id: str = ""


@dataclass
class GraphEdge:
    src: str
    dst: str
    label: str = ""


@dataclass
class RepoGraph:
    repo: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def _node_ids(self) -> set[str]:
        return {n.id for n in self.nodes}


@dataclass
class OrgGraph:
    org: str
    repo_graphs: list[RepoGraph] = field(default_factory=list)


# ── Entry point mapping ─────────────────────────────────────────

_ENTRY_LABELS = {
    AttackerLevel.EXTERNAL: "External Attacker\\n(no credentials)",
    AttackerLevel.ORG_MEMBER: "Org Member",
    AttackerLevel.REPO_WRITE: "Repo Write\\n(compromised dev)",
    AttackerLevel.REPO_MAINTAIN: "Repo Maintainer",
    AttackerLevel.REPO_ADMIN: "Repo Admin\\n(compromised admin)",
    AttackerLevel.ORG_OWNER: "Org Owner",
}


# ── Impact derivation ───────────────────────────────────────────

def _derive_impact(f: BypassFinding) -> tuple[str, str]:
    """Derive impact node (id, label) from a finding."""
    rid = f.rule_id

    # Workflow execution → code exec + secrets
    if rid == "GHOST-WF-001":
        return "impact_code_exec", "Code Execution\\n+ Secret Exfil"
    if rid == "GHOST-WF-004":
        return "impact_secrets_fork", "Secrets Leaked\\nto Fork PRs"
    if rid == "GHOST-WF-003":
        return "impact_secrets_inherit", "Secrets Exposed\\nvia Inheritance"
    if rid == "GHOST-WF-002":
        return "impact_write_all", "Write Access\\nto Repo + Packages"
    if rid == "GHOST-WF-005":
        return "impact_supply_chain", "Supply Chain\\nCode Injection"
    if rid == "GHOST-WF-006":
        return "impact_remote_exec", "Remote Code Execution\\nvia Stolen PAT"
    if rid == "GHOST-WF-007":
        return "impact_repo_takeover", "Repo Modification\\n(releases, tags, code)"
    if rid == "GHOST-WF-008":
        return "impact_malicious_publish", "Malicious Package\\nPublished"

    # OIDC → cloud
    if rid == "GHOST-OIDC-001":
        return "impact_cloud_cross", "Cloud Role Assumption\\n(cross-repo)"
    if rid == "GHOST-OIDC-002":
        return "impact_cloud_nogated", "Cloud Credentials\\n(no env gate)"

    # Branch protection → unreviewed code
    if rid in ("GHOST-BP-001", "GHOST-BP-002", "GHOST-BP-005"):
        return "impact_unreviewed", "Unreviewed Code\\nMerged to Main"
    if rid == "GHOST-BP-003":
        return "impact_no_codeowner", "Code Merged\\nWithout Owner Review"
    if rid == "GHOST-BP-004":
        return "impact_unprotected", "Push to Unprotected\\nDeploy Branch"
    if rid == "GHOST-BP-006":
        return "impact_ruleset_noop", "Ruleset Not Enforced\\n(evaluate only)"

    # Environment → prod deploy
    if rid == "GHOST-ENV-001":
        return "impact_prod_no_review", "Production Deploy\\n(no reviewers)"
    if rid == "GHOST-ENV-002":
        return "impact_prod_any_branch", "Production Deploy\\n(any branch)"
    if rid == "GHOST-ENV-003":
        return "impact_prod_auto", "Production Deploy\\n(auto-approved)"

    return "impact_unknown", "Security Impact"


# ── Bypass node labels ───────────────────────────────────────────

def _bypass_label(f: BypassFinding) -> str:
    """Build a concise label for the bypassed gate."""
    rid = f.rule_id
    ev = f.evidence

    if rid == "GHOST-WF-001":
        wf = ev.get("workflow", "?").split("/")[-1]
        return f"✗ {wf}\\npull_request_target\\n+ head checkout"

    if rid == "GHOST-WF-002":
        wf = ev.get("workflow", "?").split("/")[-1]
        scope = ev.get("scope", "?")
        return f"✗ {wf}\\npermissions: write-all\\n({scope})"

    if rid == "GHOST-WF-003":
        wf = ev.get("workflow", "?").split("/")[-1]
        return f"✗ {wf}\\nsecrets: inherit"

    if rid == "GHOST-WF-004":
        wf = ev.get("workflow", "?").split("/")[-1]
        return f"✗ {wf}\\nsecrets exposed to forks"

    if rid == "GHOST-BP-001":
        branch = ev.get("branch", "?")
        return f"✗ Branch Protection\\n{branch}\\nenforce_admins=false"

    if rid == "GHOST-BP-002":
        branch = ev.get("branch", "?")
        return f"✗ Branch Protection\\n{branch}\\nstale approvals persist"

    if rid == "GHOST-BP-003":
        branch = ev.get("branch", "?")
        return f"✗ Branch Protection\\n{branch}\\nno CODEOWNERS"

    if rid == "GHOST-BP-004":
        branches = ev.get("unprotected_branches", [])
        br_str = ", ".join(branches[:3])
        return f"✗ Unprotected Branches\\n{br_str}"

    if rid == "GHOST-BP-005":
        return "✗ Workflow Self-Approval\\nauto-merge enabled"

    if rid == "GHOST-BP-006":
        rs = ev.get("ruleset", "?")
        return f"✗ Ruleset '{rs}'\\nevaluate mode (not enforced)"

    if rid == "GHOST-ENV-001":
        env = ev.get("environment", "?")
        return f"✗ Environment '{env}'\\nno required reviewers"

    if rid == "GHOST-ENV-002":
        env = ev.get("environment", "?")
        return f"✗ Environment '{env}'\\nno branch restriction"

    if rid == "GHOST-ENV-003":
        env = ev.get("environment", "?")
        return f"✗ Environment '{env}'\\nwait timer only"

    if rid == "GHOST-OIDC-001":
        return "✗ OIDC Template\\ndefault subject claim"

    if rid == "GHOST-OIDC-002":
        wf = ev.get("workflow", "?").split("/")[-1]
        job = ev.get("job", "?")
        return f"✗ OIDC in {wf}\\n{job}: no env gate"

    if rid == "GHOST-WF-005":
        wf = ev.get("workflow", "?").split("/")[-1]
        count = ev.get("unpinned_count", "?")
        return f"✗ {wf}\\n{count} unpinned actions"

    if rid == "GHOST-WF-006":
        wf = ev.get("workflow", "?").split("/")[-1]
        return f"✗ {wf}\\nworkflow_dispatch\\n+ write perms"

    if rid == "GHOST-WF-007":
        wf = ev.get("workflow", "?").split("/")[-1]
        job = ev.get("job", "?")
        return f"✗ {wf}#{job}\\ncontents:write\\nno env gate"

    if rid == "GHOST-WF-008":
        wf = ev.get("workflow", "?").split("/")[-1]
        job = ev.get("job", "?")
        return f"✗ {wf}#{job}\\npublish without\\nenv gate"

    return f"✗ {rid}"


# ── Graph builder ────────────────────────────────────────────────

def _sanitize_id(s: str) -> str:
    """Make a safe Mermaid node ID."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", s)


def build_repo_graph(repo: str, findings: list[BypassFinding]) -> RepoGraph:
    """Build attack graph for a single repo."""
    graph = RepoGraph(repo=repo)
    seen_nodes = set()

    # Group findings by attacker level to create entry points
    by_level: dict[AttackerLevel, list[BypassFinding]] = {}
    for f in findings:
        by_level.setdefault(f.min_privilege, []).append(f)

    for level, level_findings in by_level.items():
        # Entry node
        entry_id = f"entry_{_sanitize_id(level.value)}"
        if entry_id not in seen_nodes:
            graph.nodes.append(GraphNode(
                id=entry_id,
                label=_ENTRY_LABELS.get(level, str(level)),
                kind=NodeKind.ENTRY,
            ))
            seen_nodes.add(entry_id)

        for f in level_findings:
            # Bypass node
            bypass_id = f"bypass_{_sanitize_id(f.rule_id)}_{_sanitize_id(f.instance or 'default')}"
            if bypass_id not in seen_nodes:
                graph.nodes.append(GraphNode(
                    id=bypass_id,
                    label=_bypass_label(f),
                    kind=NodeKind.BYPASS,
                    severity=f.severity,
                    rule_id=f.rule_id,
                ))
                seen_nodes.add(bypass_id)

            # Impact node
            impact_id, impact_label = _derive_impact(f)
            if impact_id not in seen_nodes:
                graph.nodes.append(GraphNode(
                    id=impact_id,
                    label=impact_label,
                    kind=NodeKind.IMPACT,
                ))
                seen_nodes.add(impact_id)

            # Edges: entry → bypass → impact
            edge_entry = GraphEdge(src=entry_id, dst=bypass_id)
            edge_impact = GraphEdge(src=bypass_id, dst=impact_id)

            # Dedup edges
            existing_edges = {(e.src, e.dst) for e in graph.edges}
            if (edge_entry.src, edge_entry.dst) not in existing_edges:
                graph.edges.append(edge_entry)
            if (edge_impact.src, edge_impact.dst) not in existing_edges:
                graph.edges.append(edge_impact)

    return graph


def build_org_graph(findings: list[BypassFinding], org: str = "") -> OrgGraph:
    """Build attack graphs for all repos in a scan."""
    by_repo: dict[str, list[BypassFinding]] = {}
    for f in findings:
        by_repo.setdefault(f.repo, []).append(f)

    graphs = []
    for repo, repo_findings in sorted(by_repo.items()):
        g = build_repo_graph(repo, repo_findings)
        if g.edges:  # only include repos with actual paths
            graphs.append(g)

    return OrgGraph(org=org, repo_graphs=graphs)


# ── Mermaid renderer ─────────────────────────────────────────────

_SEV_STYLE = {
    Severity.CRITICAL: "fill:#dc2626,stroke:#991b1b,color:#fff",
    Severity.HIGH: "fill:#ea580c,stroke:#c2410c,color:#fff",
    Severity.MEDIUM: "fill:#d97706,stroke:#b45309,color:#fff",
    Severity.LOW: "fill:#65a30d,stroke:#4d7c0f,color:#fff",
    Severity.INFO: "fill:#6b7280,stroke:#4b5563,color:#fff",
}


def render_repo_mermaid(graph: RepoGraph) -> str:
    """Render a single repo's attack graph as Mermaid."""
    lines: list[str] = []
    lines.append("graph LR")

    # Nodes
    for node in graph.nodes:
        nid = node.id
        label = node.label

        if node.kind == NodeKind.ENTRY:
            # Stadium shape for entry
            lines.append(f'    {nid}(["{label}"])')
        elif node.kind == NodeKind.BYPASS:
            # Hexagon for bypassed gate
            lines.append(f'    {nid}{{{{"{label}"}}}}')
        elif node.kind == NodeKind.IMPACT:
            # Double circle for impact
            lines.append(f'    {nid}((("{label}")))')

    lines.append("")

    # Edges
    for edge in graph.edges:
        if edge.label:
            lines.append(f"    {edge.src} -->|{edge.label}| {edge.dst}")
        else:
            lines.append(f"    {edge.src} --> {edge.dst}")

    lines.append("")

    # Styles
    for node in graph.nodes:
        if node.kind == NodeKind.ENTRY:
            lines.append(f"    style {node.id} fill:#1e40af,stroke:#1e3a8a,color:#fff")
        elif node.kind == NodeKind.BYPASS and node.severity:
            style = _SEV_STYLE.get(node.severity, "")
            if style:
                lines.append(f"    style {node.id} {style}")
        elif node.kind == NodeKind.IMPACT:
            lines.append(f"    style {node.id} fill:#7c3aed,stroke:#6d28d9,color:#fff")

    return "\n".join(lines)


def format_graph_mermaid(org_graph: OrgGraph) -> str:
    """Render full org attack graph as Mermaid markdown."""
    lines: list[str] = []

    if org_graph.org:
        lines.append(f"# GhostGates Attack Graph — {org_graph.org}")
    else:
        lines.append("# GhostGates Attack Graph")
    lines.append("")

    if not org_graph.repo_graphs:
        lines.append("No attack paths found.")
        return "\n".join(lines)

    lines.append(f"**{len(org_graph.repo_graphs)} repos with attack paths**")
    lines.append("")
    lines.append("Legend: 🔵 Entry Point → 🔴 Bypassed Gate → 🟣 Impact")
    lines.append("")

    for rg in org_graph.repo_graphs:
        lines.append(f"## {rg.repo}")
        lines.append("")
        lines.append("```mermaid")
        lines.append(render_repo_mermaid(rg))
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def format_graph_json(org_graph: OrgGraph) -> str:
    """JSON representation of attack graphs."""
    return json.dumps(
        {
            "org": org_graph.org,
            "repo_count": len(org_graph.repo_graphs),
            "repos": [
                {
                    "repo": rg.repo,
                    "nodes": [
                        {
                            "id": n.id,
                            "label": n.label.replace("\\n", " "),
                            "kind": n.kind.value,
                            "severity": n.severity.value if n.severity else None,
                            "rule_id": n.rule_id or None,
                        }
                        for n in rg.nodes
                    ],
                    "edges": [
                        {"src": e.src, "dst": e.dst, "label": e.label}
                        for e in rg.edges
                    ],
                }
                for rg in org_graph.repo_graphs
            ],
        },
        indent=2,
    )


# ── Terminal preview ─────────────────────────────────────────────

_BOLD = "\033[1m"
_RED = "\033[31m"
_CYAN = "\033[36m"
_DIM = "\033[2m"
_MAGENTA = "\033[35m"
_BLUE = "\033[34m"
_RESET = "\033[0m"

_SEV_COLOR_TERM = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[2m",
    Severity.INFO: "\033[2m",
}


def format_graph_terminal(org_graph: OrgGraph) -> str:
    """ASCII kill chain view for terminal."""
    lines: list[str] = []

    lines.append("")
    lines.append(f"{_BOLD}╔══════════════════════════════════════════════════════╗{_RESET}")
    lines.append(f"{_BOLD}║  GhostGates Kill Chain                               ║{_RESET}")
    lines.append(f"{_BOLD}╚══════════════════════════════════════════════════════╝{_RESET}")
    lines.append("")

    if org_graph.org:
        lines.append(f"  Organization:  {org_graph.org}")
    lines.append(f"  Repos:         {len(org_graph.repo_graphs)} with attack paths")
    lines.append("")

    if not org_graph.repo_graphs:
        lines.append(f"  {_DIM}No attack paths found.{_RESET}")
        return "\n".join(lines)

    for rg in org_graph.repo_graphs:
        lines.append(f"  {_BOLD}{_CYAN}── {rg.repo} ──{_RESET}")
        lines.append("")

        # Group: entry → [bypass → impact] chains
        entry_nodes = [n for n in rg.nodes if n.kind == NodeKind.ENTRY]

        for entry in entry_nodes:
            lines.append(f"    {_BLUE}{entry.label.replace(chr(92) + 'n', ' ')}{_RESET}")

            # Find all bypasses reachable from this entry
            bypass_ids = [e.dst for e in rg.edges if e.src == entry.id]
            for bid in bypass_ids:
                bypass = next((n for n in rg.nodes if n.id == bid), None)
                if not bypass:
                    continue

                sev_c = _SEV_COLOR_TERM.get(bypass.severity, "") if bypass.severity else ""
                bypass_text = bypass.label.replace("\\n", " ")
                lines.append(f"      │")
                lines.append(f"      ├─ {sev_c}{bypass_text}{_RESET}  {_DIM}({bypass.rule_id}){_RESET}")

                # Find impacts from this bypass
                impact_ids = [e.dst for e in rg.edges if e.src == bid]
                for iid in impact_ids:
                    impact = next((n for n in rg.nodes if n.id == iid), None)
                    if impact:
                        impact_text = impact.label.replace("\\n", " ")
                        lines.append(f"      │    └─▶ {_MAGENTA}{impact_text}{_RESET}")

            lines.append("")

    return "\n".join(lines)
