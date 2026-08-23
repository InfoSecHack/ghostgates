"""
ghostgates/reporting/graph.py

Finding relationship visualization. Each finding is shown with its stated
attacker prerequisite and a potential consequence. Edges do not demonstrate
exploitability or compose one finding into another.
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
    AttackerLevel.EXTERNAL: "External to target repo\\n(no target access)",
    AttackerLevel.ORG_MEMBER: "Org Member",
    AttackerLevel.REPO_WRITE: "Repo Write\\n(compromised dev)",
    AttackerLevel.REPO_MAINTAIN: "Repo Maintainer",
    AttackerLevel.REPO_ADMIN: "Repo Admin\\n(compromised admin)",
    AttackerLevel.ORG_OWNER: "Org Owner",
}


# ── Impact derivation ───────────────────────────────────────────

def _derive_impact(f: BypassFinding) -> tuple[str, str]:
    """Derive a potential consequence label from a finding."""
    rid = f.rule_id

    # Workflow-related potential consequences
    if rid == "GHOST-WF-001":
        return "impact_code_exec", "Potential code execution\\n+ secret access"
    if rid == "GHOST-WF-004":
        return "impact_secrets_fork", "Potential secret exposure\\nacross workflow boundary"
    if rid == "GHOST-WF-003":
        return "impact_secrets_inherit", "Potential secret exposure\\nvia inheritance"
    if rid == "GHOST-WF-002":
        return "impact_write_all", "Broad token permissions\\nif workflow is influenced"
    if rid == "GHOST-WF-005":
        return "impact_supply_chain", "Potential upstream action\\ncode change"
    if rid == "GHOST-WF-006":
        return "impact_remote_exec", "Sensitive manual run\\nif dispatcher is compromised"
    if rid == "GHOST-WF-007":
        return "impact_repo_write", "Potential repository\\nmodification"
    if rid == "GHOST-WF-008":
        return "impact_publish", "Potential unauthorized\\npublish"

    # OIDC → cloud
    if rid == "GHOST-OIDC-001":
        return "impact_cloud_cross", "Cloud trust-policy\\nreview required"
    if rid == "GHOST-OIDC-002":
        return "impact_cloud_nogated", "Potential OIDC token use\\nwithout reviewer gate"

    # Branch protection → unreviewed code
    if rid in ("GHOST-BP-001", "GHOST-BP-002", "GHOST-BP-005"):
        return "impact_unreviewed", "Potential review-policy\\nbypass"
    if rid == "GHOST-BP-003":
        return "impact_no_codeowner", "Potential merge without\\nowner review"
    if rid == "GHOST-BP-006":
        return "impact_ruleset_noop", "Ruleset observes only\\n(evaluate mode)"

    # Environment → prod deploy
    if rid == "GHOST-ENV-001":
        return "impact_prod_no_review", "Deployment environment\\nwithout reviewers"
    if rid == "GHOST-ENV-002":
        return "impact_prod_any_branch", "Deployment allowed\\nfrom any branch"
    if rid == "GHOST-ENV-003":
        return "impact_timed_no_review", "Timed deployment\\nwithout reviewers"

    return "impact_unknown", "Potential security consequence"


# ── Bypass node labels ───────────────────────────────────────────

def _bypass_label(f: BypassFinding) -> str:
    """Build a concise label for the finding node."""
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
        return f"✗ {wf}\\nworkflow_run trust boundary"

    if rid == "GHOST-BP-001":
        branch = ev.get("branch", "?")
        return f"✗ Branch Protection\\n{branch}\\nenforce_admins=false"

    if rid == "GHOST-BP-002":
        branch = ev.get("branch", "?")
        return f"✗ Branch Protection\\n{branch}\\nstale approvals persist"

    if rid == "GHOST-BP-003":
        branch = ev.get("branch", "?")
        return f"✗ Branch Protection\\n{branch}\\nno CODEOWNERS"


    if rid == "GHOST-BP-005":
        return "✗ Actions PR approval\\nsetting enabled"

    if rid == "GHOST-BP-006":
        rs = ev.get("ruleset_name", "?")
        return f"✗ Ruleset '{rs}'\\nevaluate mode (not enforced)"

    if rid == "GHOST-ENV-001":
        env = ev.get("environment", "?")
        return f"✗ Environment '{env}'\\nno required reviewers"

    if rid == "GHOST-ENV-002":
        env = ev.get("environment", "?")
        return f"✗ Environment '{env}'\\nno branch restriction"

    if rid == "GHOST-ENV-003":
        env = ev.get("environment", "?")
        return f"✗ Environment '{env}'\\nwait timer, no reviewers"

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
    """Build a prerequisite → finding → potential-consequence view."""
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
            # Finding node
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

            # Potential consequence node
            impact_id, impact_label = _derive_impact(f)
            if impact_id not in seen_nodes:
                graph.nodes.append(GraphNode(
                    id=impact_id,
                    label=impact_label,
                    kind=NodeKind.IMPACT,
                ))
                seen_nodes.add(impact_id)

            # Edges are presentation relationships, not validated exploit steps.
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
    """Build finding relationship graphs for all repos in a scan."""
    by_repo: dict[str, list[BypassFinding]] = {}
    for f in findings:
        by_repo.setdefault(f.repo, []).append(f)

    graphs = []
    for repo, repo_findings in sorted(by_repo.items()):
        g = build_repo_graph(repo, repo_findings)
        if g.edges:
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
    """Render a single repo's finding relationship graph as Mermaid."""
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
            # Hexagon for a finding
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
    """Render the organization finding graph as Mermaid markdown."""
    lines: list[str] = []

    if org_graph.org:
        lines.append(f"# GhostGates Finding Inference Graph — {org_graph.org}")
    else:
        lines.append("# GhostGates Finding Inference Graph")
    lines.append("")

    if not org_graph.repo_graphs:
        lines.append("No matching findings to visualize.")
        return "\n".join(lines)

    lines.append(f"**{len(org_graph.repo_graphs)} repos represented**")
    lines.append("")
    lines.append("Legend: 🔵 Attacker prerequisite → 🔴 Finding → 🟣 Potential consequence")
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
    """JSON representation of finding relationship graphs."""
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
    """Terminal view of finding prerequisites and potential consequences."""
    lines: list[str] = []

    lines.append("")
    lines.append(f"{_BOLD}╔══════════════════════════════════════════════════════╗{_RESET}")
    lines.append(f"{_BOLD}║  GhostGates Finding Inference Graph                   ║{_RESET}")
    lines.append(f"{_BOLD}╚══════════════════════════════════════════════════════╝{_RESET}")
    lines.append("")

    if org_graph.org:
        lines.append(f"  Organization:  {org_graph.org}")
    lines.append(f"  Repos:         {len(org_graph.repo_graphs)} represented")
    lines.append("")

    if not org_graph.repo_graphs:
        lines.append(f"  {_DIM}No matching findings to visualize.{_RESET}")
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
