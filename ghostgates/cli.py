"""
ghostgates/cli.py

Command-line interface for GhostGates.

Commands:
  scan       Scan an org's repos for gate bypasses
  list-rules List all registered bypass rules
  show       Show a stored scan result
  offline    Run rules against stored gate models (no API calls)

Usage:
  ghostgates scan --org <org> --token <token>
  ghostgates scan --org <org> --token <token> --repos api,web --attacker repo-admin
  ghostgates scan --org <org> --token <token> --format json > report.json
  ghostgates scan --org <org> --token <token> --format md -o report.md
  ghostgates list-rules
  ghostgates offline --org <org> --db ghostgates.db
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from ghostgates.models.enums import AttackerLevel
from ghostgates.models.findings import ScanResult


def main() -> int:
    """Main CLI entry point. Returns exit code."""
    parser = _build_parser()
    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if getattr(args, "debug", False) else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if not hasattr(args, "command") or args.command is None:
        parser.print_help()
        return 0

    if args.command == "scan":
        return asyncio.run(_cmd_scan(args))
    elif args.command == "list-rules":
        return _cmd_list_rules(args)
    elif args.command == "offline":
        return _cmd_offline(args)
    elif args.command == "show":
        return _cmd_show(args)
    elif args.command == "diff":
        return _cmd_diff(args)
    elif args.command == "rank":
        return _cmd_rank(args)
    elif args.command == "audit":
        return asyncio.run(_cmd_audit(args))
    elif args.command == "recon":
        return _cmd_recon(args)
    else:
        parser.print_help()
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghostgates",
        description="GhostGates — CI/CD gate bypass analysis engine",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    subs = parser.add_subparsers(dest="command")

    # --- scan ---
    scan_p = subs.add_parser("scan", help="Scan an org for gate bypasses")
    scan_p.add_argument("--org", required=True, help="GitHub organization name")
    scan_p.add_argument(
        "--token",
        default=os.environ.get("GITHUB_TOKEN", ""),
        help="GitHub token (or set GITHUB_TOKEN env var)",
    )
    scan_p.add_argument(
        "--attacker",
        default="org-owner",
        choices=[a.value for a in AttackerLevel],
        help="Attacker level to simulate (default: org-owner)",
    )
    scan_p.add_argument(
        "--repos",
        default=None,
        help="Comma-separated list of repo names to scan (default: all)",
    )
    scan_p.add_argument(
        "--include-forks",
        action="store_true",
        help="Include forked repos in scan",
    )
    scan_p.add_argument(
        "--format",
        default="terminal",
        choices=["terminal", "json", "md", "sarif"],
        help="Output format (default: terminal)",
    )
    scan_p.add_argument(
        "-o", "--output",
        default=None,
        help="Write output to file instead of stdout",
    )
    scan_p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed bypass paths and remediation",
    )
    scan_p.add_argument(
        "--db",
        default="ghostgates.db",
        help="SQLite database path for storing results (default: ghostgates.db)",
    )
    scan_p.add_argument(
        "--no-store",
        action="store_true",
        help="Don't store results in database",
    )
    scan_p.add_argument(
        "--rank",
        action="store_true",
        help="Show risk ranking table after scan",
    )

    # --- list-rules ---
    rules_p = subs.add_parser("list-rules", help="List all registered bypass rules")
    rules_p.add_argument(
        "--format",
        default="terminal",
        choices=["terminal", "json"],
        help="Output format",
    )

    # --- offline ---
    offline_p = subs.add_parser(
        "offline",
        help="Run rules against stored gate models (no API calls)",
    )
    offline_p.add_argument("--org", required=True, help="Organization to analyze")
    offline_p.add_argument("--db", default="ghostgates.db", help="Database path")
    offline_p.add_argument(
        "--attacker",
        default="org-owner",
        choices=[a.value for a in AttackerLevel],
        help="Attacker level",
    )
    offline_p.add_argument(
        "--format",
        default="terminal",
        choices=["terminal", "json", "md", "sarif"],
        help="Output format",
    )
    offline_p.add_argument("-v", "--verbose", action="store_true")
    offline_p.add_argument("-o", "--output", default=None)

    # --- show ---
    show_p = subs.add_parser("show", help="Show a stored scan result")
    show_p.add_argument("--org", required=True)
    show_p.add_argument("--db", default="ghostgates.db")
    show_p.add_argument("--scan-id", type=int, default=None, help="Specific scan ID (default: latest)")
    show_p.add_argument(
        "--format",
        default="terminal",
        choices=["terminal", "json", "md", "sarif"],
    )
    show_p.add_argument("-v", "--verbose", action="store_true")

    # --- diff ---
    diff_p = subs.add_parser("diff", help="Compare latest scan to previous scan (drift detection)")
    diff_p.add_argument("--org", required=True)
    diff_p.add_argument("--db", default="ghostgates.db")
    diff_p.add_argument(
        "--format",
        default="terminal",
        choices=["terminal", "json", "md"],
    )
    diff_p.add_argument("--old-id", type=int, default=None, help="Specific old scan ID (default: second-latest)")
    diff_p.add_argument("--new-id", type=int, default=None, help="Specific new scan ID (default: latest)")

    # --- rank ---
    rank_p = subs.add_parser("rank", help="Rank repos by risk score from last scan")
    rank_p.add_argument("--org", required=True)
    rank_p.add_argument("--db", default="ghostgates.db")
    rank_p.add_argument("--top", type=int, default=20, help="Show top N repos (default: 20)")
    rank_p.add_argument(
        "--format",
        default="terminal",
        choices=["terminal", "json"],
    )

    # --- audit ---
    audit_p = subs.add_parser("audit", help="Audit org against a security policy file")
    audit_p.add_argument("--org", required=True)
    audit_p.add_argument("--policy", required=True, help="Path to ghostgates-policy.yml")
    audit_p.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""),
                         help="GitHub token (or set GITHUB_TOKEN env var)")
    audit_p.add_argument("--db", default="ghostgates.db")
    audit_p.add_argument("--repos", default="", help="Comma-separated repos to scan (default: all)")
    audit_p.add_argument(
        "--format",
        default="terminal",
        choices=["terminal", "json", "md"],
    )
    audit_p.add_argument("-o", "--output", default=None, help="Write output to file")
    audit_p.add_argument("--offline", action="store_true",
                         help="Use stored gate models (no API calls)")

    # --- recon ---
    recon_p = subs.add_parser("recon", help="Attack surface view — findings grouped by offensive question")
    recon_p.add_argument("--org", required=True)
    recon_p.add_argument("--db", default="ghostgates.db")
    recon_p.add_argument(
        "--format",
        default="terminal",
        choices=["terminal", "json", "md"],
    )
    recon_p.add_argument("-o", "--output", default=None, help="Write output to file")

    return parser


# ------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------

async def _cmd_scan(args) -> int:
    """Execute a live scan against GitHub API."""
    from ghostgates.client.github_client import GitHubClient
    from ghostgates.collectors.assembly import collect_org_gate_models
    from ghostgates.engine import registry
    from ghostgates.storage import SQLiteStore
    from ghostgates.reporting import format_terminal, format_json, format_markdown

    token = args.token
    if not token:
        print("Error: GitHub token required. Set GITHUB_TOKEN or use --token.", file=sys.stderr)
        return 1

    org = args.org
    attacker = AttackerLevel(args.attacker)
    repo_filter = args.repos.split(",") if args.repos else None

    print(f"Scanning {org}...", file=sys.stderr)

    # --- Collect ---
    async with GitHubClient(token=token) as client:
        gate_models, collect_errors = await collect_org_gate_models(
            client,
            org,
            include_forks=args.include_forks,
            repo_filter=repo_filter,
        )

    if collect_errors:
        for err in collect_errors:
            logging.getLogger("ghostgates").warning("Collection error: %s", err)

    if not gate_models:
        print(f"No repos found for org '{org}'.", file=sys.stderr)
        return 1

    print(f"Collected {len(gate_models)} repos. Running rules...", file=sys.stderr)

    # --- Analyze ---
    findings = registry.run_all_repos(gate_models, attacker_level=attacker)

    # --- Build result ---
    result = ScanResult(
        org=org,
        repos_scanned=len(gate_models),
        findings=findings,
        attacker_level=attacker,
        collected_at=datetime.now(timezone.utc).isoformat(),
    )

    # --- Store ---
    if not args.no_store:
        store = SQLiteStore(args.db)
        store.upsert_gate_models(gate_models)
        scan_id = store.save_scan_result(result)
        store.close()
        print(f"Results stored (scan #{scan_id}, db: {args.db})", file=sys.stderr)

    # --- Format output ---
    output = _format_result(result, args.format, getattr(args, "verbose", False))
    _write_output(output, args.output)

    # --- Optional rank table ---
    if getattr(args, "rank", False) and findings:
        from ghostgates.reporting.rank import score_repos, format_rank_terminal
        scores = score_repos(findings)
        print(format_rank_terminal(scores, org))

    # Exit code: 2 if critical/high findings, 1 if medium+, 0 if clean
    return _exit_code(findings)


def _cmd_list_rules(args) -> int:
    """List all registered bypass rules."""
    import json
    from ghostgates.engine import registry

    if args.format == "json":
        rules_data = []
        for r in registry.rules:
            rules_data.append({
                "rule_id": r.rule_id,
                "name": r.name,
                "gate_type": str(r.gate_type),
                "min_privilege": str(r.min_privilege),
                "enabled": r.enabled,
                "tags": list(r.tags),
            })
        print(json.dumps(rules_data, indent=2))
    else:
        print(f"\n{'─' * 70}")
        print(f"  GhostGates Rules ({len(registry.rules)} registered)")
        print(f"{'─' * 70}\n")
        for r in sorted(registry.rules, key=lambda x: x.rule_id):
            status = "✓" if r.enabled else "✗"
            print(f"  {status} {r.rule_id:<16} {r.name}")
            print(f"    gate: {r.gate_type.value:<22} min: {r.min_privilege.value}")
            if r.tags:
                print(f"    tags: {', '.join(r.tags)}")
            print()

    return 0


def _cmd_offline(args) -> int:
    """Run rules against stored gate models."""
    from ghostgates.engine import registry
    from ghostgates.storage import SQLiteStore
    from ghostgates.reporting import format_terminal, format_json, format_markdown

    store = SQLiteStore(args.db)
    gate_models = store.get_gate_models(args.org)

    if not gate_models:
        print(f"No stored gate models for org '{args.org}' in {args.db}", file=sys.stderr)
        store.close()
        return 1

    attacker = AttackerLevel(args.attacker)
    findings = registry.run_all_repos(gate_models, attacker_level=attacker)

    result = ScanResult(
        org=args.org,
        repos_scanned=len(gate_models),
        findings=findings,
        attacker_level=attacker,
        collected_at=datetime.now(timezone.utc).isoformat(),
    )

    scan_id = store.save_scan_result(result)
    store.close()
    print(f"Offline scan complete (scan #{scan_id})", file=sys.stderr)

    output = _format_result(result, args.format, getattr(args, "verbose", False))
    _write_output(output, args.output)

    return _exit_code(findings)


def _cmd_show(args) -> int:
    """Show a stored scan result."""
    from ghostgates.storage import SQLiteStore

    store = SQLiteStore(args.db)

    if args.scan_id:
        result = store.get_scan_result(args.scan_id)
    else:
        result = store.get_latest_scan(args.org)

    store.close()

    if result is None:
        print(f"No scan results found.", file=sys.stderr)
        return 1

    output = _format_result(result, args.format, getattr(args, "verbose", False))
    print(output)

    return 0


def _cmd_diff(args) -> int:
    """Compare two scans for drift detection."""
    from ghostgates.storage import SQLiteStore
    from ghostgates.reporting.diff import (
        diff_scans,
        format_diff_terminal,
        format_diff_json,
        format_diff_markdown,
    )

    store = SQLiteStore(args.db)
    scans = store.list_scans(args.org, limit=20)

    if len(scans) < 2 and not (args.old_id and args.new_id):
        store.close()
        print(
            f"Need at least 2 scans for org '{args.org}' to diff. "
            f"Found {len(scans)}. Run 'ghostgates scan' again to create another.",
            file=sys.stderr,
        )
        return 1

    # Resolve scan IDs
    new_id = args.new_id or scans[0]["id"]
    old_id = args.old_id or scans[1]["id"]

    new_result = store.get_scan_result(new_id)
    old_result = store.get_scan_result(old_id)
    store.close()

    if not new_result or not old_result:
        print(f"Could not load scan(s): old={old_id}, new={new_id}", file=sys.stderr)
        return 1

    d = diff_scans(old_result, new_result)
    d.old_scan_id = old_id
    d.new_scan_id = new_id
    # Use scan metadata times
    d.old_scan_time = str(scans[1]["scan_time"]) if not args.old_id else d.old_scan_time
    d.new_scan_time = str(scans[0]["scan_time"]) if not args.new_id else d.new_scan_time

    if args.format == "json":
        print(format_diff_json(d))
    elif args.format == "md":
        print(format_diff_markdown(d))
    else:
        print(format_diff_terminal(d))

    # Exit code: 0 if no new findings, 1 if new findings introduced
    return 1 if d.new_findings else 0


def _cmd_rank(args) -> int:
    """Rank repos by risk score from latest scan."""
    from ghostgates.storage import SQLiteStore
    from ghostgates.reporting.rank import score_repos, format_rank_terminal, format_rank_json

    store = SQLiteStore(args.db)
    result = store.get_latest_scan(args.org)
    store.close()

    if result is None:
        print(f"No scan results found for org '{args.org}'.", file=sys.stderr)
        return 1

    scores = score_repos(result.findings)

    if args.format == "json":
        print(format_rank_json(scores, args.org))
    else:
        print(format_rank_terminal(scores, args.org, top_n=args.top))

    return 0


async def _cmd_audit(args) -> int:
    """Audit an org against a security policy file."""
    from ghostgates.policy.schema import load_policy
    from ghostgates.policy.evaluator import evaluate_policy
    from ghostgates.policy.formatter import (
        format_audit_terminal,
        format_audit_json,
        format_audit_markdown,
    )

    # Load policy
    try:
        policy = load_policy(args.policy)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error loading policy: {exc}", file=sys.stderr)
        return 1

    # Get gate models (live or offline)
    if getattr(args, "offline", False):
        from ghostgates.storage import SQLiteStore
        store = SQLiteStore(args.db)
        gate_models = store.get_gate_models(args.org)
        store.close()
        if not gate_models:
            print(f"No stored gate models for org '{args.org}'. Run a scan first.", file=sys.stderr)
            return 1
    else:
        token = args.token
        if not token:
            print("Error: GitHub token required. Set GITHUB_TOKEN or use --token.", file=sys.stderr)
            return 1

        from ghostgates.client.github_client import GitHubClient
        from ghostgates.collectors.assembly import collect_org_gate_models

        repos_filter = [r.strip() for r in args.repos.split(",") if r.strip()] or None

        async with GitHubClient(token=token) as client:
            gate_models = await collect_org_gate_models(
                client, args.org, repos=repos_filter,
            )

        # Store for future offline use
        from ghostgates.storage import SQLiteStore
        store = SQLiteStore(args.db)
        store.upsert_gate_models(gate_models)
        store.close()

    # Evaluate
    result = evaluate_policy(gate_models, policy, policy_path=args.policy)

    # Format output
    if args.format == "json":
        output = format_audit_json(result)
    elif args.format == "md":
        output = format_audit_markdown(result)
    else:
        output = format_audit_terminal(result)

    _write_output(output, getattr(args, "output", None))

    # Exit code: 0 if fully compliant, 1 if gaps found
    return 0 if result.noncompliant_count == 0 else 1


def _cmd_recon(args) -> int:
    """Attack surface view — findings grouped by offensive question."""
    from ghostgates.storage import SQLiteStore
    from ghostgates.reporting.recon import (
        build_recon,
        format_recon_terminal,
        format_recon_json,
        format_recon_markdown,
    )

    store = SQLiteStore(args.db)
    result = store.get_latest_scan(args.org)
    store.close()

    if result is None:
        print(f"No scan results found for org '{args.org}'.", file=sys.stderr)
        return 1

    recon = build_recon(result.findings, org=args.org)

    if args.format == "json":
        output = format_recon_json(recon)
    elif args.format == "md":
        output = format_recon_markdown(recon)
    else:
        output = format_recon_terminal(recon)

    _write_output(output, getattr(args, "output", None))
    return 0


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _format_result(result: ScanResult, fmt: str, verbose: bool) -> str:
    from ghostgates.reporting import format_terminal, format_json, format_markdown
    if fmt == "json":
        return format_json(result)
    elif fmt == "md":
        return format_markdown(result)
    elif fmt == "sarif":
        from ghostgates.reporting.sarif import format_sarif
        return format_sarif(result)
    else:
        return format_terminal(result, verbose=verbose)


def _write_output(output: str, filepath: str | None) -> None:
    if filepath:
        Path(filepath).write_text(output, encoding="utf-8")
        print(f"Report written to {filepath}", file=sys.stderr)
    else:
        print(output)


def _exit_code(findings: list) -> int:
    """Determine exit code from findings severity."""
    from ghostgates.models.enums import Severity
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities or Severity.HIGH in severities:
        return 2
    if Severity.MEDIUM in severities:
        return 1
    return 0


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())
