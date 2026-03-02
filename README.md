# GhostGates

CI/CD gate bypass analysis engine. Maps the gap between configured security gates and actual enforceability across GitHub Actions workflows, branch protections, environments, and OIDC.

## What It Does

Organizations configure security "gates" in GitHub — required reviews, environment approvals, branch protections, OIDC claims. GhostGates systematically identifies when those gates are **structurally bypassable**, meaning an attacker at a given privilege level can circumvent them without breaking any technical controls.

Each finding includes:
- **Bypass path**: Numbered attack steps showing exactly how the gate is bypassed
- **Evidence**: Raw configuration values proving the bypass exists
- **Attacker level**: Minimum privilege needed (external → org-owner)
- **Remediation**: Specific fix with configuration guidance

## Installation

```bash
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Usage

### Live scan (requires GitHub token)

```bash
# Scan all repos in an org
ghostgates scan --org my-org --token ghp_xxx

# Scan specific repos with verbose output
ghostgates scan --org my-org --token ghp_xxx --repos api,web -v

# JSON output for CI integration
ghostgates scan --org my-org --token ghp_xxx --format json > report.json

# Markdown report
ghostgates scan --org my-org --token ghp_xxx --format md -o report.md

# Simulate specific attacker level
ghostgates scan --org my-org --token ghp_xxx --attacker repo-write
```

### Offline analysis (no API calls)

After a scan, gate models are stored locally. Re-run analysis without API calls:

```bash
ghostgates offline --org my-org --db ghostgates.db
ghostgates offline --org my-org --db ghostgates.db --attacker repo-admin --format json
```

### List rules

```bash
ghostgates list-rules
ghostgates list-rules --format json
```

### Show stored results

```bash
ghostgates show --org my-org
ghostgates show --org my-org --scan-id 3 --format md
```

### Drift detection (diff)

```bash
# Compare latest scan to previous scan
ghostgates diff --org my-org

# JSON output for CI integration
ghostgates diff --org my-org --format json

# Compare specific scan IDs
ghostgates diff --org my-org --old-id 3 --new-id 5
```

### Exit codes

**scan/offline:**

| Code | Meaning |
|------|---------|
| 0 | No findings (or LOW/INFO only) |
| 1 | MEDIUM severity findings |
| 2 | HIGH or CRITICAL findings |

**diff:**

| Code | Meaning |
|------|---------|
| 0 | No new findings since last scan |
| 1 | New findings introduced |

Designed for CI/CD pipeline integration — fail the build when critical bypasses exist.

## Token Permissions

The GitHub token needs these scopes:
- `repo` (read branch protections, collaborators, rulesets)
- `read:org` (org Actions permissions, OIDC templates)
- `admin:repo_hook` (optional, for webhook-based environment protections)

Fine-grained tokens work with `Repository: Read` + `Organization: Read` permissions.

**Token safety**: Tokens are never logged, stored in the database, or included in error messages. All error paths scrub token patterns before raising.

## Rule Catalog (15 rules)

### Branch Protection (6 rules)

| ID | Rule | Severity | Min Privilege |
|----|------|----------|---------------|
| GHOST-BP-001 | Admin bypass of required reviews (enforce_admins disabled) | HIGH | repo-admin |
| GHOST-BP-002 | Stale review approval persistence (bait-and-switch PRs) | MEDIUM | repo-write |
| GHOST-BP-003 | Required reviews without CODEOWNERS enforcement | LOW | repo-write |
| GHOST-BP-004 | Deployment branches lack protection | MEDIUM | repo-write |
| GHOST-BP-005 | Workflows can approve their own PRs | HIGH | repo-write |
| GHOST-BP-006 | Ruleset in evaluate mode (false enforcement) | HIGH/MEDIUM | repo-write |

### Environment (3 rules)

| ID | Rule | Severity | Min Privilege |
|----|------|----------|---------------|
| GHOST-ENV-001 | Production environment with no required reviewers | HIGH | repo-write |
| GHOST-ENV-002 | Environment allows deployment from any branch | MEDIUM | repo-write |
| GHOST-ENV-003 | Wait timer as only protection (auto-approve) | MEDIUM | repo-write |

### Workflow (4 rules)

| ID | Rule | Severity | Min Privilege |
|----|------|----------|---------------|
| GHOST-WF-001 | pull_request_target + PR head checkout (supply chain attack) | **CRITICAL** | **external** |
| GHOST-WF-002 | Workflow with write-all permissions | HIGH | repo-write |
| GHOST-WF-003 | Reusable workflow with secrets: inherit | HIGH | repo-write |
| GHOST-WF-004 | Workflow exposes secrets to fork PRs | HIGH | external |

### OIDC (2 rules)

| ID | Rule | Severity | Min Privilege |
|----|------|----------|---------------|
| GHOST-OIDC-001 | Default/broad OIDC subject claim | HIGH | repo-write |
| GHOST-OIDC-002 | OIDC token used without environment gate | HIGH | repo-write |

## Architecture

```
GitHub API
    ↓
Collectors (org, repos, environments, workflows)
    ↓
GateModel (per-repo structured data)
    ↓
Rule Engine (15 bypass rules, decorator-registered)
    ↓
Findings (evidence-backed, attacker-level parameterized)
    ↓
Output (terminal / JSON / markdown)
```

Key design principles:
- **GateModel abstraction**: Rules never call APIs. All data is pre-collected into a typed model.
- **Decorator-based rules**: `@registry.rule(...)` — auto-registered, filterable by attacker level and gate type.
- **Evidence-first**: Every finding includes the raw config values that prove the bypass.
- **Attacker modeling**: Findings are parameterized by minimum privilege level, not just severity.
- **Fail-safe parsing**: The workflow YAML parser never crashes — malformed files produce parse_errors, not exceptions.

## Development

```bash
# Run tests
pytest tests/ -v

# Run specific rule tests
pytest tests/test_engine_bp_rules.py -v
pytest tests/test_engine_env_wf_oidc.py -v

# Run with debug output
pytest tests/ -v --tb=long -s
```

319 tests, ~11K lines of Python.

## Adding New Rules

```python
from ghostgates.engine.registry import registry
from ghostgates.models.enums import AttackerLevel, Confidence, GateType, Severity
from ghostgates.models.gates import GateModel
from ghostgates.models.findings import BypassFinding

@registry.rule(
    rule_id="GHOST-XX-001",
    name="My new bypass rule",
    gate_type=GateType.WORKFLOW,
    min_privilege=AttackerLevel.REPO_WRITE,
    tags=("workflow", "custom"),
)
def xx_001_my_rule(gate: GateModel) -> list[BypassFinding]:
    findings = []
    # Check gate model for bypass condition
    # Append BypassFinding with evidence if found
    return findings
```

Then import the module in `ghostgates/engine/__init__.py` and it auto-registers.

## License

MIT License. See [LICENSE](LICENSE) for details.
