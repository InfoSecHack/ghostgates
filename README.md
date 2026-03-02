# GhostGates

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/tests-319-green)
![Status](https://img.shields.io/badge/status-beta-orange)

GhostGates is a CI/CD security analysis tool that identifies **structural bypass paths** in GitHub Actions workflows, branch protections, environments, rulesets, and OIDC trust policies.

Traditional CI/CD scanners detect **misconfigurations**. GhostGates models **how controls interact** to uncover attack paths that allow bypassing those controls without violating any technical policy.

![GhostGates scan output showing CI/CD gate bypass findings](docs/screenshot.png)

---

## Table of Contents

- [Why GhostGates Exists](#why-ghostgates-exists)
- [Quick Start](#quick-start)
- [What GhostGates Detects](#what-ghostgates-detects)
- [Example Finding](#example-finding)
- [Threat Model](#threat-model)
- [Installation](#installation)
- [Usage](#usage)
- [Token Permissions](#token-permissions)
- [Rule Catalog](#rule-catalog-15-rules)
- [Architecture](#architecture)
- [Development](#development)
- [Adding New Rules](#adding-new-rules)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why GhostGates Exists

Organizations spend real effort configuring CI/CD security gates — required reviewers, branch protections, environment approvals, OIDC trust policies. Once configured, these controls are treated as enforced.

They often aren't.

The problem isn't misconfiguration. It's that **controls interact in ways that create structural bypass paths** — gaps where an attacker at a given privilege level can circumvent a gate entirely without violating any technical policy. The gate appears enforced. The bypass works anyway.

Real examples:

- A workflow using `pull_request_target` that checks out PR head code gives any external attacker privileged execution — no credentials required
- Branch protections with `enforce_admins` disabled make required reviews purely cosmetic for anyone with repo-admin access
- OIDC trust policies configured without an environment gate allow deployments from any branch in the repo
- Rulesets in evaluate mode log violations but block nothing — they look enforced in the UI

Traditional scanners flag the misconfiguration. GhostGates finds the bypass path.

It models **how controls interact**, maps the gap between configured and actually enforced, and shows the exact attack steps needed to exploit it.

---

## Quick Start

```bash
git clone https://github.com/InfoSecHack/ghostgates
cd ghostgates
pip install -e .
export GITHUB_TOKEN=ghp_your_token_here
ghostgates scan --org my-org
```

---

## What GhostGates Detects

Each finding includes:

- **Bypass path** — numbered attack steps showing exactly how the gate is bypassed
- **Evidence** — raw configuration values proving the bypass exists
- **Attacker level** — minimum privilege needed (external → org-owner)
- **Remediation** — specific fix with configuration guidance

---

## Example Finding

> **Note:** Simplified for readability. Actual terminal output formatting may differ.

```
[CRITICAL] GHOST-WF-001
Rule:      pull_request_target + PR head checkout (supply chain attack)
Workflow:  .github/workflows/pr_target_unsafe.yml
Attacker:  external (no credentials required)

Bypass Path:
  1. Workflow triggers on pull_request_target
  2. Job checks out the PR head branch:
       uses: actions/checkout@v3
       with:
         ref: ${{ github.event.pull_request.head.sha }}
  3. pull_request_target executes with BASE branch privileges
     and write-scoped GITHUB_TOKEN — not the fork's read-only token
  4. External attacker forks the repo and opens a PR with malicious code
  5. Malicious code runs in the privileged workflow context

Evidence:
  trigger:     pull_request_target
  head_ref:    github.event.pull_request.head.sha
  permissions: write

Impact:
  Full code execution in a privileged workflow context.
  Attacker can exfiltrate secrets, push commits, or poison
  build artifacts — from a fork PR with no write access.

Remediation:
  Replace pull_request_target with pull_request, or restructure
  the workflow to never check out untrusted PR head code in a
  privileged context. If pull_request_target is required, perform
  all untrusted code execution in a separate unprivileged job.
```

---

## Threat Model

GhostGates evaluates CI/CD security across a spectrum of attacker capability levels. Every rule specifies the **minimum privilege required** to exploit the bypass — so findings are scoped to what's actually reachable by a given attacker, not just theoretical worst-case.

| Attacker Level | Access | Typical Vector |
|----------------|--------|----------------|
| `external` | None — public repo only | Fork PR, open issue |
| `org-member` | Member of the GitHub organization | Internal PRs, org-level runners |
| `repo-write` | Can push branches and open PRs | Branch push, PR creation |
| `repo-maintain` | Can manage some branch protections | Protection overrides |
| `repo-admin` | Repository administrator | Settings, branch protection overrides |
| `org-owner` | Organization owner | Full org control |

This model matters because the blast radius of a bypass depends entirely on who can trigger it. A CRITICAL finding exploitable by `external` attackers — like GHOST-WF-001 — is a different class of risk than a HIGH finding that requires `repo-admin`.

---

## Installation

```bash
pip install -e ".[dev]"
```

Requires Python 3.11+.

---

## Usage

### Authentication

Set your GitHub token as an environment variable (recommended):

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

Or pass it directly (not recommended — appears in shell history):

```bash
ghostgates scan --org my-org --token ghp_xxx
```

### Live Scan

```bash
# Scan all repos in an org
ghostgates scan --org my-org

# Scan specific repos with verbose output
ghostgates scan --org my-org --repos api,web -v

# JSON output for CI integration
ghostgates scan --org my-org --format json > report.json

# Markdown report
ghostgates scan --org my-org --format md -o report.md

# Simulate specific attacker level
ghostgates scan --org my-org --attacker repo-write
```

### Offline Analysis

After a scan, gate models are stored locally. Re-run analysis without API calls:

```bash
ghostgates offline --org my-org --db ghostgates.db
ghostgates offline --org my-org --db ghostgates.db --attacker repo-admin --format json
```

### List Rules

```bash
ghostgates list-rules
ghostgates list-rules --format json
```

### Show Stored Results

```bash
ghostgates show --org my-org
ghostgates show --org my-org --scan-id 3 --format md
```

### Drift Detection

Detect new bypasses introduced between scans:

```bash
# Compare latest scan to previous scan
ghostgates diff --org my-org

# JSON output for CI integration
ghostgates diff --org my-org --format json

# Compare specific scan IDs
ghostgates diff --org my-org --old-id 3 --new-id 5
```

### Exit Codes

**scan / offline:**

| Code | Meaning |
|------|---------|
| `0` | No findings (or LOW/INFO only) |
| `1` | MEDIUM severity findings |
| `2` | HIGH or CRITICAL findings |

**diff:**

| Code | Meaning |
|------|---------|
| `0` | No new findings since last scan |
| `1` | New findings introduced |

Designed for CI/CD pipeline integration — fail the build when critical bypasses exist.

---

## Token Permissions

Required scopes:

- `repo` — read branch protections, collaborators, rulesets
- `read:org` — org Actions permissions, OIDC templates
- `admin:repo_hook` — optional, for webhook-based environment protections

Fine-grained tokens work with `Repository: Read` + `Organization: Read` permissions.

**Token safety:** Tokens are never logged, stored in the database, or included in error messages. All error paths scrub token patterns before raising.

---

## Rule Catalog (15 rules)

### Branch Protection (6 rules)

| ID | Rule | Severity | Min Privilege |
|----|------|----------|---------------|
| GHOST-BP-001 | Admin bypass of required reviews (`enforce_admins` disabled) | HIGH | repo-admin |
| GHOST-BP-002 | Stale review approval persistence (bait-and-switch PRs) | MEDIUM | repo-write |
| GHOST-BP-003 | Required reviews without CODEOWNERS enforcement | LOW | repo-write |
| GHOST-BP-004 | Deployment branches lack protection | MEDIUM | repo-write |
| GHOST-BP-005 | Workflows can approve their own PRs | HIGH | repo-write |
| GHOST-BP-006 | Ruleset in evaluate mode (false enforcement) | HIGH/MEDIUM | repo-write |

> **On admin bypasses:** A common objection to GHOST-BP-001 is *"I'm the admin — I need that flexibility."* The finding isn't about your intended use. It's about what happens when that account is compromised. A stolen maintainer token, a malicious insider, or a supply chain attack on a bot account with admin rights all inherit the same bypass. `enforce_admins: false` means the protection is only as strong as your weakest privileged credential.

### Environment (3 rules)

| ID | Rule | Severity | Min Privilege |
|----|------|----------|---------------|
| GHOST-ENV-001 | Production environment with no required reviewers | HIGH | repo-write |
| GHOST-ENV-002 | Environment allows deployment from any branch | MEDIUM | repo-write |
| GHOST-ENV-003 | Wait timer as only protection (auto-approve) | MEDIUM | repo-write |

### Workflow (4 rules)

| ID | Rule | Severity | Min Privilege |
|----|------|----------|---------------|
| GHOST-WF-001 | `pull_request_target` + PR head checkout (supply chain attack) | **CRITICAL** | **external** |
| GHOST-WF-002 | Workflow with write-all permissions | HIGH | repo-write |
| GHOST-WF-003 | Reusable workflow with `secrets: inherit` | HIGH | repo-write |
| GHOST-WF-004 | Workflow exposes secrets to fork PRs | HIGH | external |

### OIDC (2 rules)

| ID | Rule | Severity | Min Privilege |
|----|------|----------|---------------|
| GHOST-OIDC-001 | Default/broad OIDC subject claim | HIGH | repo-write |
| GHOST-OIDC-002 | OIDC token used without environment gate | HIGH | repo-write |

---

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

- **GateModel abstraction** — Rules never call APIs. All data is pre-collected into a typed model.
- **Decorator-based rules** — `@registry.rule(...)` auto-registers rules, filterable by attacker level and gate type.
- **Evidence-first** — Every finding includes the raw config values that prove the bypass.
- **Attacker modeling** — Findings are parameterized by minimum privilege level, not just severity.
- **Fail-safe parsing** — The workflow YAML parser never crashes; malformed files produce `parse_errors`, not exceptions.

---

## Development

```bash
# Run all tests
pytest tests/ -v

# Run specific rule tests
pytest tests/test_engine_bp_rules.py -v
pytest tests/test_engine_env_wf_oidc.py -v

# Run with debug output
pytest tests/ -v --tb=long -s
```

319 tests, ~11K lines of Python.

---

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

---

## Roadmap

- GitLab CI support
- Azure DevOps pipelines
- SARIF output
- Expanded rule catalog
- Pipeline security benchmarking
- Attack graph visualization

---

## License

MIT License. See [LICENSE](LICENSE) for details.
