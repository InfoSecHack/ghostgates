# GhostGates — Master Architecture Document
## CI/CD Runtime Gate Bypass Mapper

**Version:** 1.0
**Purpose:** This document is the single source of truth for all module interfaces, data models, and contracts. Every build session references this document. No module may deviate from these contracts without updating this document first.

---

## 1. Directory Structure

```
ghostgates/
├── pyproject.toml
├── README.md
├── ghostgates/
│   ├── __init__.py
│   ├── cli.py                    # Typer CLI entry point
│   ├── config.py                 # Configuration + constants
│   ├── models/
│   │   ├── __init__.py
│   │   ├── gates.py              # GateModel + all sub-models
│   │   ├── findings.py           # BypassFinding + BypassRule
│   │   └── enums.py              # Shared enumerations
│   ├── client/
│   │   ├── __init__.py
│   │   ├── github_client.py      # Rate-limited GitHub API client
│   │   └── rate_limiter.py       # Async rate limiter
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── org.py                # Org-level collection
│   │   ├── repos.py              # Repo + branch protection collection
│   │   ├── environments.py       # Environment protection collection
│   │   └── workflows.py          # Workflow YAML + OIDC collection
│   ├── storage/
│   │   ├── __init__.py
│   │   └── sqlite_store.py       # SQLite storage + gate model assembly
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── registry.py           # Rule registry + runner
│   │   └── rules/
│   │       ├── __init__.py
│   │       ├── branch_protection.py   # GHOST-BP-* rules
│   │       ├── environment.py         # GHOST-ENV-* rules
│   │       ├── workflow.py            # GHOST-WF-* rules
│   │       └── oidc.py               # GHOST-OIDC-* rules
│   └── reporting/
│       ├── __init__.py
│       ├── cli_output.py         # Rich terminal output
│       ├── json_output.py        # Machine-readable JSON
│       ├── markdown_report.py    # Engagement report
│       └── templates/
│           └── report.md.j2      # Jinja2 report template
└── tests/
    ├── __init__.py
    ├── conftest.py               # Shared fixtures + mock factories
    ├── test_rate_limiter.py
    ├── test_collectors.py
    ├── test_storage.py
    ├── test_engine.py
    ├── test_rules_bp.py
    ├── test_rules_env.py
    ├── test_rules_wf.py
    ├── test_rules_oidc.py
    └── mocks/
        ├── github_responses.py   # Factory functions for mock API responses
        └── gate_models.py        # Factory functions for test GateModels
```

---

## 2. Dependencies (pyproject.toml)

```toml
[project]
name = "ghostgates"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "httpx>=0.27.0",
    "pydantic>=2.0",
    "typer>=0.12.0",
    "rich>=13.0",
    "ruamel.yaml>=0.18.0",
    "jinja2>=3.1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23.0",
    "respx>=0.21.0",
    "ruff>=0.5.0",
]

[project.scripts]
ghostgates = "ghostgates.cli:app"
```

---

## 3. Enumerations (ghostgates/models/enums.py)

These are shared across all modules. No module defines its own enums.

```python
from enum import StrEnum

class AttackerLevel(StrEnum):
    """Attacker privilege levels. Higher = more access."""
    EXTERNAL = "external"           # L0: no repo access, can fork public repos
    ORG_MEMBER = "org-member"       # L1: can fork, submit PRs
    REPO_WRITE = "repo-write"       # L2: can push branches, tags
    REPO_MAINTAIN = "repo-maintain" # L3: can manage some protections
    REPO_ADMIN = "repo-admin"       # L4: full repo admin
    ORG_OWNER = "org-owner"         # L5: org-level override

    @property
    def level(self) -> int:
        return list(AttackerLevel).index(self) + 1

    def __ge__(self, other: "AttackerLevel") -> bool:
        return self.level >= other.level

    def __gt__(self, other: "AttackerLevel") -> bool:
        return self.level > other.level

    def __le__(self, other: "AttackerLevel") -> bool:
        return self.level <= other.level

    def __lt__(self, other: "AttackerLevel") -> bool:
        return self.level < other.level


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class GateType(StrEnum):
    BRANCH_PROTECTION = "branch_protection"
    RULESET = "ruleset"
    ENVIRONMENT = "environment"
    WORKFLOW = "workflow"
    OIDC = "oidc"
    ACTIONS_PERMISSIONS = "actions_permissions"
```

---

## 4. Gate Models (ghostgates/models/gates.py)

These represent the collected state of a repository's security gates. Collectors produce these. The rule engine consumes these.

```python
from pydantic import BaseModel, Field
from datetime import datetime

# --- Sub-models (building blocks) ---

class BranchProtection(BaseModel):
    """Branch protection rule as returned by GitHub API, normalized."""
    branch: str                                      # e.g. "main"
    enabled: bool = True
    required_approving_review_count: int = 0
    dismiss_stale_reviews: bool = False
    require_code_owner_reviews: bool = False
    required_status_checks: list[str] = Field(default_factory=list)
    require_status_checks_strict: bool = False       # require up-to-date branch
    enforce_admins: bool = False                     # admins subject to rules
    restrict_pushes: bool = False
    push_allowances: list[str] = Field(default_factory=list)  # actors who can push
    bypass_pull_request_allowances: list[str] = Field(default_factory=list)
    require_linear_history: bool = False
    allow_force_pushes: bool = False
    allow_deletions: bool = False
    lock_branch: bool = False
    required_signatures: bool = False
    raw: dict = Field(default_factory=dict)          # full API response for evidence


class Ruleset(BaseModel):
    """GitHub repository ruleset (newer replacement for branch protections)."""
    id: int
    name: str
    enforcement: str                                 # "active", "evaluate", "disabled"
    target: str                                      # "branch", "tag"
    conditions: dict = Field(default_factory=dict)   # ref_name include/exclude patterns
    rules: list[dict] = Field(default_factory=list)  # rule objects
    bypass_actors: list[dict] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class EnvironmentProtection(BaseModel):
    """Deployment branch policy within an environment."""
    type: str = "all"             # "all", "protected", "selected", "none"
    patterns: list[str] = Field(default_factory=list)  # branch name patterns for "selected"


class EnvironmentReviewer(BaseModel):
    """Required reviewer for an environment."""
    type: str                     # "User" or "Team"
    id: int
    login: str = ""               # username or team slug
    member_count: int | None = None  # for teams: how many members


class CustomProtectionRule(BaseModel):
    """Custom deployment protection rule (external webhook)."""
    id: int
    app_slug: str
    timeout_minutes: int = 30     # GitHub default: 30 min, auto-approve if no response


class EnvironmentConfig(BaseModel):
    """Complete environment configuration."""
    name: str
    protection_rules: list[dict] = Field(default_factory=list)  # raw wait_timer, reviewers
    deployment_branch_policy: EnvironmentProtection = Field(
        default_factory=lambda: EnvironmentProtection()
    )
    reviewers: list[EnvironmentReviewer] = Field(default_factory=list)
    wait_timer: int = 0                              # minutes
    custom_rules: list[CustomProtectionRule] = Field(default_factory=list)
    has_secrets: bool = False                         # whether env has secrets configured
    raw: dict = Field(default_factory=dict)


class WorkflowTrigger(BaseModel):
    """Parsed workflow trigger configuration."""
    event: str                    # push, pull_request, pull_request_target, etc.
    branches: list[str] = Field(default_factory=list)
    branches_ignore: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    types: list[str] = Field(default_factory=list)
    inputs: dict = Field(default_factory=dict)       # for workflow_dispatch


class WorkflowStep(BaseModel):
    """Minimal parsed step — enough for bypass analysis."""
    name: str = ""
    uses: str = ""                # action reference
    run: str = ""                 # shell command
    with_: dict = Field(default_factory=dict, alias="with")
    env: dict = Field(default_factory=dict)


class WorkflowJob(BaseModel):
    """Parsed job from workflow YAML."""
    name: str
    runs_on: str | list[str] = "ubuntu-latest"
    environment: str | dict | None = None   # environment name or {name, url}
    permissions: dict = Field(default_factory=dict)
    steps: list[WorkflowStep] = Field(default_factory=list)
    secrets: str | dict | None = None       # "inherit" or specific secrets
    uses: str = ""                          # reusable workflow ref
    if_condition: str = ""                  # if: expression


class WorkflowDefinition(BaseModel):
    """Complete parsed workflow file."""
    path: str                     # .github/workflows/deploy.yml
    name: str = ""
    triggers: list[WorkflowTrigger] = Field(default_factory=list)
    permissions: dict = Field(default_factory=dict)   # top-level permissions
    jobs: list[WorkflowJob] = Field(default_factory=list)
    raw_yaml: str = ""            # original YAML for evidence
    parse_errors: list[str] = Field(default_factory=list)


class WorkflowPermissions(BaseModel):
    """Org/repo-level Actions permission settings."""
    default_workflow_permissions: str = "read"   # "read" or "write"
    can_approve_pull_request_reviews: bool = False
    allowed_actions: str = "all"                 # "all", "local_only", "selected"
    enabled: bool = True


class OIDCConfig(BaseModel):
    """OIDC subject claim customization."""
    org_level_template: list[str] = Field(default_factory=list)  # claim keys
    repo_level_overrides: dict = Field(default_factory=dict)
    raw: dict = Field(default_factory=dict)


class Collaborator(BaseModel):
    """Repository collaborator with permission level."""
    login: str
    id: int
    permission: str               # "admin", "maintain", "write", "triage", "read"
    is_team: bool = False
    team_slug: str = ""


# --- Top-level Gate Model ---

class GateModel(BaseModel):
    """
    Complete security gate model for a single repository.
    This is the PRIMARY INPUT to the rule engine.
    Collectors build these. Rules consume these.
    """
    org: str
    repo: str
    full_name: str                # "org/repo"
    default_branch: str = "main"
    visibility: str = "private"   # "public", "private", "internal"
    is_fork: bool = False
    is_archived: bool = False
    branch_protections: list[BranchProtection] = Field(default_factory=list)
    rulesets: list[Ruleset] = Field(default_factory=list)
    environments: list[EnvironmentConfig] = Field(default_factory=list)
    workflow_permissions: WorkflowPermissions = Field(
        default_factory=lambda: WorkflowPermissions()
    )
    workflows: list[WorkflowDefinition] = Field(default_factory=list)
    oidc: OIDCConfig = Field(default_factory=lambda: OIDCConfig())
    collaborators: list[Collaborator] = Field(default_factory=list)
    collected_at: datetime | None = None
```

---

## 5. Finding Models (ghostgates/models/findings.py)

These represent the OUTPUT of the rule engine.

```python
from pydantic import BaseModel, Field
from ghostgates.models.enums import AttackerLevel, Severity, Confidence, GateType

class BypassFinding(BaseModel):
    """A single bypass finding produced by a rule."""
    rule_id: str                           # e.g. "GHOST-BP-001"
    rule_name: str
    repo: str                              # "org/repo"
    gate_type: GateType
    severity: Severity
    confidence: Confidence
    min_privilege: AttackerLevel
    summary: str                           # one-line human-readable
    bypass_path: str                       # step-by-step explanation
    evidence: dict                         # raw config proving the finding
    gating_conditions: list[str]           # what else must be true
    remediation: str                       # specific fix
    references: list[str] = Field(default_factory=list)

    def meets_filter(
        self,
        min_severity: Severity | None = None,
        max_attacker_level: AttackerLevel | None = None,
    ) -> bool:
        """Check if finding passes user-specified filters.

        Severity ordering: CRITICAL(0) > HIGH(1) > MEDIUM(2) > LOW(3) > INFO(4).
        A finding meets the filter when its severity index <= min_severity index.

        NOTE: Severity is a plain StrEnum (no custom __gt__), so we MUST
        use index-based comparison. Alphabetical comparison is wrong.
        """
        if min_severity is not None:
            severity_order = list(Severity)
            if severity_order.index(self.severity) > severity_order.index(min_severity):
                return False
        if max_attacker_level is not None and self.min_privilege > max_attacker_level:
            return False
        return True


class ScanResult(BaseModel):
    """Complete scan result for an org."""
    org: str
    repos_scanned: int
    repos_skipped: int = 0                 # archived, forked, etc.
    findings: list[BypassFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    scan_duration_seconds: float = 0.0
    attacker_level: AttackerLevel
    collected_at: str = ""

    @property
    def finding_count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
```

---

## 6. Rule Engine Contract (ghostgates/engine/registry.py)

```python
from typing import Callable
from ghostgates.models.gates import GateModel
from ghostgates.models.findings import BypassFinding
from ghostgates.models.enums import AttackerLevel, Severity, Confidence, GateType

# Type alias for rule functions
RuleFunc = Callable[[GateModel], list[BypassFinding]]


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata wrapper for a registered bypass rule."""
    rule_id: str          # e.g. "GHOST-BP-001"
    name: str             # human-readable rule name
    gate_type: GateType   # which gate category this rule checks
    min_privilege: AttackerLevel  # minimum attacker level to trigger
    func: RuleFunc        # the actual rule function
    tags: tuple[str, ...] = ()
    enabled: bool = True


class RuleRegistry:
    """Central registry of all bypass rules."""

    def rule(
        self,
        rule_id: str,
        name: str,
        gate_type: GateType,
        min_privilege: AttackerLevel,
        tags: tuple[str, ...] = (),
        enabled: bool = True,
    ) -> Callable[[RuleFunc], RuleFunc]:
        """Decorator to register a bypass rule."""
        ...

    def run_rules(
        self,
        gate: GateModel,
        *,
        attacker_level: AttackerLevel = AttackerLevel.ORG_MEMBER,
        rule_ids: list[str] | None = None,
        gate_types: list[GateType] | None = None,
    ) -> list[BypassFinding]:
        """Execute all applicable rules against a GateModel, filtered by attacker level."""
        ...

    def run_all_repos(
        self,
        gates: list[GateModel],
        *,
        attacker_level: AttackerLevel = AttackerLevel.ORG_MEMBER,
    ) -> list[BypassFinding]:
        """Run all rules against multiple GateModels."""
        ...

# Global registry instance — rules register themselves on import
registry = RuleRegistry()
```

### Rule Implementation Pattern (Example)

Every rule file follows this exact pattern:

```python
# ghostgates/engine/rules/branch_protection.py
from ghostgates.engine.registry import registry
from ghostgates.models.gates import GateModel
from ghostgates.models.findings import BypassFinding
from ghostgates.models.enums import *


@registry.rule(
    rule_id="GHOST-BP-001",
    name="Admin bypass of required reviews",
    gate_type=GateType.BRANCH_PROTECTION,
    min_privilege=AttackerLevel.REPO_ADMIN,
    tags=("branch-protection", "review-bypass"),
)
def bp_001_admin_bypass(gate: GateModel) -> list[BypassFinding]:
    findings = []
    for bp in gate.branch_protections:
        if bp.required_approving_review_count > 0 and not bp.enforce_admins:
            admin_count = sum(
                1 for c in gate.collaborators if c.permission == "admin"
            )
            findings.append(BypassFinding(
                rule_id="GHOST-BP-001",
                rule_name="Admin bypass of required reviews",
                repo=gate.full_name,
                gate_type=GateType.BRANCH_PROTECTION,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                min_privilege=AttackerLevel.REPO_ADMIN,
                summary=(
                    f"Branch '{bp.branch}' requires {bp.required_approving_review_count} "
                    f"review(s) but enforce_admins is disabled. "
                    f"{admin_count} admin(s) can bypass."
                ),
                bypass_path=(
                    f"1. Attacker with admin access to {gate.full_name}\n"
                    f"2. Push directly to '{bp.branch}' (admins exempt from reviews)\n"
                    f"3. Or: merge own PR without required approvals"
                ),
                evidence={
                    "branch": bp.branch,
                    "required_reviews": bp.required_approving_review_count,
                    "enforce_admins": False,
                    "admin_count": admin_count,
                    "admin_logins": [
                        c.login for c in gate.collaborators
                        if c.permission == "admin"
                    ],
                },
                gating_conditions=[
                    "Attacker must have admin access to the repository",
                ],
                remediation=(
                    f"Enable 'Include administrators' (enforce_admins) on "
                    f"branch protection for '{bp.branch}'"
                ),
                references=[
                    "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule/about-branch-protection-rules"
                ],
            ))
    return findings
```

---

## 7. GitHub Client Contract (ghostgates/client/github_client.py)

```python
class GitHubClient:
    """Rate-limited async GitHub API client."""

    def __init__(self, token: str, base_url: str = "https://api.github.com"):
        ...

    async def get(self, path: str, params: dict | None = None) -> dict | list:
        """GET request with rate limiting and retry."""
        ...

    async def get_paginated(self, path: str, params: dict | None = None) -> list[dict]:
        """GET with automatic pagination (follows Link headers)."""
        ...

    async def get_raw(self, path: str) -> str:
        """GET raw content (for workflow YAML files)."""
        ...

    async def close(self) -> None:
        ...

    # --- Convenience methods (thin wrappers) ---

    async def list_org_repos(self, org: str) -> list[dict]:
        return await self.get_paginated(f"/orgs/{org}/repos", {"type": "all"})

    async def get_branch_protection(self, owner: str, repo: str, branch: str) -> dict | None:
        """Returns None if no protection (404)."""
        ...

    async def list_environments(self, owner: str, repo: str) -> list[dict]:
        ...

    async def get_environment(self, owner: str, repo: str, env_name: str) -> dict:
        ...

    async def list_collaborators(self, owner: str, repo: str) -> list[dict]:
        ...

    async def get_workflow_content(self, owner: str, repo: str, path: str) -> str:
        """Fetch raw workflow YAML content."""
        ...

    async def list_workflow_files(self, owner: str, repo: str) -> list[dict]:
        """List files in .github/workflows/."""
        ...

    async def get_org_actions_permissions(self, org: str) -> dict:
        ...

    async def get_repo_actions_permissions(self, owner: str, repo: str) -> dict:
        ...

    async def list_rulesets(self, owner: str, repo: str) -> list[dict]:
        ...

    async def get_oidc_template(self, org: str) -> dict | None:
        ...
```

---

## 8. Rate Limiter Contract (ghostgates/client/rate_limiter.py)

```python
class RateLimiter:
    """
    Respects GitHub's three rate limit layers:
    1. Primary: 5000 requests/hour (tracked via x-ratelimit-remaining)
    2. Secondary: points-per-minute (tracked via retry-after header on 403)
    3. Concurrent: max simultaneous requests (configurable, default 10)
    """

    def __init__(self, max_concurrent: int = 10):
        ...

    async def acquire(self) -> None:
        """Block until a request slot is available."""
        ...

    def update_from_headers(self, headers: dict) -> None:
        """Update rate limit state from response headers."""
        ...

    async def handle_rate_limit(self, response) -> float:
        """Handle 403/429 responses. Returns seconds to wait."""
        ...

    @property
    def remaining(self) -> int:
        ...

    @property
    def is_exhausted(self) -> bool:
        ...
```

---

## 9. Collector Contracts

Each collector takes a `GitHubClient` and produces model objects.

```python
# collectors/org.py
async def collect_org_metadata(client: GitHubClient, org: str) -> dict:
    """Collect org-level settings (Actions permissions, OIDC templates)."""
    ...

# collectors/repos.py
async def collect_repos(client: GitHubClient, org: str) -> list[dict]:
    """List all repos, filter out archived/disabled."""
    ...

async def collect_branch_protections(
    client: GitHubClient, owner: str, repo: str, default_branch: str
) -> list[BranchProtection]:
    """Collect branch protection rules for default + common branches."""
    ...

async def collect_collaborators(
    client: GitHubClient, owner: str, repo: str
) -> list[Collaborator]:
    ...

# collectors/environments.py
async def collect_environments(
    client: GitHubClient, owner: str, repo: str
) -> list[EnvironmentConfig]:
    ...

# collectors/workflows.py
async def collect_workflows(
    client: GitHubClient, owner: str, repo: str
) -> list[WorkflowDefinition]:
    """Fetch and parse all workflow YAML files."""
    ...

def parse_workflow_yaml(path: str, content: str) -> WorkflowDefinition:
    """Parse a workflow YAML string into a WorkflowDefinition.
    This is a pure function — no API calls. Testable in isolation."""
    ...
```

---

## 10. Storage Contract (ghostgates/storage/sqlite_store.py)

```python
class GhostGatesStore:
    """SQLite storage for collected data and scan results."""

    def __init__(self, db_path: str = "ghostgates.db"):
        ...

    def init_db(self) -> None:
        """Create tables if not exist."""
        ...

    def save_gate_model(self, gate: GateModel) -> None:
        """Upsert a gate model (keyed by org/repo)."""
        ...

    def load_gate_model(self, org: str, repo: str) -> GateModel | None:
        ...

    def load_all_gate_models(self, org: str) -> list[GateModel]:
        ...

    def save_scan_result(self, result: ScanResult) -> None:
        ...

    def load_latest_scan(self, org: str) -> ScanResult | None:
        ...

    def get_repo_last_collected(self, org: str, repo: str) -> str | None:
        """Return ISO timestamp of last collection, for incremental."""
        ...
```

### SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS gate_models (
    org TEXT NOT NULL,
    repo TEXT NOT NULL,
    full_name TEXT NOT NULL,
    gate_model_json TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    PRIMARY KEY (org, repo)
);

CREATE TABLE IF NOT EXISTS scan_results (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    org TEXT NOT NULL,
    attacker_level TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scans_org ON scan_results(org, created_at DESC);
```

Storage is intentionally simple for MVP: serialize GateModel and ScanResult as JSON. This avoids complex relational mapping while keeping all data queryable via json_extract() if needed.

---

## 11. CLI Contract (ghostgates/cli.py)

```python
import typer
app = typer.Typer(name="ghostgates", help="CI/CD Gate Bypass Mapper")

@app.command()
def scan(
    org: str = typer.Argument(..., help="GitHub organization name"),
    token: str = typer.Option(..., envvar="GITHUB_TOKEN", help="GitHub PAT"),
    attacker_level: str = typer.Option("repo-write", "--attacker-level", "-a"),
    severity: str = typer.Option("low", "--min-severity", "-s"),
    output: str = typer.Option("cli", "--output", "-o",
                               help="Output format: cli, json, markdown"),
    output_file: str = typer.Option(None, "--output-file", "-f"),
    repos: str = typer.Option(None, "--repos", "-r",
                              help="Comma-separated repo names to scan (default: all)"),
    skip_collection: bool = typer.Option(False, "--skip-collection",
                                         help="Use cached data, skip API calls"),
    db_path: str = typer.Option("ghostgates.db", "--db"),
    max_concurrent: int = typer.Option(10, "--max-concurrent"),
):
    """Scan a GitHub org for CI/CD gate bypass paths."""
    ...

@app.command()
def list_rules():
    """List all registered bypass rules."""
    ...

@app.command()
def show(
    org: str = typer.Argument(...),
    db_path: str = typer.Option("ghostgates.db", "--db"),
):
    """Show results from the last scan."""
    ...
```

---

## 12. Security Requirements (Non-Negotiable)

1. **Token handling**: GitHub PAT is passed via `--token` or `GITHUB_TOKEN` env var. Never logged, never stored in SQLite, never included in findings or reports.
2. **No secrets in evidence**: Evidence dicts contain config structure, never secret values.
3. **Input validation**: Org names and repo names validated against `^[a-zA-Z0-9._-]+$` before API calls.
4. **Error messages**: Never include tokens or credentials in error messages or tracebacks.
5. **SQLite**: DB file permissions set to 0o600 on creation.
6. **Dependencies**: Minimal. No unnecessary packages. Every dependency is justified.
7. **No eval/exec**: No dynamic code execution anywhere.
8. **YAML parsing**: Use ruamel.yaml safe loading only. Never yaml.load() with unsafe loader.

---

## 13. Testing Strategy

- **Unit tests for rules**: Each rule gets at least 3 test cases: positive (bypass exists), negative (no bypass), edge case.
- **Mock factories**: `tests/mocks/gate_models.py` provides factory functions that create GateModels with specific configurations for testing.
- **No live API calls in tests**: All API responses mocked via respx.
- **Rule isolation**: Each rule is tested in complete isolation from other rules.
- **Integration test**: One end-to-end test that runs the full pipeline with mocked API responses.

---

## 14. Module Dependency Graph

```
enums.py ──────────────────────────────────────────────┐
    │                                                   │
    v                                                   │
gates.py ──────────────────────────────────────────┐    │
    │                                               │    │
    v                                               │    │
findings.py ───────────────────────────────────┐   │    │
    │                                           │   │    │
    v                                           │   │    │
registry.py ──────────────────────────────┐    │   │    │
    │                                      │    │   │    │
    v                                      v    v   v    v
rules/*.py                            cli.py (imports all)
                                           │
rate_limiter.py ──> github_client.py ──> collectors/*.py ──> storage.py
```

Build order (each layer depends only on layers above it):
1. enums → gates → findings → registry  (pure models, no I/O)
2. rate_limiter → github_client          (HTTP layer)
3. collectors                            (uses client, produces models)
4. storage                               (persists models)
5. rules                                 (uses registry + models)
6. cli + reporting                       (orchestrates everything)
7. tests                                 (validates everything)
