# Security policy

GhostGates is a research prototype that processes sensitive repository security configuration and an authenticated GitHub token. It is not production-ready and does not make absolute credential-safety or vulnerability-detection guarantees.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository when it is available. If it is not available, contact the repository owner through a non-public channel listed on their GitHub profile.

Include:

- the affected component and version or commit;
- a minimal reproduction;
- the expected and actual behavior;
- potential impact; and
- whether logs, reports, or databases contain sensitive material.

Do not include a real token, secret, private workflow, or production database in the report. No response or remediation deadline is promised by this prototype.

## Credential handling

The CLI accepts a token through GITHUB_TOKEN or the token option. Environment-based input is preferred because command-line arguments can be exposed through shell history or process listings.

The API client:

- places the token in the HTTP Authorization header;
- masks it in the client representation;
- does not intentionally add it to GateModels or ScanResults; and
- applies best-effort regex scrubbing to common token forms in errors.

Scrubbing is defense in depth, not a proof that every possible credential format or third-party exception is safe. Avoid debug logs when handling sensitive repositories, inspect generated artifacts before sharing them, and use a short-lived least-privilege token restricted to the repositories in scope.

## Stored data

The default SQLite database stores serialized GateModels and ScanResults. These can contain:

- repository and organization security settings;
- raw API response fields;
- raw workflow YAML;
- finding evidence; and
- URLs and repository names.

Workflow YAML can itself contain literal credentials or sensitive values in an incorrectly configured repository. GhostGates does not need secret values, but retaining raw YAML means the database cannot be described as secret-free.

On POSIX systems, the storage layer attempts to create a new database with owner-only permissions. Filesystem permissions, backups, copies, output redirection, uploaded artifacts, and pre-existing database permissions remain the user's responsibility.

Protect ghostgates.db and generated JSON, Markdown, SARIF, Mermaid, and terminal logs as repository security data. Remove them when they are no longer required.

## Network and API scope

GhostGates sends authenticated requests to the configured GitHub API base URL. Use the default trusted GitHub endpoint unless you intentionally operate a compatible server.

The tool is intended only for organizations and repositories you are authorized to inspect. Start with:

- a controlled organization or test repository;
- a repository filter;
- read-only or otherwise minimal token permissions; and
- `--no-store` when persistence is unnecessary.

Missing permissions can produce partial collection. Review collection errors instead of interpreting missing modeled data as a secure or absent configuration.

## Parsing and local execution

Workflow YAML is parsed with ruamel.yaml's safe loader. The scanner does not execute parsed workflow commands or actions.

The SQLite layer uses parameterized statements for modeled values. Organization and repository names are validated before use in API paths. These controls reduce risk but do not replace normal dependency review, input scoping, and artifact handling.

## CI workflow

The included example GitHub Actions workflow:

- installs the checked-out GhostGates revision;
- scopes the scan to the current repository;
- reads its token from a secret;
- uploads SARIF to code scanning only when the report marks collection complete; and
- retains complete or incomplete reports as workflow artifacts for review.

Before enabling it, review token permissions, fork behavior, artifact retention, and whether repository security findings should be visible through code scanning or artifacts.

## Dependency handling

Runtime dependencies are declared in pyproject.toml:

- httpx for HTTP;
- pydantic for models and serialization; and
- ruamel.yaml for YAML parsing.

Development dependencies add pytest, pytest-asyncio, and respx. Version lower bounds do not guarantee that all future releases are compatible. Use an isolated environment, review resolved packages, and apply your own locking and update policy when reproducibility matters.

## Security claims and findings

A GhostGates finding is an inference from selected GitHub-side configuration. It is not proof of:

- a working exploit;
- attacker control;
- secret disclosure;
- package publication;
- cloud-role assumption; or
- complete repository coverage.

Validate high-impact findings manually in an authorized, controlled environment. In particular, compare OIDC findings with the external cloud trust policy and confirm that environment reviewers and workflow execution paths behave as modeled.

## Before sharing a report

1. Confirm the scan scope and collection errors.
2. Remove tokens or secrets if any source workflow contained literal values.
3. Consider redacting repository names, URLs, branch names, and workflow paths.
4. Treat inferred consequences as hypotheses until manually validated.
5. Do not publish details that would expose an unremediated vulnerability.
