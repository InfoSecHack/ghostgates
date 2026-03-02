# Security Policy

## Responsible Disclosure

If you discover a security vulnerability in GhostGates, please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email the maintainer directly with:
   - A description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Any suggested fix
3. Allow up to 72 hours for initial response and 30 days for a fix before public disclosure.

## Credential Handling Policy

GhostGates handles GitHub Personal Access Tokens (PATs) and must never leak them.

### Token lifecycle

| Stage | Handling |
|-------|----------|
| **Input** | Accepted via `--token` CLI flag or `GITHUB_TOKEN` environment variable. Never prompted interactively to avoid shell history leaks. |
| **In memory** | Stored only in the `GitHubClient._token` attribute and the `httpx.AsyncClient` Authorization header. |
| **Storage** | **Never stored** in the SQLite database, findings, evidence dicts, reports, or any persisted file. |
| **Logging** | **Never logged.** All error paths run through `_scrub()` which strips `ghp_*`, `ghs_*`, `gho_*`, `ghu_*`, `gha_*`, `Bearer *`, and `token=*` patterns before any log emission. |
| **Exceptions** | All `GitHubClientError` messages are scrubbed before the exception is raised. Stack traces never include the raw token because it is never interpolated into error messages. |
| **Repr** | `GitHubClient.__repr__` returns `GitHubClient(base_url=..., token=***)`. |

### What is stored

The SQLite database (`ghostgates.db`) stores:
- **GateModels**: Repository security configuration (branch protections, environments, workflows). These contain structural config, never secrets or tokens.
- **ScanResults**: Findings with evidence dicts showing config values. Evidence never contains credentials.

### File permissions

The database file is created with `0o600` (owner read/write only) on systems that support it.

## Safe Logging Guarantees

GhostGates follows these logging rules:

1. **No token in any log level** (DEBUG, INFO, WARNING, ERROR, CRITICAL).
2. **Error messages are scrubbed** via regex before propagation, catching: `ghp_*`, `ghs_*`, `gho_*`, `ghu_*`, `gha_*`, `github_pat_*`, `Bearer <token>`, `token=<value>`.
3. **No `repr()` of the client** in log output that would expose the token (custom `__repr__` masks it).
4. **Workflow YAML content** is stored in `raw_yaml` fields for evidence, but workflow YAML never contains tokens in a correctly configured repository.
5. **No `eval()` or `exec()`** anywhere in the codebase. No dynamic code execution.

## YAML Safety

All YAML parsing uses `ruamel.yaml` with `typ='safe'` exclusively. No unsafe loader is ever instantiated. The shared parser instance is created once at module level in `collectors/workflows.py`:

```python
_yaml = YAML(typ="safe")
```

## SQL Safety

All SQL queries use parameterized placeholders (`?`). No string interpolation (`f"..."`) or concatenation is used in any SQL statement. The database layer (`storage/sqlite_store.py`) is the only module that touches SQL.

## Input Validation

Organization and repository names are validated against `^[a-zA-Z0-9._-]+$` before being used in API paths. This prevents path traversal and injection through crafted org/repo names.

## Dependency Policy

GhostGates uses a minimal dependency set. Each dependency is justified:

| Package | Purpose | Justification |
|---------|---------|---------------|
| `httpx` | Async HTTP client | Industry-standard async HTTP with timeout support |
| `pydantic` | Data models | Type-safe serialization/deserialization |
| `ruamel.yaml` | YAML parsing | Supports safe loading with round-trip capability |

No unnecessary packages. No native extensions beyond what these packages require.

## How to Report Vulnerabilities

Contact the maintainer directly. Include:
- The vulnerability type (credential leak, injection, logic bypass, etc.)
- Which component is affected (client, storage, engine, CLI)
- A minimal reproduction case
- Your assessment of severity and impact

Thank you for helping keep GhostGates secure.
