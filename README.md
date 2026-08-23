# GhostGates

> An AI-assisted research prototype for exploring how GitHub workflow, branch/ruleset, environment, permission, and OIDC controls compose into security gates and potential bypass paths.

GhostGates collects selected GitHub configuration, combines it with an attacker-prerequisite model, and emits findings about security consequences that may follow when controls interact. Its narrow differentiator is cross-control composition plus explicit attacker prerequisites and gate-bypass reasoning.

This is a learning and research artifact. It is not production-ready, a complete GitHub security assessment, or proof that a reported path is exploitable.

## Reasoning model

GhostGates follows this model:

~~~
observed GitHub configuration
        + attacker prerequisite
        + interacting controls
        -> inferred potential gate-bypass path
~~~

The distinction between those terms matters:

| Term | Meaning in GhostGates |
|---|---|
| Observed configuration | Data returned by the GitHub API or parsed from workflow YAML. |
| Attacker prerequisite | The minimum target-repository access assumed by a finding. It is an input to the inference, not an observation about a real attacker. |
| Inferred consequence | A rule-derived security outcome that still depends on stated and sometimes unobserved conditions. |
| Demonstrated by tests | Behavior exercised with synthetic models and mocked HTTP responses. |
| Validated against GitHub | Not established by the repository's current test evidence. |
| Not validated | Runtime exploitability, cloud-role assumption, action behavior, and the completeness of GitHub API coverage. |

A green test suite demonstrates that the implementation behaves as its tests specify. It does not independently validate GitHub's current behavior, a cloud trust policy, or an end-to-end exploit.

## What is collected

For active, in-scope repositories, the collector models:

- repository identity, visibility, fork state, and default branch;
- classic branch protection for the default branch;
- repository rulesets returned by GitHub;
- environments, required reviewers, wait timers, and deployment branch policies;
- workflow YAML, triggers, jobs, steps, environments, permissions, and reusable-workflow references;
- organization and repository Actions permission settings; and
- the organization OIDC subject customization template.

GhostGates does not enumerate all branches or cloud IAM configuration. It does not fetch secret values, execute workflows or actions, attempt bypasses, or prove that an inferred consequence is reachable.

## Quick start

Python 3.11 or newer is required.

~~~
python -m venv .venv
# Activate the environment using the command for your shell.
python -m pip install -e ".[dev]"
python -m pytest -q
~~~

Set a GitHub token in the environment, then limit an initial scan to a repository you control:

~~~
export GITHUB_TOKEN=...
ghostgates scan --org example-org --repos example-repo --attacker repo-write -v
~~~

Token permissions and organization policy determine which endpoints can be collected. Collection errors should be reviewed; missing data is not evidence that a control is absent.

Useful commands:

~~~
ghostgates list-rules
ghostgates scan --org example-org --format json -o report.json
ghostgates scan --org example-org --format sarif -o report.sarif
ghostgates offline --org example-org --db ghostgates.db
ghostgates diff --org example-org --db ghostgates.db
ghostgates rank --org example-org --db ghostgates.db
ghostgates recon --org example-org --db ghostgates.db
ghostgates graph --org example-org --db ghostgates.db --format mermaid
ghostgates audit --org example-org --policy ghostgates-policy.example.yml
~~~

The attacker option is a maximum prerequisite filter. For example, repo-write includes findings whose stated prerequisite is external, organization membership, or repository write access. Public and private repositories can produce different per-finding prerequisites.

Scan exit statuses are fixed: 0 for no medium-or-higher findings, 1 for
medium findings, 2 for high or critical findings, and 3 when collection was
incomplete. Completeness requires successful repository enumeration, coverage
of the requested and selected repository scope, and no collection errors.
There is no configurable fail-on threshold. Severity labels are output data,
so changing a label can change the fixed exit status. An incomplete report may
still contain useful partial results.

## Rule coverage

There are 18 registered rules. Run ghostgates list-rules for the authoritative names and metadata.

| Area | IDs | Review question |
|---|---|---|
| Branch protection | GHOST-BP-001, 002, 003 | Can observed review settings be bypassed by an admin, stale approval, or missing CODEOWNERS enforcement? |
| Actions approval setting | GHOST-BP-005 | Is the Actions pull-request approval setting enabled where protected branches require reviews? |
| Rulesets | GHOST-BP-006 | Is a ruleset only evaluating rather than enforcing? |
| Environments | GHOST-ENV-001 through 003 | Are deployment reviewers or branch restrictions absent, or are custom protection rules unmodeled? |
| Workflow trust | GHOST-WF-001 through 004 | Do trigger, checkout, permission, secret-inheritance, or workflow-run boundaries interact unsafely? |
| Workflow dependencies and publishing | GHOST-WF-005 through 008 | Do mutable action references, manual write-capable runs, or ungated write/publish jobs need review? |
| OIDC | GHOST-OIDC-001 and 002 | Do GitHub-side subject and environment controls need comparison with an external cloud trust policy? |

Rules intentionally vary in confidence. In particular:

- a mutable third-party reference requires an upstream change or compromise before it affects a run;
- workflow_dispatch with write permissions requires an authorized dispatcher and security-sensitive workflow behavior;
- a named environment is only treated as a human gate when collected configuration shows required reviewers; and
- an OIDC finding never proves cloud access because cloud trust policies are not collected.

## Outputs

The scan command supports terminal, JSON, Markdown, and SARIF output. Stored scans can also be:

- diffed to show finding drift, with missing results kept unverified after incomplete scans or rule removal;
- ordered with an explicitly uncalibrated review-priority heuristic;
- regrouped as security-review questions; or
- rendered as a prerequisite → finding → potential-consequence graph.

The graph is a presentation of individual finding relationships. It does not establish a composed exploit chain between findings. Review-priority points and tiers are not risk, likelihood, exploitability, CVSS, or impact measurements.

SARIF output maps GhostGates severity categories to SARIF levels and to
documented security-severity category representatives (9.1, 7.0, 4.0, 0.1,
and 0.0). Those values are not calculated CVSS scores. GhostGates does not
emit machine-applicable fixes.

## Policy audit

The policy command evaluates collected models against a local YAML policy:

~~~
ghostgates audit \
  --org example-org \
  --policy ghostgates-policy.example.yml \
  --repos example-repo
~~~

Policy compliance means only that the modeled fields matched the supplied policy checks. It is not certification or proof of repository security.

## Architecture

The implementation is deliberately small:

~~~
GitHub API + workflow YAML
          |
       collectors
          |
       GateModel
          |
   registry + rules
          |
      findings
          |
 reports / SQLite / policy audit
~~~

Collectors record configuration. Pydantic models provide the boundary between collection and reasoning. Rules consume a GateModel and emit findings with evidence, a prerequisite, conditions, remediation, and an inferred path. Reporting reorganizes those findings without adding observations.

See [ARCHITECTURE.md](ARCHITECTURE.md) for boundaries and known modeling limits.

## Testing and validation status

The test suite includes:

- parsers and collectors exercised against synthetic GitHub responses;
- rule tests with positive, negative, and boundary cases;
- client regressions for pagination, permission failures, rate-limit slots, and token scrubbing;
- storage and policy round trips; and
- a mocked-HTTP pipeline test covering collection, analysis, storage, and formatting.

These are not live GitHub integration tests. The repository currently contains no reproducible external-validation record that establishes rule coverage against a real GitHub organization or cloud environment. Treat live behavior and exploitability as unvalidated until a human reproduces them in a controlled environment.

## Known limitations

- Only the default branch's classic protection is collected; rulesets are modeled separately.
- Missing or unauthorized API data can make the model incomplete.
- Repository workflows are parsed statically. Expressions, generated configuration, composite actions, and called workflows are not fully evaluated.
- First-party action ownership is identified by exact owner name, not by provenance verification.
- Environment custom protection rules are recorded but their runtime decision behavior is unknown.
- OIDC rules do not inspect AWS, Azure, GCP, or other provider trust policies.
- The tool does not enumerate collaborators, teams, effective identities, secrets, artifacts, packages, deployments, or workflow-run history.
- Finding severities and review-priority weights are project heuristics, not empirically calibrated measurements.
- A SARIF rule descriptor uses metadata from the first finding with that rule ID; per-instance severity remains on each SARIF result.
- No finding and policy compliance are both weaker statements than proof of safety.

## Development transparency

Codex and Claude Code were heavily used for implementation. The project author directed the threat model, test goals, validation work, and interpretation of results. AI assistance is part of the project's development method and research subject, not a claim of independent verification.

## Data and security

GhostGates is intended for authorized review of organizations and repositories you are permitted to inspect. It stores collected models and scan results in a local SQLite database by default. Models can include raw workflow YAML and raw API fields, so protect the database and generated reports according to the sensitivity of the source repository.

Tokens are read from the command line option or GITHUB_TOKEN environment variable and sent to GitHub through the API client. Prefer environment-based token handling, least privilege, scoped repository selection, and short-lived credentials. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
