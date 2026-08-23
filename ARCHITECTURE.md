# GhostGates architecture

GhostGates is a small research prototype that separates GitHub configuration collection from rule-based security inference.

Its core relationship is:

~~~
observations + attacker prerequisite + control interaction
    -> inferred potential gate-bypass path
~~~

This document describes the implementation as it exists. It is not a future design contract.

## Goals and boundaries

The architecture supports:

- collection of selected GitHub repository and organization settings;
- a typed boundary between collected facts and security reasoning;
- rules that state evidence, prerequisites, conditions, and potential consequences;
- deterministic offline analysis of stored models; and
- several views over the same findings.

It does not attempt to:

- execute or modify workflows;
- test a bypass against GitHub;
- evaluate cloud-provider trust policies;
- resolve every GitHub expression, action, or reusable workflow;
- enumerate effective user/team access; or
- establish a complete attack graph.

## Data flow

~~~
GitHub REST API and workflow YAML
                |
             client
                |
            collectors
                |
            GateModel
                |
        registry and rules
                |
         BypassFinding list
                |
 CLI reports / policy audit / SQLite
~~~

### 1. Client

ghostgates/client/github_client.py wraps httpx with:

- input validation for organization and repository names;
- bounded concurrent requests;
- primary and secondary rate-limit handling;
- retries for transient HTTP and server failures;
- pagination; and
- best-effort credential scrubbing in errors.

Permission-denied 403 responses are distinguished from rate-limit responses so they fail promptly and release their concurrency slot.

### 2. Collection

ghostgates/collectors/assembly.py is the orchestration boundary.

It first collects organization-level Actions permissions and the organization OIDC subject template. It then lists active repositories, applies the requested repository/fork filters, and runs independent per-repository collectors concurrently.

Per repository, GhostGates collects:

- default-branch classic protection;
- repository rulesets;
- environment configuration;
- workflow files and parsed YAML; and
- repository Actions permission settings.

Repository Actions settings override organization defaults when the field is present. Collection returns GateModels plus non-fatal repository errors. A repository whose required per-repository collection raises an exception is omitted and reported as an error rather than treated as having no controls.

The classic branch-protection collector checks only the default branch identified by the repository API. GhostGates does not enumerate branches, so it cannot claim that an unmodeled branch exists or is unprotected.

### 3. Models

ghostgates/models/gates.py contains the observation model:

- GateModel is the repository-level aggregate;
- BranchProtection and Ruleset model GitHub review/enforcement controls;
- EnvironmentConfig models reviewers, timers, custom rules, and branch policy;
- WorkflowDefinition, WorkflowJob, WorkflowStep, and WorkflowTrigger model parsed YAML;
- WorkflowPermissions models Actions settings; and
- OIDCConfig models the organization subject template.

Raw API fields and raw workflow YAML are retained where useful for evidence and debugging. That improves inspectability but makes the local database and reports potentially sensitive.

ghostgates/models/findings.py defines rule metadata, findings, and scan results. A BypassFinding contains:

- the rule identity and affected repository;
- severity and confidence heuristics;
- a minimum attacker prerequisite;
- a summary and inferred path;
- supporting evidence;
- additional gating conditions; and
- remediation and references.

These fields are assertions made by the rule implementation. Pydantic validates their shape, not their external correctness.

### 4. Rule engine

ghostgates/engine/registry.py registers functions with static metadata and evaluates them against a GateModel.

The registry:

1. filters rules whose static minimum prerequisite is above the requested maximum;
2. invokes enabled rules and captures rule exceptions so one rule does not stop a scan;
3. filters returned findings again using each finding's actual prerequisite; and
4. supports rule-ID and gate-type selection.

The second prerequisite filter matters when a rule derives a finding-specific prerequisite, such as external access for a public repository versus organization membership for a private repository.

Rules live in four modules:

- branch_protection.py;
- environment.py;
- workflow.py; and
- oidc.py.

Rules should distinguish observed fields from inferred consequences and unobserved prerequisites. A named environment is not a reviewer gate unless collected environment configuration shows reviewers. A mutable action reference is not itself evidence of upstream compromise. GitHub OIDC configuration cannot prove cloud access without the provider trust policy.

### 5. Reporting

ghostgates/reporting contains:

- terminal, JSON, Markdown, and SARIF scan formatting;
- scan-to-scan diffing;
- heuristic repository review ordering;
- review-question regrouping; and
- Mermaid/terminal finding relationship graphs.

Reports consume findings. They do not perform new collection or turn independent findings into a validated exploit chain.

The ranking weights and tiers are intentionally uncalibrated review aids.
SARIF maps project severity labels to SARIF levels and documented numeric
category representatives; those values are not calculated CVSS scores.
Machine-applicable fixes are not emitted.

### 6. Policy audit

ghostgates/policy loads a local YAML policy and evaluates configured checks against GateModels. This is a separate question from inference rules:

- rule evaluation asks what potential consequence follows from observed controls and prerequisites;
- policy evaluation asks whether modeled fields match the supplied expectation.

Policy compliance covers only implemented checks and collected fields. It is not certification.

### 7. Storage

ghostgates/storage/sqlite_store.py stores serialized GateModels and ScanResults in SQLite. Stored models allow offline reevaluation and stored results support show, diff, rank, recon, and graph commands.

The database can contain raw workflow YAML and raw API fields. It should be protected as repository security data and deleted according to the user's retention needs.

## Error and absence semantics

Three states must not be collapsed:

| State | Interpretation |
|---|---|
| API returned an observed setting | The model can use the value as evidence. |
| API explicitly returned a supported not-configured response | The collector may model the documented absence. |
| Request failed or permission was missing | The model is incomplete; do not infer absence. |

Some convenience collectors continue after endpoint-specific failures and return partial data. Collection logs and returned errors therefore remain part of the review context.

## Test boundary

Tests use synthetic GateModels, mocked GitHub HTTP responses, temporary SQLite databases, and formatter assertions. The pipeline test is end-to-end within that mocked boundary. No current test contacts GitHub or a cloud provider.

The suite demonstrates implementation behavior and regression coverage. It does not establish API completeness, real-world exploitability, or live-cloud correctness.

## Source layout

~~~
ghostgates/
  client/       GitHub HTTP and rate limiting
  collectors/   API/YAML to GateModel
  models/       typed observations and findings
  engine/       registry and inference rules
  policy/       local policy schema/evaluator
  reporting/    output-only views
  storage/      SQLite persistence
tests/          mocked and synthetic regression tests
~~~

Run ghostgates list-rules for the authoritative rule catalog. Run python -m pytest -q for the repository's implementation checks.
