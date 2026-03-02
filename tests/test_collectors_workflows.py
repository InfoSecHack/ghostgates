"""
Tests for ghostgates.collectors.workflows

The parse_workflow_yaml function is the most complex parser in GhostGates.
These tests cover:
  - All three trigger formats (string, list, dict)
  - pull_request_target detection (CRITICAL for WF-001 rule)
  - workflow_dispatch with inputs
  - Job parsing: environment, permissions, secrets, uses (reusable)
  - Step parsing: uses, run, with, env
  - Malformed YAML handling (never crashes)
  - Missing/unexpected types in every field
  - Permissions shorthand vs dict
  - Self-hosted runner detection
"""

from __future__ import annotations

import pytest
import httpx
import respx

from ghostgates.client.github_client import GitHubClient
from ghostgates.collectors.workflows import (
    collect_workflows,
    parse_workflow_yaml,
)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

BASE_URL = "https://api.github.com"


def _rl_headers() -> dict:
    return {"x-ratelimit-remaining": "4999", "x-ratelimit-reset": "9999999999"}


@pytest.fixture
def mock_router():
    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        yield router


@pytest.fixture
async def client(mock_router) -> GitHubClient:
    c = GitHubClient(token="ghp_test123", base_url=BASE_URL, max_concurrent=5)
    yield c
    await c.close()


# ==================================================================
# Tests: Trigger parsing — all three formats
# ==================================================================

class TestTriggerParsing:
    """Test all supported 'on:' formats."""

    def test_trigger_string(self):
        """on: push → single trigger."""
        wf = parse_workflow_yaml("ci.yml", "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
        assert len(wf.triggers) == 1
        assert wf.triggers[0].event == "push"
        assert wf.parse_errors == []

    def test_trigger_list(self):
        """on: [push, pull_request] → two triggers."""
        wf = parse_workflow_yaml("ci.yml", "name: CI\non: [push, pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
        assert len(wf.triggers) == 2
        events = {t.event for t in wf.triggers}
        assert events == {"push", "pull_request"}

    def test_trigger_dict_with_branches(self):
        """on: {push: {branches: [main]}} → trigger with branch filter."""
        yaml = """
name: CI
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        assert len(wf.triggers) == 2
        push = next(t for t in wf.triggers if t.event == "push")
        assert push.branches == ["main", "develop"]
        pr = next(t for t in wf.triggers if t.event == "pull_request")
        assert pr.branches == ["main"]

    def test_trigger_dict_null_config(self):
        """on: {push: null} → trigger with no config (valid YAML)."""
        yaml = "name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
        wf = parse_workflow_yaml("ci.yml", yaml)
        assert len(wf.triggers) == 1
        assert wf.triggers[0].event == "push"

    def test_trigger_branches_ignore(self):
        yaml = """
name: CI
on:
  push:
    branches-ignore: [gh-pages, docs]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        push = wf.triggers[0]
        assert push.branches_ignore == ["gh-pages", "docs"]

    def test_trigger_paths(self):
        yaml = """
name: CI
on:
  push:
    paths: [src/**, tests/**]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        assert wf.triggers[0].paths == ["src/**", "tests/**"]

    def test_trigger_types(self):
        yaml = """
name: PR
on:
  pull_request:
    types: [opened, synchronize, reopened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        assert wf.triggers[0].types == ["opened", "synchronize", "reopened"]

    def test_no_trigger_section(self):
        """Missing 'on:' section records an error but doesn't crash."""
        wf = parse_workflow_yaml("bad.yml", "name: Bad\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
        assert len(wf.parse_errors) > 0
        assert any("trigger" in e.lower() or "'on:'" in e for e in wf.parse_errors)


# ==================================================================
# Tests: CRITICAL — pull_request_target detection
# ==================================================================

class TestPullRequestTarget:
    """pull_request_target is the most dangerous trigger for bypass analysis.
    These tests ensure we detect it in all forms."""

    def test_pull_request_target_dict(self):
        yaml = """
name: Label
on:
  pull_request_target:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        wf = parse_workflow_yaml("label.yml", yaml)
        events = {t.event for t in wf.triggers}
        assert "pull_request_target" in events

    def test_pull_request_target_list(self):
        wf = parse_workflow_yaml("x.yml", "on: [pull_request_target]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        events = {t.event for t in wf.triggers}
        assert "pull_request_target" in events

    def test_pull_request_target_with_checkout(self):
        """The critical pattern: pull_request_target + checkout of PR head."""
        yaml = """
name: Dangerous
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
"""
        wf = parse_workflow_yaml("dangerous.yml", yaml)
        events = {t.event for t in wf.triggers}
        assert "pull_request_target" in events

        # Verify the checkout step captured the ref
        build_job = wf.jobs[0]
        checkout_step = build_job.steps[0]
        assert "actions/checkout" in checkout_step.uses
        assert "ref" in checkout_step.with_
        assert "pull_request.head" in checkout_step.with_["ref"]


# ==================================================================
# Tests: workflow_dispatch
# ==================================================================

class TestWorkflowDispatch:
    def test_workflow_dispatch_with_inputs(self):
        yaml = """
name: Deploy
on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Target environment'
        required: true
        type: choice
        options: [staging, production]
      dry_run:
        description: 'Dry run'
        type: boolean
        default: false
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploying
"""
        wf = parse_workflow_yaml("deploy.yml", yaml)
        dispatch = next(t for t in wf.triggers if t.event == "workflow_dispatch")
        assert "environment" in dispatch.inputs
        assert "dry_run" in dispatch.inputs

    def test_workflow_dispatch_no_inputs(self):
        yaml = "name: Manual\non:\n  workflow_dispatch:\njobs:\n  run:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
        wf = parse_workflow_yaml("manual.yml", yaml)
        dispatch = next(t for t in wf.triggers if t.event == "workflow_dispatch")
        assert dispatch.inputs == {}


# ==================================================================
# Tests: Job parsing
# ==================================================================

class TestJobParsing:
    def test_job_with_environment(self):
        yaml = """
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: echo deploy
"""
        wf = parse_workflow_yaml("deploy.yml", yaml)
        assert wf.jobs[0].environment == "production"

    def test_job_with_environment_dict(self):
        yaml = """
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://example.com
    steps:
      - run: echo deploy
"""
        wf = parse_workflow_yaml("deploy.yml", yaml)
        env = wf.jobs[0].environment
        assert isinstance(env, dict)
        assert env["name"] == "production"

    def test_job_permissions_dict(self):
        yaml = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - run: echo build
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        perms = wf.jobs[0].permissions
        assert perms["contents"] == "read"
        assert perms["packages"] == "write"

    def test_job_permissions_shorthand(self):
        yaml = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo build
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        assert wf.jobs[0].permissions == {"_shorthand": "write-all"}

    def test_job_secrets_inherit(self):
        yaml = """
name: Caller
on: push
jobs:
  reuse:
    uses: org/repo/.github/workflows/reusable.yml@main
    secrets: inherit
"""
        wf = parse_workflow_yaml("caller.yml", yaml)
        assert wf.jobs[0].secrets == "inherit"
        assert wf.jobs[0].uses == "org/repo/.github/workflows/reusable.yml@main"

    def test_reusable_workflow_no_steps(self):
        """Jobs with 'uses:' don't have steps — that's valid."""
        yaml = """
name: Caller
on: push
jobs:
  reuse:
    uses: org/repo/.github/workflows/build.yml@v1
"""
        wf = parse_workflow_yaml("caller.yml", yaml)
        assert wf.jobs[0].uses == "org/repo/.github/workflows/build.yml@v1"
        assert wf.jobs[0].steps == []

    def test_job_self_hosted_runner(self):
        yaml = """
name: CI
on: push
jobs:
  build:
    runs-on: [self-hosted, linux, x64]
    steps:
      - run: echo build
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        runs_on = wf.jobs[0].runs_on
        assert isinstance(runs_on, list)
        assert "self-hosted" in runs_on

    def test_job_if_condition(self):
        yaml = """
name: CI
on: push
jobs:
  deploy:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        assert "refs/heads/main" in wf.jobs[0].if_condition

    def test_multiple_jobs(self):
        yaml = """
name: CI
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: npm run lint
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        assert len(wf.jobs) == 3
        names = {j.name for j in wf.jobs}
        assert "lint" in names
        assert "test" in names
        assert "build" in names


# ==================================================================
# Tests: Step parsing
# ==================================================================

class TestStepParsing:
    def test_step_uses_action(self):
        yaml = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        steps = wf.jobs[0].steps
        assert len(steps) == 2
        assert steps[0].uses == "actions/checkout@v4"
        assert steps[1].uses == "actions/setup-node@v4"
        assert steps[1].with_["node-version"] == "20"

    def test_step_run_command(self):
        yaml = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build
        run: npm run build
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        step = wf.jobs[0].steps[0]
        assert step.name == "Build"
        assert step.run == "npm run build"

    def test_step_env_vars(self):
        yaml = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh
        env:
          AWS_REGION: us-east-1
          NODE_ENV: production
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        step = wf.jobs[0].steps[0]
        assert step.env["AWS_REGION"] == "us-east-1"
        assert step.env["NODE_ENV"] == "production"


# ==================================================================
# Tests: Top-level permissions
# ==================================================================

class TestTopLevelPermissions:
    def test_top_level_permissions_dict(self):
        yaml = """
name: CI
on: push
permissions:
  contents: read
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        assert wf.permissions["contents"] == "read"
        assert wf.permissions["id-token"] == "write"

    def test_top_level_permissions_read_all(self):
        yaml = """
name: CI
on: push
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        wf = parse_workflow_yaml("ci.yml", yaml)
        assert wf.permissions == {"_shorthand": "read-all"}


# ==================================================================
# Tests: Malformed YAML — NEVER crashes
# ==================================================================

class TestMalformedYaml:
    def test_invalid_yaml_syntax(self):
        """Completely broken YAML returns error, no crash."""
        wf = parse_workflow_yaml("bad.yml", "{{{{not yaml at all::::")
        assert len(wf.parse_errors) > 0
        assert wf.path == "bad.yml"

    def test_yaml_is_string(self):
        """YAML that parses to a plain string."""
        wf = parse_workflow_yaml("str.yml", "just a string")
        assert len(wf.parse_errors) > 0

    def test_yaml_is_list(self):
        """YAML that parses to a list."""
        wf = parse_workflow_yaml("list.yml", "- item1\n- item2\n")
        assert len(wf.parse_errors) > 0

    def test_yaml_is_number(self):
        """YAML that parses to a number."""
        wf = parse_workflow_yaml("num.yml", "42")
        assert len(wf.parse_errors) > 0

    def test_empty_yaml(self):
        """Empty string."""
        wf = parse_workflow_yaml("empty.yml", "")
        assert len(wf.parse_errors) > 0

    def test_yaml_null(self):
        """YAML that parses to None."""
        wf = parse_workflow_yaml("null.yml", "null")
        assert len(wf.parse_errors) > 0

    def test_jobs_is_list_not_dict(self):
        """jobs: as a list instead of dict."""
        yaml = "name: Bad\non: push\njobs:\n  - name: x\n"
        wf = parse_workflow_yaml("bad.yml", yaml)
        assert len(wf.parse_errors) > 0
        assert wf.triggers[0].event == "push"  # triggers still parsed

    def test_steps_is_dict_not_list(self):
        """steps: as a dict instead of list."""
        yaml = """
name: Bad
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      step1:
        run: echo hi
"""
        wf = parse_workflow_yaml("bad.yml", yaml)
        assert len(wf.parse_errors) > 0

    def test_step_is_string(self):
        """A step that's a string instead of dict."""
        yaml = """
name: Bad
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - just a string step
"""
        wf = parse_workflow_yaml("bad.yml", yaml)
        # Should not crash — step gets a placeholder name
        assert len(wf.jobs) == 1
        assert len(wf.jobs[0].steps) == 1

    def test_raw_yaml_always_preserved(self):
        """Raw YAML content is always available for evidence."""
        content = "name: Test\non: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
        wf = parse_workflow_yaml("test.yml", content)
        assert wf.raw_yaml == content

    def test_partial_parse_on_bad_job(self):
        """If one job is bad, other jobs still parse."""
        yaml = """
name: Mixed
on: push
jobs:
  good:
    runs-on: ubuntu-latest
    steps:
      - run: echo good
  bad: not_a_dict
"""
        wf = parse_workflow_yaml("mixed.yml", yaml)
        # Should have parse errors for the bad job
        assert len(wf.parse_errors) > 0
        # But should still have parsed jobs
        assert len(wf.jobs) >= 1


# ==================================================================
# Tests: collect_workflows (API integration)
# ==================================================================

class TestCollectWorkflows:
    @pytest.mark.asyncio
    async def test_collects_yaml_files(self, client, mock_router):
        """Fetches and parses workflow YAML files."""
        mock_router.get("/repos/org/repo/contents/.github/workflows").mock(
            return_value=httpx.Response(200, json=[
                {"name": "ci.yml", "path": ".github/workflows/ci.yml"},
                {"name": "deploy.yaml", "path": ".github/workflows/deploy.yaml"},
                {"name": "README.md", "path": ".github/workflows/README.md"},
            ], headers=_rl_headers())
        )
        mock_router.get("/repos/org/repo/contents/.github/workflows/ci.yml").mock(
            return_value=httpx.Response(200, text="name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo build\n", headers=_rl_headers())
        )
        mock_router.get("/repos/org/repo/contents/.github/workflows/deploy.yaml").mock(
            return_value=httpx.Response(200, text="name: Deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo deploy\n", headers=_rl_headers())
        )

        workflows = await collect_workflows(client, "org", "repo")
        assert len(workflows) == 2  # README.md skipped
        names = {w.name for w in workflows}
        assert "CI" in names
        assert "Deploy" in names

    @pytest.mark.asyncio
    async def test_skips_non_yaml_files(self, client, mock_router):
        """Non-YAML files are ignored."""
        mock_router.get("/repos/org/repo/contents/.github/workflows").mock(
            return_value=httpx.Response(200, json=[
                {"name": "README.md", "path": ".github/workflows/README.md"},
                {"name": "script.sh", "path": ".github/workflows/script.sh"},
            ], headers=_rl_headers())
        )

        workflows = await collect_workflows(client, "org", "repo")
        assert workflows == []

    @pytest.mark.asyncio
    async def test_no_workflows_directory(self, client, mock_router):
        """Returns empty when no .github/workflows/ exists."""
        mock_router.get("/repos/org/repo/contents/.github/workflows").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"}, headers=_rl_headers())
        )

        workflows = await collect_workflows(client, "org", "repo")
        assert workflows == []

    @pytest.mark.asyncio
    async def test_failed_fetch_records_error(self, client, mock_router):
        """If a workflow file fails to fetch, it records an error."""
        mock_router.get("/repos/org/repo/contents/.github/workflows").mock(
            return_value=httpx.Response(200, json=[
                {"name": "ci.yml", "path": ".github/workflows/ci.yml"},
            ], headers=_rl_headers())
        )
        mock_router.get("/repos/org/repo/contents/.github/workflows/ci.yml").mock(
            return_value=httpx.Response(500, headers=_rl_headers())
        )

        workflows = await collect_workflows(client, "org", "repo")
        assert len(workflows) == 1
        assert len(workflows[0].parse_errors) > 0


# ==================================================================
# Tests: Complex real-world workflow
# ==================================================================

class TestRealWorldWorkflows:
    def test_full_cicd_pipeline(self):
        """Realistic CI/CD workflow with multiple jobs, environments, OIDC."""
        yaml = """
name: CI/CD Pipeline
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  id-token: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test

  deploy-staging:
    needs: test
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: staging
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/deploy
          aws-region: us-east-1
      - run: npm run deploy:staging

  deploy-prod:
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - run: npm run deploy:production
"""
        wf = parse_workflow_yaml("cicd.yml", yaml)
        assert wf.parse_errors == []
        assert len(wf.triggers) == 3
        assert len(wf.jobs) == 3

        # Top-level permissions
        assert wf.permissions["id-token"] == "write"

        # Test job
        test_job = next(j for j in wf.jobs if j.name == "test")
        assert len(test_job.steps) == 4

        # Staging deploy
        staging = next(j for j in wf.jobs if j.name == "deploy-staging")
        assert staging.environment == "staging"
        assert staging.permissions["id-token"] == "write"
        assert "refs/heads/main" in staging.if_condition

        # Production deploy
        prod = next(j for j in wf.jobs if j.name == "deploy-prod")
        assert prod.environment == "production"

    def test_reusable_workflow_caller(self):
        """Workflow that calls reusable workflows with secrets: inherit."""
        yaml = """
name: Orchestrator
on:
  push:
    branches: [main]
jobs:
  lint:
    uses: org/shared-workflows/.github/workflows/lint.yml@v2
  test:
    uses: org/shared-workflows/.github/workflows/test.yml@v2
    secrets: inherit
  deploy:
    needs: [lint, test]
    uses: org/shared-workflows/.github/workflows/deploy.yml@v2
    with:
      environment: production
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
"""
        wf = parse_workflow_yaml("orchestrator.yml", yaml)
        assert wf.parse_errors == []
        assert len(wf.jobs) == 3

        lint = next(j for j in wf.jobs if j.name == "lint")
        assert "lint.yml" in lint.uses
        assert lint.steps == []  # reusable workflows have no steps

        test = next(j for j in wf.jobs if j.name == "test")
        assert test.secrets == "inherit"

        deploy = next(j for j in wf.jobs if j.name == "deploy")
        assert isinstance(deploy.secrets, dict)
