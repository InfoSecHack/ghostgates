"""
ghostgates/collectors/workflows.py

Collect and parse GitHub Actions workflow files.

The parse_workflow_yaml() function is the critical parser — it must handle
messy real-world YAML without crashing. All parse errors are captured in
parse_errors, and partial results are returned when possible.

Security: uses ruamel.yaml with typ='safe' ONLY. No unsafe loading.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ruamel.yaml import YAML, YAMLError

from ghostgates.models.gates import (
    WorkflowDefinition,
    WorkflowJob,
    WorkflowStep,
    WorkflowTrigger,
)

if TYPE_CHECKING:
    from ghostgates.client.github_client import GitHubClient

logger = logging.getLogger("ghostgates.collectors.workflows")

# Shared safe YAML parser instance
_yaml = YAML(typ="safe")
_yaml.default_flow_style = False


# ------------------------------------------------------------------
# API collection
# ------------------------------------------------------------------

async def collect_workflows(
    client: GitHubClient,
    owner: str,
    repo: str,
) -> list[WorkflowDefinition]:
    """Fetch and parse all workflow YAML files from a repository.

    Lists .github/workflows/ directory, fetches each .yml/.yaml file,
    and parses it. Returns partial results if some files fail.
    """
    try:
        files = await client.list_workflow_files(owner, repo)
    except Exception as exc:
        logger.debug("Error listing workflows for %s/%s: %s", owner, repo, exc)
        return []

    if not files:
        return []

    workflows: list[WorkflowDefinition] = []
    for file_entry in files:
        name = file_entry.get("name", "")
        path = file_entry.get("path", "")

        # Only parse YAML files
        if not name.endswith((".yml", ".yaml")):
            continue

        try:
            content = await client.get_workflow_content(owner, repo, path)
        except Exception as exc:
            logger.debug(
                "Error fetching workflow %s/%s:%s — %s", owner, repo, path, exc
            )
            workflows.append(WorkflowDefinition(
                path=path,
                name=name,
                parse_errors=[f"Failed to fetch: {exc}"],
            ))
            continue

        wf = parse_workflow_yaml(path, content)
        workflows.append(wf)

    logger.debug("Collected %d workflows for %s/%s", len(workflows), owner, repo)
    return workflows


# ------------------------------------------------------------------
# YAML parser — PURE FUNCTION, no API calls, fully testable
# ------------------------------------------------------------------

def parse_workflow_yaml(path: str, content: str) -> WorkflowDefinition:
    """Parse a workflow YAML string into a WorkflowDefinition.

    This function NEVER raises. All errors are captured in parse_errors.
    Partial results are returned when possible.

    Handles:
      - "on:" in all three forms (string, list, dict)
      - pull_request_target detection
      - workflow_dispatch with inputs
      - jobs with environment, permissions, secrets, uses (reusable)
      - steps with uses, run, with, env
      - Malformed YAML, missing keys, unexpected types
    """
    errors: list[str] = []

    # --- Parse raw YAML ---
    try:
        data = _yaml.load(content)
    except YAMLError as exc:
        return WorkflowDefinition(
            path=path,
            raw_yaml=content,
            parse_errors=[f"YAML parse error: {exc}"],
        )

    if not isinstance(data, dict):
        return WorkflowDefinition(
            path=path,
            raw_yaml=content,
            parse_errors=[f"Workflow root is {type(data).__name__}, expected dict"],
        )

    # --- Name ---
    name = ""
    raw_name = data.get("name")
    if isinstance(raw_name, str):
        name = raw_name

    # --- Triggers ---
    triggers = _parse_triggers(data, errors)

    # --- Top-level permissions ---
    permissions = _parse_permissions_block(data.get("permissions"), errors)

    # --- Jobs ---
    jobs = _parse_jobs(data.get("jobs"), errors)

    return WorkflowDefinition(
        path=path,
        name=name,
        triggers=triggers,
        permissions=permissions,
        jobs=jobs,
        raw_yaml=content,
        parse_errors=errors,
    )


# ------------------------------------------------------------------
# Trigger parsing
# ------------------------------------------------------------------

def _parse_triggers(data: dict, errors: list[str]) -> list[WorkflowTrigger]:
    """Parse the 'on:' section in all supported formats.

    Formats:
      on: push                         # string
      on: [push, pull_request]         # list
      on:                              # dict
        push:
          branches: [main]
        pull_request_target:
          types: [opened]
        workflow_dispatch:
          inputs:
            env:
              description: "Environment"
    """
    # "on" is a reserved word in YAML — ruamel.yaml loads it as True
    # if it appears as a bare key. Check both "on" and True.
    raw_on = data.get("on")
    if raw_on is None:
        raw_on = data.get(True)  # ruamel parses bare "on:" as True key
    if raw_on is None:
        errors.append("No 'on:' trigger section found")
        return []

    triggers: list[WorkflowTrigger] = []

    if isinstance(raw_on, str):
        # Simple string: "on: push"
        triggers.append(WorkflowTrigger(event=raw_on))

    elif isinstance(raw_on, list):
        # List: "on: [push, pull_request]"
        for item in raw_on:
            if isinstance(item, str):
                triggers.append(WorkflowTrigger(event=item))
            else:
                errors.append(f"Unexpected trigger list item type: {type(item).__name__}")

    elif isinstance(raw_on, dict):
        # Dict: "on: {push: {branches: [main]}, ...}"
        for event_name, event_config in raw_on.items():
            trigger = _parse_single_trigger(event_name, event_config, errors)
            triggers.append(trigger)

    else:
        errors.append(f"Unexpected 'on:' type: {type(raw_on).__name__}")

    return triggers


def _parse_single_trigger(
    event_name: str | bool,
    config: dict | None,
    errors: list[str],
) -> WorkflowTrigger:
    """Parse a single trigger event with its configuration."""
    # Handle ruamel parsing "on:" key as True
    name = str(event_name) if not isinstance(event_name, bool) else "push"

    if config is None or not isinstance(config, dict):
        return WorkflowTrigger(event=name)

    branches = _safe_str_list(config.get("branches"), errors, f"{name}.branches")
    branches_ignore = _safe_str_list(
        config.get("branches-ignore"), errors, f"{name}.branches-ignore"
    )
    paths = _safe_str_list(config.get("paths"), errors, f"{name}.paths")
    types = _safe_str_list(config.get("types"), errors, f"{name}.types")

    # workflow_dispatch inputs
    inputs: dict = {}
    raw_inputs = config.get("inputs")
    if isinstance(raw_inputs, dict):
        inputs = raw_inputs

    return WorkflowTrigger(
        event=name,
        branches=branches,
        branches_ignore=branches_ignore,
        paths=paths,
        types=types,
        inputs=inputs,
    )


# ------------------------------------------------------------------
# Job parsing
# ------------------------------------------------------------------

def _parse_jobs(raw_jobs: object, errors: list[str]) -> list[WorkflowJob]:
    """Parse the 'jobs:' section."""
    if raw_jobs is None:
        errors.append("No 'jobs:' section found")
        return []

    if not isinstance(raw_jobs, dict):
        errors.append(f"'jobs:' is {type(raw_jobs).__name__}, expected dict")
        return []

    jobs: list[WorkflowJob] = []
    for job_id, job_config in raw_jobs.items():
        try:
            job = _parse_single_job(str(job_id), job_config, errors)
            jobs.append(job)
        except Exception as exc:
            errors.append(f"Failed to parse job '{job_id}': {exc}")

    return jobs


def _parse_single_job(
    job_id: str,
    config: object,
    errors: list[str],
) -> WorkflowJob:
    """Parse a single job definition."""
    if not isinstance(config, dict):
        errors.append(f"Job '{job_id}' is {type(config).__name__}, expected dict")
        return WorkflowJob(name=job_id)

    # --- name ---
    name = config.get("name", job_id)
    if not isinstance(name, str):
        name = job_id

    # --- runs-on ---
    runs_on = config.get("runs-on", "ubuntu-latest")
    if isinstance(runs_on, list):
        runs_on = runs_on  # list of labels, e.g. ["self-hosted", "linux"]
    elif isinstance(runs_on, str):
        runs_on = runs_on
    else:
        runs_on = str(runs_on)

    # --- environment ---
    environment = config.get("environment")
    # Can be string "production" or dict {"name": "production", "url": "..."}
    if environment is not None and not isinstance(environment, (str, dict)):
        environment = str(environment)

    # --- permissions ---
    permissions = _parse_permissions_block(config.get("permissions"), errors)

    # --- secrets ---
    secrets = config.get("secrets")
    # Can be "inherit" (str) or dict of specific secrets
    if secrets is not None and not isinstance(secrets, (str, dict)):
        secrets = str(secrets)

    # --- uses (reusable workflow) ---
    uses = ""
    raw_uses = config.get("uses")
    if isinstance(raw_uses, str):
        uses = raw_uses

    # --- if condition ---
    if_condition = ""
    raw_if = config.get("if")
    if raw_if is not None:
        if_condition = str(raw_if)

    # --- steps ---
    steps = _parse_steps(config.get("steps"), job_id, errors)

    return WorkflowJob(
        name=name,
        runs_on=runs_on,
        environment=environment,
        permissions=permissions,
        steps=steps,
        secrets=secrets,
        uses=uses,
        if_condition=if_condition,
    )


# ------------------------------------------------------------------
# Step parsing
# ------------------------------------------------------------------

def _parse_steps(
    raw_steps: object,
    job_id: str,
    errors: list[str],
) -> list[WorkflowStep]:
    """Parse the 'steps:' list for a job."""
    if raw_steps is None:
        # Jobs using 'uses:' (reusable workflows) don't have steps
        return []

    if not isinstance(raw_steps, list):
        errors.append(f"Job '{job_id}' steps is {type(raw_steps).__name__}, expected list")
        return []

    steps: list[WorkflowStep] = []
    for i, raw_step in enumerate(raw_steps):
        try:
            step = _parse_single_step(raw_step, errors)
            steps.append(step)
        except Exception as exc:
            errors.append(f"Failed to parse step {i} in job '{job_id}': {exc}")

    return steps


def _parse_single_step(raw: object, errors: list[str]) -> WorkflowStep:
    """Parse a single step."""
    if not isinstance(raw, dict):
        return WorkflowStep(name=f"<non-dict step: {type(raw).__name__}>")

    name = ""
    raw_name = raw.get("name")
    if isinstance(raw_name, str):
        name = raw_name

    uses = ""
    raw_uses = raw.get("uses")
    if isinstance(raw_uses, str):
        uses = raw_uses

    run = ""
    raw_run = raw.get("run")
    if isinstance(raw_run, str):
        run = raw_run

    # "with" is a Python keyword — in the model it's "with_" with alias "with"
    with_dict: dict = {}
    raw_with = raw.get("with")
    if isinstance(raw_with, dict):
        # Convert all values to strings for consistency
        with_dict = {str(k): str(v) if v is not None else "" for k, v in raw_with.items()}

    env_dict: dict = {}
    raw_env = raw.get("env")
    if isinstance(raw_env, dict):
        env_dict = {str(k): str(v) if v is not None else "" for k, v in raw_env.items()}

    return WorkflowStep(
        name=name,
        uses=uses,
        run=run,
        with_=with_dict,
        env=env_dict,
    )


# ------------------------------------------------------------------
# Shared helpers
# ------------------------------------------------------------------

def _parse_permissions_block(
    raw: object,
    errors: list[str],
) -> dict:
    """Parse a permissions block (top-level or per-job).

    Can be:
      permissions: read-all       # string shorthand
      permissions: write-all      # string shorthand
      permissions:                # dict
        contents: read
        packages: write
    """
    if raw is None:
        return {}

    if isinstance(raw, str):
        # Shorthand: "read-all" or "write-all"
        return {"_shorthand": raw}

    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}

    errors.append(f"Unexpected permissions type: {type(raw).__name__}")
    return {}


def _safe_str_list(
    raw: object,
    errors: list[str],
    context: str,
) -> list[str]:
    """Safely extract a list of strings from a YAML value.

    Handles: None, str (single item), list[str], list[mixed].
    """
    if raw is None:
        return []

    if isinstance(raw, str):
        return [raw]

    if isinstance(raw, list):
        result: list[str] = []
        for item in raw:
            if isinstance(item, str):
                result.append(item)
            else:
                result.append(str(item))
        return result

    errors.append(f"Unexpected type for {context}: {type(raw).__name__}")
    return []
