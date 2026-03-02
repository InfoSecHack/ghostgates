"""GitHub settings URL helpers for remediation links."""


def branches_url(full_name: str) -> str:
    return f"https://github.com/{full_name}/settings/branches"


def environment_url(full_name: str, env_name: str | None = None) -> str:
    base = f"https://github.com/{full_name}/settings/environments"
    # GitHub doesn't have direct deep links to specific environments
    return base


def actions_url(full_name: str) -> str:
    return f"https://github.com/{full_name}/settings/actions"


def rulesets_url(full_name: str) -> str:
    return f"https://github.com/{full_name}/settings/rules"


def workflow_file_url(full_name: str, workflow_path: str, branch: str = "main") -> str:
    """Link to workflow file in repo (for editing permissions block)."""
    return f"https://github.com/{full_name}/blob/{branch}/{workflow_path}"


def oidc_org_url(org: str) -> str:
    return f"https://github.com/organizations/{org}/settings/actions"
