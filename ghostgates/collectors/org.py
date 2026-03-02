"""
ghostgates/collectors/org.py

Collect organization-level settings: Actions permissions, OIDC templates.
These are applied to all repos during gate model assembly.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ghostgates.client.github_client import GitHubClient

logger = logging.getLogger("ghostgates.collectors.org")


async def collect_org_metadata(client: GitHubClient, org: str) -> dict:
    """Collect org-level settings that apply to all repositories.

    Returns a dict with keys:
        - actions_permissions: dict from GitHub Actions permissions endpoint
        - oidc_template: dict | None from OIDC subject claim customization

    Both keys are always present. Individual failures are logged and
    the corresponding value is set to a safe default (empty dict / None).
    """
    result: dict = {
        "actions_permissions": {},
        "oidc_template": None,
    }

    # --- Actions permissions ---
    try:
        perms = await client.get_org_actions_permissions(org)
        result["actions_permissions"] = perms
        logger.info(
            "Collected org Actions permissions for '%s': enabled=%s",
            org,
            perms.get("enabled_repositories", "unknown"),
        )
    except Exception as exc:
        exc_str = str(exc)
        if "403" in exc_str:
            logger.info(
                "Org-level Actions permissions not accessible for '%s' "
                "(requires admin:org scope — using repo-level settings)", org,
            )
        else:
            logger.warning(
                "Failed to collect Actions permissions for org '%s': %s", org, exc
            )

    # --- OIDC subject claim customization ---
    try:
        oidc = await client.get_oidc_template(org)
        result["oidc_template"] = oidc
        if oidc:
            logger.info(
                "Collected OIDC template for '%s': include_claim_keys=%s",
                org,
                oidc.get("include_claim_keys", []),
            )
        else:
            logger.debug("No OIDC template configured for org '%s'", org)
    except Exception as exc:
        exc_str = str(exc)
        if "403" in exc_str or "404" in exc_str:
            logger.info(
                "OIDC subject customization not configured for org '%s' "
                "(using default claims)", org,
            )
        else:
            logger.warning(
                "Failed to collect OIDC template for org '%s': %s", org, exc
            )

    return result
