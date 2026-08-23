"""
ghostgates/collectors/org.py

Collect organization-level settings: Actions permissions, OIDC templates.
These are applied to all repos during gate model assembly.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ghostgates.models.gates import CollectionError

if TYPE_CHECKING:
    from ghostgates.client.github_client import GitHubClient

logger = logging.getLogger("ghostgates.collectors.org")


async def collect_org_metadata(client: GitHubClient, org: str) -> dict:
    """Collect org settings and record evidence that could not be observed."""
    result: dict = {
        "actions_permissions": {},
        "oidc_template": None,
        "collection_errors": [],
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
        result["collection_errors"].append(CollectionError(
            collector="org_actions_permissions",
            message=str(exc),
        ))
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
        result["collection_errors"].append(CollectionError(
            collector="org_oidc_template",
            message=str(exc),
        ))
        logger.warning(
            "Failed to collect OIDC template for org '%s': %s", org, exc
        )

    return result
