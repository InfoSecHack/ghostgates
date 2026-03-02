"""GhostGates rule engine package.

Importing this package registers all rules with the global registry.
"""

from ghostgates.engine.registry import registry, RuleRegistry, RuleMetadata

# Import rule modules to trigger @registry.rule() registration
import ghostgates.engine.rules.branch_protection  # noqa: F401
import ghostgates.engine.rules.environment  # noqa: F401
import ghostgates.engine.rules.workflow  # noqa: F401
import ghostgates.engine.rules.oidc  # noqa: F401

__all__ = ["registry", "RuleRegistry", "RuleMetadata"]
