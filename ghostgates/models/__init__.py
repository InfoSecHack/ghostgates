"""GhostGates models package.

Re-exports every public type so consumers can do:

    from ghostgates.models import GateModel, BypassFinding, Severity, ...

instead of reaching into sub-modules directly.
"""

from ghostgates.models.enums import (
    AttackerLevel,
    Confidence,
    GateType,
    Severity,
)
from ghostgates.models.findings import (
    BypassFinding,
    ScanResult,
)
from ghostgates.models.gates import (
    BranchProtection,
    Collaborator,
    CustomProtectionRule,
    EnvironmentConfig,
    EnvironmentProtection,
    EnvironmentReviewer,
    GateModel,
    OIDCConfig,
    Ruleset,
    WorkflowDefinition,
    WorkflowJob,
    WorkflowPermissions,
    WorkflowStep,
    WorkflowTrigger,
)

__all__ = [
    # enums
    "AttackerLevel",
    "Confidence",
    "GateType",
    "Severity",
    # gate sub-models
    "BranchProtection",
    "Collaborator",
    "CustomProtectionRule",
    "EnvironmentConfig",
    "EnvironmentProtection",
    "EnvironmentReviewer",
    "OIDCConfig",
    "Ruleset",
    "WorkflowDefinition",
    "WorkflowJob",
    "WorkflowPermissions",
    "WorkflowStep",
    "WorkflowTrigger",
    # top-level gate model
    "GateModel",
    # finding models
    "BypassFinding",
    "ScanResult",
]
