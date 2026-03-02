"""GhostGates — shared enumerations.

Section 3 of ARCHITECTURE.md.  No other module may define its own enums;
all enum usage across the codebase imports from here.
"""

from enum import StrEnum


class AttackerLevel(StrEnum):
    """Attacker privilege levels.  Higher = more access."""

    EXTERNAL = "external"            # L0: no repo access, can fork public repos
    ORG_MEMBER = "org-member"       # L1: can fork, submit PRs
    REPO_WRITE = "repo-write"       # L2: can push branches, tags
    REPO_MAINTAIN = "repo-maintain" # L3: can manage some protections
    REPO_ADMIN = "repo-admin"       # L4: full repo admin
    ORG_OWNER = "org-owner"         # L5: org-level override

    @property
    def level(self) -> int:
        return list(AttackerLevel).index(self) + 1

    def __ge__(self, other: "AttackerLevel") -> bool:
        return self.level >= other.level

    def __gt__(self, other: "AttackerLevel") -> bool:
        return self.level > other.level

    def __le__(self, other: "AttackerLevel") -> bool:
        return self.level <= other.level

    def __lt__(self, other: "AttackerLevel") -> bool:
        return self.level < other.level


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class GateType(StrEnum):
    BRANCH_PROTECTION = "branch_protection"
    RULESET = "ruleset"
    ENVIRONMENT = "environment"
    WORKFLOW = "workflow"
    OIDC = "oidc"
    ACTIONS_PERMISSIONS = "actions_permissions"
