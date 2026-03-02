"""GhostGates — configuration constants.

This module is the single source of truth for all compile-time constants.
No I/O, no imports from within the package.
"""

import re

# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------

API_BASE_URL: str = "https://api.github.com"
API_VERSION: str = "2022-11-28"
USER_AGENT: str = "ghostgates/0.1.0"

# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------

MAX_CONCURRENT_DEFAULT: int = 10

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

ORG_NAME_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9._-]+$")

# ---------------------------------------------------------------------------
# Branch targeting
# ---------------------------------------------------------------------------

DEFAULT_BRANCHES_TO_CHECK: list[str] = [
    "main",
    "master",
    "develop",
    "staging",
    "production",
]

DEPLOY_BRANCH_PATTERNS: list[str] = [
    "release/*",
    "deploy/*",
    "staging",
    "production",
]
