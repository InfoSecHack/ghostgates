"""GhostGates collectors package.

Individual collectors:
  - org.py: org-level metadata (Actions perms, OIDC)
  - repos.py: repo listing, branch protections, collaborators, rulesets
  - environments.py: environment protection rules
  - workflows.py: workflow YAML parsing
  - assembly.py: orchestrates all collectors into GateModels
"""

from ghostgates.collectors.assembly import collect_org_gate_models

__all__ = ["collect_org_gate_models"]
