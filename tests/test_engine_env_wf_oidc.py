"""
Tests for GHOST-ENV, GHOST-WF, and GHOST-OIDC rules.
"""

from __future__ import annotations

import pytest

from ghostgates.engine import registry
from ghostgates.models.enums import AttackerLevel, GateType, Severity
from ghostgates.models.gates import WorkflowPermissions, OIDCConfig

from tests.mocks.gate_models import (
    make_bp,
    make_environment,
    make_gate,
    make_job,
    make_reviewer,
    make_step,
    make_trigger,
    make_workflow,
)


# ==================================================================
# GHOST-ENV-001: Environment with no required reviewers
# ==================================================================

class TestENV001:
    def test_fires_production_no_reviewers(self):
        gate = make_gate(environments=[
            make_environment("production"),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-001"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["environment"] == "production"
        assert findings[0].severity == Severity.HIGH

    def test_silent_when_reviewers_present(self):
        gate = make_gate(environments=[
            make_environment("production", reviewers=[make_reviewer("alice")]),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-001"],
        )
        assert len(findings) == 0

    def test_silent_for_dev_environment(self):
        """Non-security-relevant env names don't fire."""
        gate = make_gate(environments=[
            make_environment("dev"),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-001"],
        )
        assert len(findings) == 0

    def test_fires_for_staging(self):
        gate = make_gate(environments=[
            make_environment("staging"),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-001"],
        )
        assert len(findings) == 1

    def test_fires_for_partial_match(self):
        """aws-production should still match."""
        gate = make_gate(environments=[
            make_environment("aws-production"),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-001"],
        )
        assert len(findings) == 1

    def test_multiple_envs(self):
        gate = make_gate(environments=[
            make_environment("production"),
            make_environment("staging"),
            make_environment("dev"),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-001"],
        )
        assert len(findings) == 2  # production + staging, not dev


# ==================================================================
# GHOST-ENV-002: Environment allows deployment from any branch
# ==================================================================

class TestENV002:
    def test_fires_when_all_branches_with_reviewers(self):
        gate = make_gate(environments=[
            make_environment(
                "production",
                reviewers=[make_reviewer("alice")],
                deployment_policy_type="all",
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-002"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["deployment_branch_policy"] == "all"

    def test_silent_when_protected_branches_only(self):
        gate = make_gate(environments=[
            make_environment(
                "production",
                reviewers=[make_reviewer("alice")],
                deployment_policy_type="protected",
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-002"],
        )
        assert len(findings) == 0

    def test_silent_when_no_reviewers(self):
        """No reviewers → ENV-001 handles it, not ENV-002."""
        gate = make_gate(environments=[
            make_environment("production", deployment_policy_type="all"),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-002"],
        )
        assert len(findings) == 0


# ==================================================================
# GHOST-ENV-003: Wait timer as only protection
# ==================================================================

class TestENV003:
    def test_fires_timer_without_reviewers(self):
        gate = make_gate(environments=[
            make_environment("production", wait_timer=30),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-003"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["wait_timer"] == 30

    def test_silent_when_timer_with_reviewers(self):
        gate = make_gate(environments=[
            make_environment(
                "production",
                wait_timer=30,
                reviewers=[make_reviewer("alice")],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-003"],
        )
        assert len(findings) == 0

    def test_silent_when_no_timer(self):
        gate = make_gate(environments=[
            make_environment("production", wait_timer=0),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-ENV-003"],
        )
        assert len(findings) == 0


# ==================================================================
# GHOST-WF-001: pull_request_target + checkout (CRITICAL)
# ==================================================================

class TestWF001:
    def test_fires_on_classic_pwn_request(self):
        """The canonical attack: pr_target + checkout head + run."""
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/label.yml",
                name="Auto Label",
                triggers=[make_trigger("pull_request_target", types=["opened"])],
                jobs=[make_job(
                    name="label",
                    steps=[
                        make_step(
                            uses="actions/checkout@v4",
                            with_={"ref": "${{ github.event.pull_request.head.sha }}"},
                        ),
                        make_step(run="npm install && npm run label"),
                    ],
                )],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-001"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].min_privilege == AttackerLevel.EXTERNAL
        assert "pull_request_target" in findings[0].evidence["trigger"]

    def test_fires_with_github_head_ref(self):
        """Alternative ref format."""
        gate = make_gate(workflows=[
            make_workflow(
                triggers=[make_trigger("pull_request_target")],
                jobs=[make_job(steps=[
                    make_step(
                        uses="actions/checkout@v4",
                        with_={"ref": "${{ github.head_ref }}"},
                    ),
                    make_step(run="make test"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-001"],
        )
        assert len(findings) == 1

    def test_silent_when_no_pr_target(self):
        """Regular pull_request trigger is safe."""
        gate = make_gate(workflows=[
            make_workflow(
                triggers=[make_trigger("pull_request")],
                jobs=[make_job(steps=[
                    make_step(uses="actions/checkout@v4"),
                    make_step(run="npm test"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-001"],
        )
        assert len(findings) == 0

    def test_silent_when_checkout_base_only(self):
        """pr_target but checkout without ref (defaults to base) is safe."""
        gate = make_gate(workflows=[
            make_workflow(
                triggers=[make_trigger("pull_request_target")],
                jobs=[make_job(steps=[
                    make_step(uses="actions/checkout@v4"),  # no ref = base branch
                    make_step(run="echo 'safe'"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-001"],
        )
        assert len(findings) == 0

    def test_silent_when_no_code_after_checkout(self):
        """Checkout PR head but no execution afterward — no danger."""
        gate = make_gate(workflows=[
            make_workflow(
                triggers=[make_trigger("pull_request_target")],
                jobs=[make_job(steps=[
                    make_step(
                        uses="actions/checkout@v4",
                        with_={"ref": "${{ github.event.pull_request.head.sha }}"},
                    ),
                    # No run: or uses: after checkout
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-001"],
        )
        assert len(findings) == 0

    def test_fires_with_action_after_checkout(self):
        """A uses: action after PR head checkout is also dangerous."""
        gate = make_gate(workflows=[
            make_workflow(
                triggers=[make_trigger("pull_request_target")],
                jobs=[make_job(steps=[
                    make_step(
                        uses="actions/checkout@v4",
                        with_={"ref": "${{ github.event.pull_request.head.sha }}"},
                    ),
                    make_step(uses="actions/setup-node@v4"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-001"],
        )
        assert len(findings) == 1


# ==================================================================
# GHOST-WF-002: write-all permissions
# ==================================================================

class TestWF002:
    def test_fires_on_workflow_write_all(self):
        gate = make_gate(workflows=[
            make_workflow(
                permissions={"_shorthand": "write-all"},
                jobs=[make_job(steps=[make_step(run="echo")])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-002"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_fires_on_job_write_all(self):
        gate = make_gate(workflows=[
            make_workflow(
                jobs=[make_job(
                    name="deploy",
                    permissions={"_shorthand": "write-all"},
                    steps=[make_step(run="deploy")],
                )],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-002"],
        )
        assert len(findings) == 1

    def test_fires_on_inherited_write_default(self):
        """Org default is write + workflow has no permissions block."""
        gate = make_gate(
            workflow_permissions=WorkflowPermissions(
                default_workflow_permissions="write",
            ),
            workflows=[
                make_workflow(
                    permissions={},
                    jobs=[make_job(permissions={}, steps=[make_step(run="echo")])],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-002"],
        )
        assert len(findings) >= 1

    def test_silent_with_least_privilege(self):
        gate = make_gate(workflows=[
            make_workflow(
                permissions={"contents": "read"},
                jobs=[make_job(steps=[make_step(run="echo")])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-002"],
        )
        assert len(findings) == 0

    def test_silent_with_read_all(self):
        gate = make_gate(workflows=[
            make_workflow(
                permissions={"_shorthand": "read-all"},
                jobs=[make_job(steps=[make_step(run="echo")])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-002"],
        )
        assert len(findings) == 0


# ==================================================================
# GHOST-WF-003: secrets: inherit
# ==================================================================

class TestWF003:
    def test_fires_on_secrets_inherit(self):
        gate = make_gate(workflows=[
            make_workflow(
                jobs=[make_job(
                    name="call-external",
                    uses="other-org/repo/.github/workflows/build.yml@main",
                    secrets="inherit",
                )],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-003"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["is_external"] is True
        assert findings[0].evidence["is_mutable_ref"] is True
        assert findings[0].severity == Severity.HIGH

    def test_lower_severity_internal_pinned(self):
        """Internal reusable workflow with SHA ref → MEDIUM."""
        gate = make_gate(
            org="test-org",
            workflows=[
                make_workflow(
                    jobs=[make_job(
                        name="call-internal",
                        uses="test-org/shared/.github/workflows/build.yml@abc123def456789012345678901234567890abcd",
                        secrets="inherit",
                    )],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-003"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["is_external"] is False
        assert findings[0].evidence["is_mutable_ref"] is False
        assert findings[0].severity == Severity.MEDIUM

    def test_silent_without_inherit(self):
        gate = make_gate(workflows=[
            make_workflow(
                jobs=[make_job(
                    name="call",
                    uses="test-org/shared/.github/workflows/build.yml@v1",
                    secrets={"DEPLOY_KEY": "${{ secrets.DEPLOY_KEY }}"},
                )],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-003"],
        )
        assert len(findings) == 0

    def test_semver_tag_is_immutable(self):
        gate = make_gate(
            org="test-org",
            workflows=[
                make_workflow(
                    jobs=[make_job(
                        name="call",
                        uses="test-org/shared/.github/workflows/build.yml@v1.2.3",
                        secrets="inherit",
                    )],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-003"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["is_mutable_ref"] is False


# ==================================================================
# GHOST-WF-004: Fork PR secrets exposure
# ==================================================================

class TestWF004:
    def test_fires_on_workflow_run_public_repo(self):
        gate = make_gate(
            visibility="public",
            workflows=[
                make_workflow(
                    name="Process PR",
                    triggers=[make_trigger("workflow_run")],
                    jobs=[make_job(steps=[make_step(run="echo")])],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-004"],
        )
        assert len(findings) == 1

    def test_silent_on_private_repo(self):
        gate = make_gate(
            visibility="private",
            workflows=[
                make_workflow(
                    triggers=[make_trigger("workflow_run")],
                    jobs=[make_job(steps=[make_step(run="echo")])],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-004"],
        )
        assert len(findings) == 0

    def test_silent_without_workflow_run(self):
        gate = make_gate(
            visibility="public",
            workflows=[
                make_workflow(
                    triggers=[make_trigger("push")],
                    jobs=[make_job(steps=[make_step(run="echo")])],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-004"],
        )
        assert len(findings) == 0


# ==================================================================
# GHOST-OIDC-001: Default/broad OIDC subject claim
# ==================================================================

class TestOIDC001:
    def test_fires_no_custom_template(self):
        gate = make_gate(
            oidc=OIDCConfig(),  # no custom template
            workflows=[
                make_workflow(
                    permissions={"id-token": "write"},
                    jobs=[make_job(steps=[make_step(run="deploy")])],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-OIDC-001"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_fires_template_without_environment(self):
        gate = make_gate(
            oidc=OIDCConfig(org_level_template=["repo", "ref"]),
            workflows=[
                make_workflow(
                    permissions={"id-token": "write"},
                    jobs=[make_job(steps=[make_step(run="deploy")])],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-OIDC-001"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].evidence["missing_claim"] == "environment"

    def test_silent_with_full_template(self):
        gate = make_gate(
            oidc=OIDCConfig(org_level_template=["repo", "environment", "ref"]),
            workflows=[
                make_workflow(
                    permissions={"id-token": "write"},
                    jobs=[make_job(steps=[make_step(run="deploy")])],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-OIDC-001"],
        )
        assert len(findings) == 0

    def test_silent_when_oidc_not_used(self):
        """No workflow requests id-token → rule doesn't fire."""
        gate = make_gate(
            oidc=OIDCConfig(),
            workflows=[
                make_workflow(
                    permissions={"contents": "read"},
                    jobs=[make_job(steps=[make_step(run="echo")])],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-OIDC-001"],
        )
        assert len(findings) == 0

    def test_detects_oidc_via_write_all(self):
        """write-all includes id-token: write."""
        gate = make_gate(
            oidc=OIDCConfig(),
            workflows=[
                make_workflow(
                    permissions={"_shorthand": "write-all"},
                    jobs=[make_job(steps=[make_step(run="deploy")])],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-OIDC-001"],
        )
        assert len(findings) == 1


# ==================================================================
# GHOST-OIDC-002: OIDC without environment gate
# ==================================================================

class TestOIDC002:
    def test_fires_oidc_without_environment(self):
        gate = make_gate(
            workflows=[
                make_workflow(
                    jobs=[make_job(
                        name="deploy",
                        permissions={"id-token": "write"},
                        steps=[make_step(run="deploy")],
                    )],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-OIDC-002"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["environment"] is None

    def test_fires_oidc_with_ungated_environment(self):
        """Environment exists but has no reviewers."""
        gate = make_gate(
            environments=[make_environment("staging")],  # no reviewers
            workflows=[
                make_workflow(
                    jobs=[make_job(
                        name="deploy",
                        environment="staging",
                        permissions={"id-token": "write"},
                        steps=[make_step(run="deploy")],
                    )],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-OIDC-002"],
        )
        assert len(findings) == 1

    def test_silent_with_gated_environment(self):
        """Environment with reviewers → OIDC is gated."""
        gate = make_gate(
            environments=[
                make_environment("production", reviewers=[make_reviewer("alice")]),
            ],
            workflows=[
                make_workflow(
                    jobs=[make_job(
                        name="deploy",
                        environment="production",
                        permissions={"id-token": "write"},
                        steps=[make_step(run="deploy")],
                    )],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-OIDC-002"],
        )
        assert len(findings) == 0

    def test_workflow_level_oidc_propagates(self):
        """id-token: write at workflow level applies to all jobs."""
        gate = make_gate(
            workflows=[
                make_workflow(
                    permissions={"id-token": "write"},
                    jobs=[make_job(
                        name="deploy",
                        steps=[make_step(run="deploy")],
                    )],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-OIDC-002"],
        )
        assert len(findings) == 1

    def test_silent_when_no_oidc(self):
        gate = make_gate(
            workflows=[
                make_workflow(
                    permissions={"contents": "read"},
                    jobs=[make_job(
                        name="build",
                        permissions={"contents": "read"},
                        steps=[make_step(run="build")],
                    )],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-OIDC-002"],
        )
        assert len(findings) == 0


# ==================================================================
# Integration: Full scan with all rules
# ==================================================================

class TestFullScan:
    def test_maximally_vulnerable_repo(self):
        """A repo with every misconfiguration should trigger many rules."""
        gate = make_gate(
            visibility="public",
            branch_protections=[
                make_bp("main", reviews=2, enforce_admins=False,
                        dismiss_stale=False, codeowners=False),
            ],
            rulesets=[
                make_gate.__wrapped__ if hasattr(make_gate, '__wrapped__') else
                None,
            ] if False else [],
            environments=[
                make_environment("production"),  # no reviewers
                make_environment("staging", wait_timer=15),  # timer only
            ],
            workflow_permissions=WorkflowPermissions(
                default_workflow_permissions="write",
                can_approve_pull_request_reviews=True,
            ),
            oidc=OIDCConfig(),
            workflows=[
                make_workflow(
                    path=".github/workflows/ci.yml",
                    name="CI",
                    triggers=[make_trigger("pull_request_target")],
                    permissions={"_shorthand": "write-all"},
                    jobs=[make_job(
                        name="build",
                        steps=[
                            make_step(
                                uses="actions/checkout@v4",
                                with_={"ref": "${{ github.event.pull_request.head.sha }}"},
                            ),
                            make_step(run="npm install"),
                        ],
                    )],
                ),
                make_workflow(
                    path=".github/workflows/deploy.yml",
                    name="Deploy",
                    triggers=[make_trigger("workflow_run")],
                    jobs=[make_job(
                        name="deploy",
                        uses="other-org/deploy/.github/workflows/deploy.yml@main",
                        secrets="inherit",
                    )],
                ),
            ],
        )
        findings = registry.run_rules(gate, attacker_level=AttackerLevel.ORG_OWNER)

        rule_ids = {f.rule_id for f in findings}

        # Should trigger many rules
        assert "GHOST-BP-001" in rule_ids  # admin bypass
        assert "GHOST-BP-002" in rule_ids  # stale reviews
        assert "GHOST-BP-003" in rule_ids  # no codeowners
        assert "GHOST-BP-005" in rule_ids  # workflows can approve
        assert "GHOST-ENV-001" in rule_ids  # production no reviewers
        assert "GHOST-ENV-003" in rule_ids  # staging timer only
        assert "GHOST-WF-001" in rule_ids  # pr_target + checkout
        assert "GHOST-WF-002" in rule_ids  # write-all
        assert "GHOST-WF-003" in rule_ids  # secrets inherit
        assert "GHOST-WF-004" in rule_ids  # fork PR secrets (public repo)

        # Every finding should have evidence
        for f in findings:
            assert f.evidence, f"Finding {f.rule_id} missing evidence"
            assert f.bypass_path, f"Finding {f.rule_id} missing bypass_path"
            assert f.remediation, f"Finding {f.rule_id} missing remediation"
