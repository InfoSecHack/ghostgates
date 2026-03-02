"""
Tests for GHOST-WF-005 through GHOST-WF-008 (supply chain rules).

Inspired by the March 2026 Trivy attack:
- Stolen PAT + workflow vulnerability → repo takeover
- Deleted releases, published malicious VSIX extension
- Part of campaign hitting Microsoft, DataDog, CNCF
"""

from __future__ import annotations

import pytest

from ghostgates.engine import registry
from ghostgates.models.enums import AttackerLevel, GateType, Severity
from ghostgates.models.gates import WorkflowPermissions

from tests.mocks.gate_models import (
    make_gate,
    make_job,
    make_step,
    make_trigger,
    make_workflow,
)


# ==================================================================
# GHOST-WF-005: Unpinned third-party action references
# ==================================================================


class TestWF005:
    def test_fires_on_unpinned_third_party(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(uses="actions/checkout@v3"),
                    make_step(uses="some-org/some-action@v2"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-005"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "some-org/some-action@v2" in findings[0].evidence["unpinned_refs"]

    def test_silent_when_pinned_to_sha(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(uses="actions/checkout@v3"),
                    make_step(uses="some-org/some-action@abcdef1234567890abcdef1234567890abcdef12"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-005"],
        )
        assert len(findings) == 0

    def test_skips_first_party_actions(self):
        """actions/ and github/ org actions are lower risk."""
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(uses="actions/checkout@v3"),
                    make_step(uses="actions/setup-node@v4"),
                    make_step(uses="actions/upload-artifact@v4"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-005"],
        )
        assert len(findings) == 0

    def test_counts_multiple_unpinned(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(uses="actions/checkout@v3"),
                    make_step(uses="org-a/lint@v1"),
                    make_step(uses="org-b/deploy@main"),
                    make_step(uses="org-c/notify@v2"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-005"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["unpinned_count"] == 3

    def test_flags_unpinned_reusable_workflow(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(
                    uses="other-org/shared/.github/workflows/build.yml@main",
                )],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-005"],
        )
        assert len(findings) == 1

    def test_deduplicates_same_action(self):
        """Same action used in multiple jobs should only count once."""
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("push")],
                jobs=[
                    make_job(name="build", steps=[
                        make_step(uses="org/action@v1"),
                    ]),
                    make_job(name="test", steps=[
                        make_step(uses="org/action@v1"),
                    ]),
                ],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-005"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["unpinned_count"] == 1

    def test_mixed_pinned_unpinned(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(uses="org/pinned@abcdef1234567890abcdef1234567890abcdef12"),
                    make_step(uses="org/unpinned@v3"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.EXTERNAL,
            rule_ids=["GHOST-WF-005"],
        )
        assert len(findings) == 1
        assert findings[0].evidence["unpinned_count"] == 1


# ==================================================================
# GHOST-WF-006: workflow_dispatch with write permissions
# ==================================================================


class TestWF006:
    def test_fires_dispatch_with_write_all(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/deploy.yml",
                triggers=[make_trigger("workflow_dispatch")],
                permissions={"_shorthand": "write-all"},
                jobs=[make_job()],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-006"],
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "workflow_dispatch" in findings[0].evidence["trigger"]

    def test_fires_dispatch_inheriting_write_default(self):
        gate = make_gate(
            workflow_permissions=WorkflowPermissions(
                default_workflow_permissions="write",
            ),
            workflows=[
                make_workflow(
                    path=".github/workflows/deploy.yml",
                    triggers=[make_trigger("workflow_dispatch")],
                    jobs=[make_job()],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-006"],
        )
        assert len(findings) == 1
        assert "inherited" in findings[0].evidence.get("permissions_source", "")

    def test_silent_dispatch_with_read_only(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("workflow_dispatch")],
                permissions={"contents": "read"},
                jobs=[make_job(permissions={"contents": "read"})],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-006"],
        )
        assert len(findings) == 0

    def test_silent_no_dispatch_trigger(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("push")],
                permissions={"_shorthand": "write-all"},
                jobs=[make_job()],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-006"],
        )
        assert len(findings) == 0

    def test_fires_dispatch_with_job_level_dangerous_perms(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/deploy.yml",
                triggers=[make_trigger("workflow_dispatch")],
                permissions={"contents": "read"},
                jobs=[make_job(
                    permissions={"contents": "write", "packages": "write"},
                )],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-006"],
        )
        assert len(findings) == 1


# ==================================================================
# GHOST-WF-007: contents:write without environment gate
# ==================================================================


class TestWF007:
    def test_fires_contents_write_no_env(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/release.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(
                    permissions={"contents": "write"},
                )],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-007"],
        )
        assert len(findings) == 1
        assert "contents:write" in findings[0].summary

    def test_silent_contents_write_with_env(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/release.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(
                    permissions={"contents": "write"},
                    environment="production",
                )],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-007"],
        )
        assert len(findings) == 0

    def test_fires_write_all_no_env(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/release.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(
                    permissions={"_shorthand": "write-all"},
                )],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-007"],
        )
        assert len(findings) == 1

    def test_fires_inherited_write_default(self):
        gate = make_gate(
            workflow_permissions=WorkflowPermissions(
                default_workflow_permissions="write",
            ),
            workflows=[
                make_workflow(
                    path=".github/workflows/release.yml",
                    triggers=[make_trigger("push")],
                    jobs=[make_job()],
                ),
            ],
        )
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-007"],
        )
        assert len(findings) == 1
        assert "inherited" in findings[0].evidence["permissions_source"]

    def test_fires_workflow_level_contents_write(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/release.yml",
                triggers=[make_trigger("push")],
                permissions={"contents": "write"},
                jobs=[make_job()],  # no job-level perms, inherits wf-level
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-007"],
        )
        assert len(findings) == 1

    def test_silent_contents_read(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("push")],
                permissions={"contents": "read"},
                jobs=[make_job()],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-007"],
        )
        assert len(findings) == 0


# ==================================================================
# GHOST-WF-008: Package/release publish without environment gate
# ==================================================================


class TestWF008:
    def test_fires_npm_publish_no_env(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/publish.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(run="npm publish"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-008"],
        )
        assert len(findings) == 1
        assert "npm publish" in findings[0].evidence["publish_steps"][0]

    def test_fires_docker_push_no_env(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/publish.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(run="docker push myimage:latest"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-008"],
        )
        assert len(findings) == 1

    def test_fires_pypi_publish_action(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/publish.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(uses="pypa/gh-action-pypi-publish@v1"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-008"],
        )
        assert len(findings) == 1

    def test_fires_release_action(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/release.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(uses="softprops/action-gh-release@v1"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-008"],
        )
        assert len(findings) == 1

    def test_fires_vsce_publish(self):
        """The exact attack vector used against Trivy's VSIX."""
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/vscode-ext.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(run="vsce publish"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-008"],
        )
        assert len(findings) == 1

    def test_fires_ovsx_publish(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ext.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(run="ovsx publish -p $TOKEN"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-008"],
        )
        assert len(findings) == 1

    def test_silent_publish_with_env_gate(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/publish.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(
                    environment="production",
                    steps=[
                        make_step(run="npm publish"),
                    ],
                )],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-008"],
        )
        assert len(findings) == 0

    def test_silent_no_publish_steps(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/ci.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(run="npm test"),
                    make_step(run="npm run lint"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-008"],
        )
        assert len(findings) == 0

    def test_fires_gh_release_create(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/release.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(run="gh release create v1.0.0 --notes 'Release'"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-008"],
        )
        assert len(findings) == 1

    def test_multiple_publish_steps(self):
        gate = make_gate(workflows=[
            make_workflow(
                path=".github/workflows/publish.yml",
                triggers=[make_trigger("push")],
                jobs=[make_job(steps=[
                    make_step(uses="docker/build-push-action@v5"),
                    make_step(run="npm publish"),
                ])],
            ),
        ])
        findings = registry.run_rules(
            gate, attacker_level=AttackerLevel.REPO_WRITE,
            rule_ids=["GHOST-WF-008"],
        )
        assert len(findings) == 1
        assert len(findings[0].evidence["publish_steps"]) == 2
