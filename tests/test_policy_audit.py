"""Tests for ghostgates policy audit."""

from __future__ import annotations

import json
import textwrap
import tempfile
from pathlib import Path

import pytest

from ghostgates.models.gates import (
    BranchProtection,
    EnvironmentConfig,
    EnvironmentProtection,
    EnvironmentReviewer,
    GateModel,
    OIDCConfig,
    WorkflowDefinition,
    WorkflowJob,
    WorkflowPermissions,
    WorkflowTrigger,
)
from ghostgates.policy.schema import GhostGatesPolicy, load_policy
from ghostgates.policy.evaluator import (
    GapCategory,
    PolicyAuditResult,
    PolicyGap,
    RepoAuditResult,
    _repo_in_scope,
    evaluate_policy,
)
from ghostgates.policy.formatter import (
    format_audit_json,
    format_audit_markdown,
    format_audit_terminal,
)


# ── Helpers ──────────────────────────────────────────────────────

def _write_policy(content: str) -> str:
    """Write policy YAML to a temp file and return path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
    f.write(content)
    f.close()
    return f.name


def _gate(
    repo: str = "api",
    org: str = "acme",
    branch_protections: list | None = None,
    environments: list | None = None,
    workflows: list | None = None,
    workflow_permissions: WorkflowPermissions | None = None,
    oidc: OIDCConfig | None = None,
) -> GateModel:
    return GateModel(
        org=org,
        repo=repo,
        full_name=f"{org}/{repo}",
        default_branch="main",
        branch_protections=branch_protections or [],
        environments=environments or [],
        workflows=workflows or [],
        workflow_permissions=workflow_permissions or WorkflowPermissions(),
        oidc=oidc or OIDCConfig(),
    )


def _bp(
    branch: str = "main",
    enforce_admins: bool = True,
    dismiss_stale_reviews: bool = True,
    reviewers: int = 2,
    codeowners: bool = True,
    status_checks: list | None = None,
    force_pushes: bool = False,
    signatures: bool = False,
) -> BranchProtection:
    return BranchProtection(
        branch=branch,
        enforce_admins=enforce_admins,
        dismiss_stale_reviews=dismiss_stale_reviews,
        required_approving_review_count=reviewers,
        require_code_owner_reviews=codeowners,
        required_status_checks=status_checks or [],
        allow_force_pushes=force_pushes,
        required_signatures=signatures,
    )


# ── Policy loading ───────────────────────────────────────────────


class TestPolicyLoading:
    def test_load_minimal(self):
        path = _write_policy("policy:\n  branch_protection:\n    enforce_admins: true\n")
        p = load_policy(path)
        assert p.policy.branch_protection.enforce_admins is True
        Path(path).unlink()

    def test_load_full(self):
        path = _write_policy(textwrap.dedent("""\
            policy:
              branch_protection:
                enforce_admins: true
                min_reviewers: 2
              environments:
                "prod.*":
                  required_reviewers: true
              workflows:
                max_default_permissions: read
              oidc:
                require_environment_claim: true
            scope:
              include: [".*"]
              exclude: ["docs"]
        """))
        p = load_policy(path)
        assert p.policy.branch_protection.min_reviewers == 2
        assert "prod.*" in p.policy.environments
        assert p.scope.exclude == ["docs"]
        Path(path).unlink()

    def test_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_policy("/nonexistent/policy.yml")

    def test_empty_file(self):
        path = _write_policy("")
        with pytest.raises(ValueError, match="Empty"):
            load_policy(path)
        Path(path).unlink()

    def test_unset_fields_are_none(self):
        path = _write_policy("policy:\n  branch_protection:\n    enforce_admins: true\n")
        p = load_policy(path)
        assert p.policy.branch_protection.dismiss_stale_reviews is None
        assert p.policy.branch_protection.min_reviewers is None
        Path(path).unlink()


# ── Scope filtering ──────────────────────────────────────────────


class TestScopeFiltering:
    def test_default_includes_all(self):
        p = GhostGatesPolicy()
        assert _repo_in_scope("anything", p.scope)

    def test_exclude_pattern(self):
        p = GhostGatesPolicy(scope={"include": [".*"], "exclude": ["docs"]})
        assert _repo_in_scope("api", p.scope)
        assert not _repo_in_scope("docs", p.scope)

    def test_include_pattern(self):
        p = GhostGatesPolicy(scope={"include": ["^api"], "exclude": []})
        assert _repo_in_scope("api", p.scope)
        assert _repo_in_scope("api-v2", p.scope)
        assert not _repo_in_scope("web", p.scope)

    def test_exclude_regex(self):
        p = GhostGatesPolicy(scope={"include": [".*"], "exclude": [".*-sandbox"]})
        assert _repo_in_scope("api", p.scope)
        assert not _repo_in_scope("api-sandbox", p.scope)

    def test_repo_excluded_not_audited(self):
        policy = GhostGatesPolicy(
            policy={"branch_protection": {"enforce_admins": True}},
            scope={"include": [".*"], "exclude": ["docs"]},
        )
        gates = [
            _gate(repo="api", branch_protections=[_bp(enforce_admins=False)]),
            _gate(repo="docs", branch_protections=[_bp(enforce_admins=False)]),
        ]
        result = evaluate_policy(gates, policy)
        assert result.total_repos == 1
        assert result.excluded_repos == 1


# ── Branch protection checks ────────────────────────────────────


class TestBranchProtectionAudit:
    def _policy(self, **kw) -> GhostGatesPolicy:
        return GhostGatesPolicy(policy={"branch_protection": kw})

    def test_enforce_admins_compliant(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(enforce_admins=True)])],
            self._policy(enforce_admins=True),
        )
        assert result.compliant_count == 1

    def test_enforce_admins_gap(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(enforce_admins=False)])],
            self._policy(enforce_admins=True),
        )
        assert result.noncompliant_count == 1
        assert result.repo_results[0].gaps[0].check == "enforce_admins"

    def test_min_reviewers_gap(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(reviewers=1)])],
            self._policy(min_reviewers=2),
        )
        assert result.repo_results[0].gaps[0].check == "min_reviewers"
        assert result.repo_results[0].gaps[0].actual == "1"

    def test_min_reviewers_met(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(reviewers=3)])],
            self._policy(min_reviewers=2),
        )
        assert result.compliant_count == 1

    def test_dismiss_stale_reviews_gap(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(dismiss_stale_reviews=False)])],
            self._policy(dismiss_stale_reviews=True),
        )
        assert result.repo_results[0].gaps[0].check == "dismiss_stale_reviews"

    def test_codeowners_gap(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(codeowners=False)])],
            self._policy(require_codeowners=True),
        )
        assert result.repo_results[0].gaps[0].check == "require_codeowners"

    def test_status_checks_gap(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(status_checks=[])])],
            self._policy(require_status_checks=True),
        )
        assert result.repo_results[0].gaps[0].check == "require_status_checks"

    def test_status_checks_compliant(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(status_checks=["ci/build"])])],
            self._policy(require_status_checks=True),
        )
        assert result.compliant_count == 1

    def test_force_pushes_gap(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(force_pushes=True)])],
            self._policy(block_force_pushes=True),
        )
        assert result.repo_results[0].gaps[0].check == "block_force_pushes"

    def test_signatures_gap(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(signatures=False)])],
            self._policy(require_signatures=True),
        )
        assert result.repo_results[0].gaps[0].check == "require_signatures"

    def test_no_branch_protection_at_all(self):
        result = evaluate_policy(
            [_gate(branch_protections=[])],
            self._policy(enforce_admins=True),
        )
        assert result.repo_results[0].gaps[0].check == "branch_protection_exists"

    def test_multiple_gaps_same_repo(self):
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(enforce_admins=False, reviewers=0)])],
            self._policy(enforce_admins=True, min_reviewers=2),
        )
        assert len(result.repo_results[0].gaps) == 2

    def test_only_checks_default_branch(self):
        """Non-default branches are not checked."""
        result = evaluate_policy(
            [_gate(branch_protections=[
                _bp(branch="develop", enforce_admins=False),  # not default
            ])],
            self._policy(enforce_admins=True),
        )
        # No default branch protection found → flags that
        assert result.repo_results[0].gaps[0].check == "branch_protection_exists"

    def test_unchecked_fields_ignored(self):
        """If policy doesn't set a field, it's not checked."""
        result = evaluate_policy(
            [_gate(branch_protections=[_bp(enforce_admins=False, codeowners=False)])],
            self._policy(min_reviewers=2),  # only checks reviewers
        )
        gaps = result.repo_results[0].gaps
        assert all(g.check == "min_reviewers" for g in gaps)


# ── Environment checks ──────────────────────────────────────────


class TestEnvironmentAudit:
    def test_prod_reviewers_gap(self):
        policy = GhostGatesPolicy(policy={
            "environments": {"prod.*": {"required_reviewers": True}},
        })
        gate = _gate(environments=[
            EnvironmentConfig(name="production", reviewers=[]),
        ])
        result = evaluate_policy([gate], policy)
        assert result.repo_results[0].gaps[0].check == "required_reviewers"

    def test_prod_reviewers_compliant(self):
        policy = GhostGatesPolicy(policy={
            "environments": {"prod.*": {"required_reviewers": True}},
        })
        gate = _gate(environments=[
            EnvironmentConfig(
                name="production",
                reviewers=[EnvironmentReviewer(type="User", id=1, login="alice")],
            ),
        ])
        result = evaluate_policy([gate], policy)
        assert result.compliant_count == 1

    def test_restrict_branches_gap(self):
        policy = GhostGatesPolicy(policy={
            "environments": {"production": {"restrict_branches": True}},
        })
        gate = _gate(environments=[
            EnvironmentConfig(
                name="production",
                deployment_branch_policy=EnvironmentProtection(type="all"),
            ),
        ])
        result = evaluate_policy([gate], policy)
        assert result.repo_results[0].gaps[0].check == "restrict_branches"

    def test_wait_timer_gap(self):
        policy = GhostGatesPolicy(policy={
            "environments": {"prod.*": {"min_wait_timer": 5}},
        })
        gate = _gate(environments=[
            EnvironmentConfig(name="production", wait_timer=0),
        ])
        result = evaluate_policy([gate], policy)
        assert result.repo_results[0].gaps[0].check == "min_wait_timer"

    def test_non_matching_env_not_checked(self):
        policy = GhostGatesPolicy(policy={
            "environments": {"prod.*": {"required_reviewers": True}},
        })
        gate = _gate(environments=[
            EnvironmentConfig(name="staging", reviewers=[]),
        ])
        result = evaluate_policy([gate], policy)
        assert result.compliant_count == 1  # staging doesn't match prod.*


# ── Workflow checks ──────────────────────────────────────────────


class TestWorkflowAudit:
    def test_default_permissions_gap(self):
        policy = GhostGatesPolicy(policy={
            "workflows": {"max_default_permissions": "read"},
        })
        gate = _gate(workflow_permissions=WorkflowPermissions(
            default_workflow_permissions="write",
        ))
        result = evaluate_policy([gate], policy)
        assert result.repo_results[0].gaps[0].check == "max_default_permissions"

    def test_default_permissions_compliant(self):
        policy = GhostGatesPolicy(policy={
            "workflows": {"max_default_permissions": "read"},
        })
        gate = _gate(workflow_permissions=WorkflowPermissions(
            default_workflow_permissions="read",
        ))
        result = evaluate_policy([gate], policy)
        assert result.compliant_count == 1

    def test_block_pr_target_gap(self):
        policy = GhostGatesPolicy(policy={
            "workflows": {"block_pull_request_target": True},
        })
        gate = _gate(workflows=[
            WorkflowDefinition(
                path=".github/workflows/ci.yml",
                triggers=[WorkflowTrigger(event="pull_request_target")],
            ),
        ])
        result = evaluate_policy([gate], policy)
        assert result.repo_results[0].gaps[0].check == "block_pull_request_target"

    def test_block_secrets_inherit_gap(self):
        policy = GhostGatesPolicy(policy={
            "workflows": {"block_secrets_inherit": True},
        })
        gate = _gate(workflows=[
            WorkflowDefinition(
                path=".github/workflows/ci.yml",
                jobs=[WorkflowJob(name="build", secrets="inherit")],
            ),
        ])
        result = evaluate_policy([gate], policy)
        assert result.repo_results[0].gaps[0].check == "block_secrets_inherit"

    def test_block_write_all_top_level(self):
        policy = GhostGatesPolicy(policy={
            "workflows": {"block_write_all": True},
        })
        gate = _gate(workflows=[
            WorkflowDefinition(
                path=".github/workflows/ci.yml",
                permissions={"__all__": "write-all"},
            ),
        ])
        result = evaluate_policy([gate], policy)
        assert result.repo_results[0].gaps[0].check == "block_write_all"

    def test_block_write_all_job_level(self):
        policy = GhostGatesPolicy(policy={
            "workflows": {"block_write_all": True},
        })
        gate = _gate(workflows=[
            WorkflowDefinition(
                path=".github/workflows/ci.yml",
                jobs=[WorkflowJob(name="deploy", permissions={"__all__": "write-all"})],
            ),
        ])
        result = evaluate_policy([gate], policy)
        assert result.repo_results[0].gaps[0].check == "block_write_all"

    def test_block_pr_approval_gap(self):
        policy = GhostGatesPolicy(policy={
            "workflows": {"block_pr_approval": True},
        })
        gate = _gate(workflow_permissions=WorkflowPermissions(
            can_approve_pull_request_reviews=True,
        ))
        result = evaluate_policy([gate], policy)
        assert result.repo_results[0].gaps[0].check == "block_pr_approval"


# ── OIDC checks ──────────────────────────────────────────────────


class TestOIDCAudit:
    def test_require_custom_template_gap(self):
        policy = GhostGatesPolicy(policy={
            "oidc": {"require_custom_template": True},
        })
        gate = _gate(oidc=OIDCConfig(org_level_template=[]))
        result = evaluate_policy([gate], policy)
        assert result.repo_results[0].gaps[0].check == "require_custom_template"

    def test_require_custom_template_compliant(self):
        policy = GhostGatesPolicy(policy={
            "oidc": {"require_custom_template": True},
        })
        gate = _gate(oidc=OIDCConfig(org_level_template=["repo", "environment"]))
        result = evaluate_policy([gate], policy)
        assert result.compliant_count == 1

    def test_require_env_claim_missing(self):
        policy = GhostGatesPolicy(policy={
            "oidc": {"require_environment_claim": True},
        })
        gate = _gate(oidc=OIDCConfig(org_level_template=["repo", "ref"]))
        result = evaluate_policy([gate], policy)
        gaps = [g for g in result.repo_results[0].gaps if g.check == "require_environment_claim"]
        assert len(gaps) >= 1

    def test_oidc_job_without_env_gap(self):
        policy = GhostGatesPolicy(policy={
            "oidc": {"require_environment_claim": True},
        })
        gate = _gate(
            oidc=OIDCConfig(org_level_template=["repo", "environment"]),
            workflows=[
                WorkflowDefinition(
                    path=".github/workflows/deploy.yml",
                    jobs=[WorkflowJob(
                        name="deploy",
                        permissions={"id-token": "write"},
                        environment=None,  # no env!
                    )],
                ),
            ],
        )
        result = evaluate_policy([gate], policy)
        oidc_gaps = [g for g in result.repo_results[0].gaps
                     if g.check == "require_environment_claim"]
        assert len(oidc_gaps) == 1
        assert "deploy" in oidc_gaps[0].actual


# ── Result properties ────────────────────────────────────────────


class TestAuditResultProperties:
    def test_compliance_percentage(self):
        result = PolicyAuditResult(
            policy_path="test.yml",
            total_repos=4,
            excluded_repos=0,
            repo_results=[
                RepoAuditResult(repo="a", gaps=[]),
                RepoAuditResult(repo="b", gaps=[]),
                RepoAuditResult(repo="c", gaps=[]),
                RepoAuditResult(repo="d", gaps=[
                    PolicyGap(repo="d", category=GapCategory.BRANCH_PROTECTION,
                              check="x", expected="y", actual="z"),
                ]),
            ],
        )
        assert result.compliance_pct == 75.0
        assert result.compliant_count == 3
        assert result.noncompliant_count == 1

    def test_empty_result(self):
        result = PolicyAuditResult(
            policy_path="test.yml", total_repos=0, excluded_repos=0,
        )
        assert result.compliance_pct == 100.0
        assert result.total_gaps == 0


# ── Multi-repo audit ─────────────────────────────────────────────


class TestMultiRepoAudit:
    def test_mixed_compliance(self):
        policy = GhostGatesPolicy(policy={
            "branch_protection": {"enforce_admins": True},
        })
        gates = [
            _gate(repo="api", branch_protections=[_bp(enforce_admins=True)]),
            _gate(repo="web", branch_protections=[_bp(enforce_admins=False)]),
            _gate(repo="docs", branch_protections=[_bp(enforce_admins=True)]),
        ]
        result = evaluate_policy(gates, policy)
        assert result.compliant_count == 2
        assert result.noncompliant_count == 1

    def test_sorted_noncompliant_first(self):
        policy = GhostGatesPolicy(policy={
            "branch_protection": {"enforce_admins": True, "min_reviewers": 2},
        })
        gates = [
            _gate(repo="compliant", branch_protections=[_bp()]),
            _gate(repo="bad", branch_protections=[_bp(enforce_admins=False, reviewers=0)]),
        ]
        result = evaluate_policy(gates, policy)
        assert result.repo_results[0].repo == "acme/bad"  # noncompliant first


# ── Formatters ───────────────────────────────────────────────────


class TestAuditTerminalFormatter:
    def _result(self) -> PolicyAuditResult:
        return PolicyAuditResult(
            policy_path="policy.yml",
            total_repos=3,
            excluded_repos=1,
            repo_results=[
                RepoAuditResult(repo="acme/api", gaps=[
                    PolicyGap(repo="acme/api", category=GapCategory.BRANCH_PROTECTION,
                              check="enforce_admins", expected="true", actual="false",
                              context="main"),
                ]),
                RepoAuditResult(repo="acme/web", gaps=[]),
                RepoAuditResult(repo="acme/docs", gaps=[]),
            ],
        )

    def test_shows_compliance(self):
        output = format_audit_terminal(self._result())
        assert "Policy Audit" in output
        assert "67%" in output  # 2/3

    def test_shows_gaps(self):
        output = format_audit_terminal(self._result())
        assert "enforce_admins" in output
        assert "acme/api" in output

    def test_shows_compliant(self):
        output = format_audit_terminal(self._result())
        assert "acme/web" in output or "Compliant" in output

    def test_empty_no_crash(self):
        result = PolicyAuditResult(
            policy_path="x.yml", total_repos=0, excluded_repos=0,
        )
        output = format_audit_terminal(result)
        assert "No repos in scope" in output


class TestAuditJsonFormatter:
    def test_valid_json(self):
        result = PolicyAuditResult(
            policy_path="p.yml",
            total_repos=1,
            excluded_repos=0,
            repo_results=[
                RepoAuditResult(repo="acme/api", gaps=[
                    PolicyGap(repo="acme/api", category=GapCategory.BRANCH_PROTECTION,
                              check="enforce_admins", expected="true", actual="false"),
                ]),
            ],
        )
        parsed = json.loads(format_audit_json(result))
        assert parsed["compliance_pct"] == 0.0
        assert parsed["total_gaps"] == 1
        assert parsed["repos"][0]["gaps"][0]["check"] == "enforce_admins"


class TestAuditMarkdownFormatter:
    def test_has_headers(self):
        result = PolicyAuditResult(
            policy_path="p.yml",
            total_repos=2,
            excluded_repos=0,
            repo_results=[
                RepoAuditResult(repo="acme/api", gaps=[
                    PolicyGap(repo="acme/api", category=GapCategory.BRANCH_PROTECTION,
                              check="enforce_admins", expected="true", actual="false"),
                ]),
                RepoAuditResult(repo="acme/web", gaps=[]),
            ],
        )
        output = format_audit_markdown(result)
        assert "# GhostGates Policy Audit Report" in output
        assert "## Policy Gaps" in output
        assert "enforce_admins" in output
