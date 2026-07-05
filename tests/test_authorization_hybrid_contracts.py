from astraauth.core.authorization.engine import AuthorizationEngine
from astraauth.core.authorization.models import (
    AuthorizationAttributes,
    AuthorizationContext,
    Decision,
    PolicyRule,
    Role,
    TenantRoleAssignment,
)
from astraauth.core.authorization.store import (
    InMemoryAssignmentStore,
    InMemoryPolicyStore,
    InMemoryRoleStore,
)


def _build_engine(
    *, with_policies: bool = True
) -> tuple[AuthorizationEngine, InMemoryPolicyStore | None]:
    roles = InMemoryRoleStore()
    assignments = InMemoryAssignmentStore()
    policies = InMemoryPolicyStore() if with_policies else None
    roles.add_role(Role(name="admin", permissions={"reports:view", "payments:approve"}))
    assignments.assign(
        TenantRoleAssignment(subject_id="user-1", tenant_id="tenant-1", roles={"admin"})
    )
    return AuthorizationEngine(roles, assignments, policy_store=policies), policies


def test_authorization_engine_preserves_rbac_allow_without_policies() -> None:
    engine, _ = _build_engine(with_policies=False)

    decision = engine.authorize(
        subject_id="user-1",
        tenant_id="tenant-1",
        permission="reports:view",
    )

    assert decision.decision == Decision.ALLOW
    assert decision.reasons == ("permission_granted",)
    assert decision.matched_policies == ()


def test_authorization_engine_denies_when_abac_constraint_matches() -> None:
    engine, policies = _build_engine()
    assert policies is not None
    policies.add_policy(
        PolicyRule(
            policy_id="deny-unmanaged-device",
            permission="payments:approve",
            effect=Decision.DENY,
            tenant_id="tenant-1",
            environment_match={"device_trust": "unmanaged"},
            reasons=("device_not_trusted",),
        )
    )

    decision = engine.authorize(
        subject_id="user-1",
        tenant_id="tenant-1",
        permission="payments:approve",
        environment_attributes={"device_trust": "unmanaged"},
    )

    assert decision.decision == Decision.DENY
    assert decision.reasons == ("device_not_trusted",)
    assert decision.matched_policies[0].policy_id == "deny-unmanaged-device"


def test_authorization_engine_returns_step_up_for_matching_policy() -> None:
    engine, policies = _build_engine()
    assert policies is not None
    policies.add_policy(
        PolicyRule(
            policy_id="step-up-high-risk",
            permission="payments:approve",
            effect=Decision.STEP_UP,
            tenant_id="tenant-1",
            subject_match={"risk_level": "high"},
            required_acr=3,
            reasons=("risk_based_step_up",),
        )
    )

    decision = engine.authorize(
        subject_id="user-1",
        tenant_id="tenant-1",
        permission="payments:approve",
        current_acr=1,
        subject_attributes={"risk_level": "high"},
    )

    assert decision.decision == Decision.STEP_UP
    assert decision.required_acr == 3
    assert decision.reasons == ("risk_based_step_up",)


def test_authorize_context_supports_phase6_idp_attributes() -> None:
    engine, policies = _build_engine()
    assert policies is not None
    policies.add_policy(
        PolicyRule(
            policy_id="allow-finance-export",
            permission="reports:view",
            effect=Decision.ALLOW,
            tenant_id="tenant-1",
            subject_match={"department": ("finance", "audit")},
            environment_match={"network_zone": "corp"},
            reasons=("department_and_network_ok",),
        )
    )

    decision = engine.authorize_context(
        AuthorizationContext(
            subject_id="user-1",
            tenant_id="tenant-1",
            permission="reports:view",
            attributes=AuthorizationAttributes(
                subject={"department": "finance"},
                environment={"network_zone": "corp"},
            ),
        )
    )

    assert decision is not None
    assert decision.decision == Decision.ALLOW
    assert "department_and_network_ok" in decision.reasons
