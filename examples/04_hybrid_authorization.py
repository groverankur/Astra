from __future__ import annotations

from pprint import pprint

from astraauth.core.authorization.engine import AuthorizationEngine
from astraauth.core.authorization.models import Decision, PolicyRule, Role, TenantRoleAssignment
from astraauth.core.authorization.store import (
    InMemoryAssignmentStore,
    InMemoryPolicyStore,
    InMemoryRoleStore,
)


def main() -> None:
    roles = InMemoryRoleStore()
    assignments = InMemoryAssignmentStore()
    policies = InMemoryPolicyStore()

    roles.add_role(Role(name="finance_admin", permissions={"payments:approve", "reports:view"}))
    assignments.assign(
        TenantRoleAssignment(subject_id="user-1", tenant_id="tenant-1", roles={"finance_admin"})
    )
    policies.add_policy(
        PolicyRule(
            policy_id="step-up-high-risk-payments",
            permission="payments:approve",
            effect=Decision.STEP_UP,
            tenant_id="tenant-1",
            subject_match={"risk_level": "high"},
            required_acr=3,
            reasons=("high_risk_payment_requires_step_up",),
        )
    )
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

    engine = AuthorizationEngine(roles, assignments, policy_store=policies)

    print("allow:")
    pprint(
        engine.authorize(
            subject_id="user-1",
            tenant_id="tenant-1",
            permission="payments:approve",
            current_acr=2,
            subject_attributes={"risk_level": "low"},
            environment_attributes={"device_trust": "managed"},
        )
    )
    print("\nstep-up:")
    pprint(
        engine.authorize(
            subject_id="user-1",
            tenant_id="tenant-1",
            permission="payments:approve",
            current_acr=1,
            subject_attributes={"risk_level": "high"},
            environment_attributes={"device_trust": "managed"},
        )
    )
    print("\ndeny:")
    pprint(
        engine.authorize(
            subject_id="user-1",
            tenant_id="tenant-1",
            permission="payments:approve",
            current_acr=3,
            subject_attributes={"risk_level": "low"},
            environment_attributes={"device_trust": "unmanaged"},
        )
    )


if __name__ == "__main__":
    main()
