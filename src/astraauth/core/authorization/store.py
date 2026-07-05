from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from astraauth.core.authorization.models import PolicyRule, Role, TenantRoleAssignment


class RoleStore(Protocol):
    def get_role(self, role_name: str) -> Role | None: ...


class AssignmentStore(Protocol):
    def get_assignments(self, subject_id: str, tenant_id: str) -> TenantRoleAssignment | None: ...


class PolicyStore(Protocol):
    def list_policies(self, *, permission: str, tenant_id: str) -> Iterable[PolicyRule]: ...


class InMemoryRoleStore(RoleStore):
    def __init__(self) -> None:
        self._roles: dict[str, Role] = {}

    def add_role(self, role: Role) -> None:
        self._roles[role.name] = role

    def get_role(self, role_name: str) -> Role | None:
        return self._roles.get(role_name)


class InMemoryAssignmentStore(AssignmentStore):
    def __init__(self) -> None:
        self._assignments: dict[tuple[str, str], TenantRoleAssignment] = {}

    def assign(self, assignment: TenantRoleAssignment) -> None:
        self._assignments[(assignment.subject_id, assignment.tenant_id)] = assignment

    def get_assignments(self, subject_id: str, tenant_id: str) -> TenantRoleAssignment | None:
        return self._assignments.get((subject_id, tenant_id))


class InMemoryPolicyStore(PolicyStore):
    def __init__(self) -> None:
        self._policies: dict[str, PolicyRule] = {}

    def add_policy(self, policy: PolicyRule) -> None:
        self._policies[policy.policy_id] = policy

    def list_policies(self, *, permission: str, tenant_id: str) -> Iterable[PolicyRule]:
        return tuple(
            policy
            for policy in self._policies.values()
            if policy.permission == permission
            and (policy.tenant_id is None or policy.tenant_id == tenant_id)
        )


# Repository aliases: canonical repository naming while preserving store imports.
RoleRepository = RoleStore
RoleAssignmentRepository = AssignmentStore
PolicyRepository = PolicyStore
InMemoryRoleRepository = InMemoryRoleStore
InMemoryRoleAssignmentRepository = InMemoryAssignmentStore
InMemoryPolicyRepository = InMemoryPolicyStore
