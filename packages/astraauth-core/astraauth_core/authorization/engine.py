from __future__ import annotations

from astraauth_core.authorization.exceptions import RoleNotFoundError
from astraauth_core.authorization.models import (
    AuthorizationAttributes,
    AuthorizationContext,
    AuthorizationDecision,
    Decision,
    PolicyMatch,
    PolicyRule,
)
from astraauth_core.authorization.store import AssignmentStore, PolicyStore, RoleStore


class AuthorizationEngine:
    def __init__(
        self,
        role_store: RoleStore,
        assignment_store: AssignmentStore,
        policy_store: PolicyStore | None = None,
    ) -> None:
        self._roles = role_store
        self._assignments = assignment_store
        self._policies = policy_store

    def resolve_permissions(
        self,
        *,
        subject_id: str,
        tenant_id: str,
    ) -> set[str]:
        assignment = self._assignments.get_assignments(subject_id, tenant_id)
        if not assignment:
            return set()

        permissions: set[str] = set()

        for role_name in assignment.roles:
            role = self._roles.get_role(role_name)
            if role:
                permissions.update(role.permissions)
            if not role:
                raise RoleNotFoundError(f"Role '{role_name}' not found")

        return permissions

    def has_permission(
        self,
        *,
        subject_id: str,
        tenant_id: str,
        permission: str,
    ) -> bool:
        return permission in self.resolve_permissions(
            subject_id=subject_id,
            tenant_id=tenant_id,
        )

    def resolve_roles(
        self,
        *,
        subject_id: str,
        tenant_id: str,
    ) -> set[str]:
        assignment = self._assignments.get_assignments(subject_id, tenant_id)
        if not assignment:
            return set()
        return assignment.roles

    def authorize(
        self,
        *,
        subject_id: str,
        tenant_id: str,
        permission: str,
        current_acr: int = 1,
        required_acr: int | None = None,
        subject_attributes: dict[str, str | int | float | bool] | None = None,
        resource_attributes: dict[str, str | int | float | bool] | None = None,
        environment_attributes: dict[str, str | int | float | bool] | None = None,
        session_id: str | None = None,
    ) -> AuthorizationDecision:
        if not self.has_permission(
            subject_id=subject_id,
            tenant_id=tenant_id,
            permission=permission,
        ):
            return AuthorizationDecision(
                decision=Decision.DENY,
                reasons=("missing_permission", permission),
            )

        context = AuthorizationContext(
            subject_id=subject_id,
            tenant_id=tenant_id,
            permission=permission,
            current_acr=current_acr,
            required_acr=required_acr,
            session_id=session_id,
            attributes=AuthorizationAttributes(
                subject=subject_attributes or {},
                resource=resource_attributes or {},
                environment=environment_attributes or {},
            ),
        )
        policy_decision = self.authorize_context(context)
        if policy_decision is not None:
            return policy_decision

        if required_acr is not None and current_acr < required_acr:
            return AuthorizationDecision(
                decision=Decision.STEP_UP,
                reasons=("acr_too_low",),
                required_acr=required_acr,
            )

        return AuthorizationDecision(
            decision=Decision.ALLOW,
            reasons=("permission_granted",),
        )

    def authorize_context(self, context: AuthorizationContext) -> AuthorizationDecision | None:
        if self._policies is None:
            return None

        matches = self._evaluate_policies(context)
        if not matches:
            return None

        denies = tuple(match for match in matches if match.effect == Decision.DENY)
        if denies:
            return AuthorizationDecision(
                decision=Decision.DENY,
                reasons=denies[0].reasons,
                matched_policies=matches,
            )

        step_ups = tuple(match for match in matches if match.effect == Decision.STEP_UP)
        if step_ups:
            required_acr = max(match.required_acr or context.required_acr or 1 for match in step_ups)
            if context.current_acr < required_acr:
                return AuthorizationDecision(
                    decision=Decision.STEP_UP,
                    reasons=step_ups[0].reasons,
                    required_acr=required_acr,
                    matched_policies=matches,
                )

        allows = tuple(match for match in matches if match.effect == Decision.ALLOW)
        if allows:
            reasons = ("permission_granted",) + allows[0].reasons
            return AuthorizationDecision(
                decision=Decision.ALLOW,
                reasons=reasons,
                matched_policies=matches,
            )

        return None

    def _evaluate_policies(self, context: AuthorizationContext) -> tuple[PolicyMatch, ...]:
        assert self._policies is not None
        matches: list[PolicyMatch] = []
        for policy in self._policies.list_policies(
            permission=context.permission,
            tenant_id=context.tenant_id,
        ):
            if self._policy_matches(policy, context):
                reasons = policy.reasons or (f"policy:{policy.policy_id}",)
                matches.append(
                    PolicyMatch(
                        policy_id=policy.policy_id,
                        effect=policy.effect,
                        reasons=reasons,
                        required_acr=policy.required_acr,
                    )
                )
        return tuple(matches)

    def _policy_matches(self, policy: PolicyRule, context: AuthorizationContext) -> bool:
        return (
            self._match_attributes(policy.subject_match, context.attributes.subject)
            and self._match_attributes(policy.resource_match, context.attributes.resource)
            and self._match_attributes(policy.environment_match, context.attributes.environment)
        )

    def _match_attributes(
        self,
        expected: dict[str, str | int | float | bool | tuple[str | int | float | bool, ...]],
        actual: dict[str, str | int | float | bool],
    ) -> bool:
        for key, expected_value in expected.items():
            if key not in actual:
                return False
            actual_value = actual[key]
            if isinstance(expected_value, tuple):
                if actual_value not in expected_value:
                    return False
            elif actual_value != expected_value:
                return False
        return True
