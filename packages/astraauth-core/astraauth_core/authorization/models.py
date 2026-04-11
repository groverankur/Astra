from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

PolicyAttributeValue = str | int | float | bool
PolicyAttributeMap = dict[str, PolicyAttributeValue]
PolicyMatchMap = dict[str, PolicyAttributeValue | tuple[PolicyAttributeValue, ...]]
PolicyRuleMode = Literal["constraint", "allow"]


@dataclass(frozen=True)
class Permission:
    name: str  # e.g. "user:read"


@dataclass(frozen=True)
class Role:
    name: str
    permissions: set[str]  # permission names


@dataclass(frozen=True)
class TenantRoleAssignment:
    subject_id: str
    tenant_id: str
    roles: set[str]


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"


@dataclass(frozen=True)
class AuthorizationAttributes:
    subject: PolicyAttributeMap = field(default_factory=dict)
    resource: PolicyAttributeMap = field(default_factory=dict)
    environment: PolicyAttributeMap = field(default_factory=dict)


@dataclass(frozen=True)
class AuthorizationContext:
    subject_id: str
    tenant_id: str
    permission: str
    current_acr: int = 1
    required_acr: int | None = None
    session_id: str | None = None
    attributes: AuthorizationAttributes = field(default_factory=AuthorizationAttributes)


@dataclass(frozen=True)
class PolicyRule:
    policy_id: str
    permission: str
    effect: Decision
    tenant_id: str | None = None
    required_acr: int | None = None
    mode: PolicyRuleMode = "constraint"
    subject_match: PolicyMatchMap = field(default_factory=dict)
    resource_match: PolicyMatchMap = field(default_factory=dict)
    environment_match: PolicyMatchMap = field(default_factory=dict)
    reasons: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PolicyMatch:
    policy_id: str
    effect: Decision
    reasons: tuple[str, ...]
    required_acr: int | None = None


@dataclass(frozen=True)
class AuthorizationDecision:
    decision: Decision
    reasons: tuple[str, ...]
    required_acr: int | None = None
    matched_policies: tuple[PolicyMatch, ...] = ()
