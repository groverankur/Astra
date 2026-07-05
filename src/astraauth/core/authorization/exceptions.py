from __future__ import annotations


class AuthorizationError(Exception):
    """
    Base class for authorization failures.
    """


class PermissionDeniedError(AuthorizationError):
    """
    Raised when a subject lacks a required permission.
    """


class RoleNotFoundError(AuthorizationError):
    """
    Raised when a referenced role does not exist.
    """


class TenantIsolationError(AuthorizationError):
    """
    Raised when tenant context is invalid or missing.
    """


class StepUpRequiredError(AuthorizationError):
    """
    Raised when MFA step-up is required before allowing access.
    """
