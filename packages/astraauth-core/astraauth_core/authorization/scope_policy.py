from __future__ import annotations

from typing import Protocol

from astraauth_core.oauth.errors import InvalidGrantError


class ScopePolicy(Protocol):
    def filter_scopes(
        self,
        *,
        requested_scopes: set[str],
        permissions: set[str],
    ) -> set[str]: ...


class DefaultScopePolicy:
    """
    Maps permissions to OAuth scopes.

    strict_mode:
        If True, any unauthorized requested scope causes failure.
        If False, unauthorized scopes are silently dropped.
    """

    def __init__(
        self,
        permission_scope_map: dict[str, str],
        *,
        strict_mode: bool = True,
    ) -> None:
        self._permission_scope_map = permission_scope_map
        self._strict_mode = strict_mode

    def filter_scopes(
        self,
        *,
        requested_scopes: set[str],
        permissions: set[str],
    ) -> set[str]:
        allowed_scopes = {
            self._permission_scope_map[p] for p in permissions if p in self._permission_scope_map
        }

        unauthorized = requested_scopes - allowed_scopes

        if self._strict_mode and unauthorized:
            raise InvalidGrantError(
                f"Unauthorized scope(s) requested: {', '.join(sorted(unauthorized))}"
            )

        return requested_scopes & allowed_scopes
