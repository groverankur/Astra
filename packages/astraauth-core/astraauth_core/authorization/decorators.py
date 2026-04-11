from collections.abc import Callable
from functools import wraps
from typing import Any, Protocol

from astraauth_core.authorization.exceptions import PermissionDeniedError


class PermissionEngine(Protocol):
    def has_permission(self, subject_id: Any, tenant_id: Any, permission: str) -> bool: ...


def require_permission(
    engine: PermissionEngine, permission: str
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            subject_id: Any = kwargs.get("subject_id")
            tenant_id: Any = kwargs.get("tenant_id")

            if not engine.has_permission(
                subject_id=subject_id,
                tenant_id=tenant_id,
                permission=permission,
            ):
                raise PermissionDeniedError("Forbidden")

            return fn(*args, **kwargs)

        return wrapper

    return decorator
