from __future__ import annotations

from pydantic import BaseModel


class TenantWorkspace(BaseModel):
    tenant_id: str
    name: str
    database_url: str | None = None
    max_users: int = 1000
    max_relation_tuples: int = 10000
    is_active: bool = True
