from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, Literal, cast

from astraauth.core.persistence.relational import (
    compile_sql,
    create_sync_database,
    upsert_sql,
)
from astraauth.idp.models import (
    ClaimAttributeMapping,
    ExternalIdentityLink,
    FederationAuditRecord,
    GroupRoleMapping,
    OIDCLoginState,
)
from astraauth.idp.store import (
    BaseIdentityLinkRepository,
    ClaimAttributeMappingRepository,
    FederationAuditRepository,
    GroupRoleMappingRepository,
    OIDCLoginStateRepository,
)

_LINK_COLUMNS = (
    "provider_id",
    "external_subject",
    "subject_id",
    "tenant_id",
    "created_at",
    "updated_at",
    "email",
    "email_verified",
    "claims_json",
)

ClaimTransform = Literal["string", "lower", "bool", "csv"]
AuditStatus = Literal["started", "succeeded", "failed"]


class SQLIdentityLinkRepository(BaseIdentityLinkRepository):
    def __init__(self, dsn: str) -> None:
        self._db = create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        conn = self._db.connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS idp_identity_links (
                provider_id TEXT NOT NULL,
                external_subject TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                email TEXT NULL,
                email_verified INTEGER NULL,
                claims_json TEXT NOT NULL,
                PRIMARY KEY (provider_id, external_subject, tenant_id)
            )
            """
        )
        conn.commit()

    def save(self, link: ExternalIdentityLink) -> None:
        statement = upsert_sql(
            table="idp_identity_links",
            columns=_LINK_COLUMNS,
            conflict_columns=("provider_id", "external_subject", "tenant_id"),
            dialect=self._db.dialect,
        )
        payload = {
            "provider_id": link.provider_id,
            "external_subject": link.external_subject,
            "subject_id": link.subject_id,
            "tenant_id": link.tenant_id,
            "created_at": link.created_at.isoformat(),
            "updated_at": link.updated_at.isoformat(),
            "email": link.email,
            "email_verified": None if link.email_verified is None else int(link.email_verified),
            "claims_json": json.dumps(link.claims),
        }
        compiled = compile_sql(statement, payload, self._db.dialect)
        conn = self._db.connection()
        conn.execute(compiled.sql, compiled.params)
        conn.commit()

    def get(
        self,
        *,
        provider_id: str,
        external_subject: str,
        tenant_id: str,
    ) -> ExternalIdentityLink | None:
        compiled = compile_sql(
            "SELECT * FROM idp_identity_links WHERE provider_id={{provider_id}} AND external_subject={{external_subject}} AND tenant_id={{tenant_id}}",
            {
                "provider_id": provider_id,
                "external_subject": external_subject,
                "tenant_id": tenant_id,
            },
            self._db.dialect,
        )
        row = self._db.connection().execute(compiled.sql, compiled.params).fetchone()
        return None if row is None else _link_from_row(dict(row))

    def _iter_links(self) -> Iterable[ExternalIdentityLink]:
        rows = self._db.connection().execute("SELECT * FROM idp_identity_links").fetchall()
        return tuple(_link_from_row(dict(row)) for row in rows)


class SQLGroupRoleMappingRepository(GroupRoleMappingRepository):
    def __init__(self, dsn: str) -> None:
        self._db = create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        conn = self._db.connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS idp_group_role_mappings (
                provider_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                external_group TEXT NOT NULL,
                role_name TEXT NOT NULL,
                PRIMARY KEY (provider_id, tenant_id, external_group, role_name)
            )
            """
        )
        conn.commit()

    def add(self, mapping: GroupRoleMapping) -> None:
        statement = upsert_sql(
            table="idp_group_role_mappings",
            columns=("provider_id", "tenant_id", "external_group", "role_name"),
            conflict_columns=("provider_id", "tenant_id", "external_group", "role_name"),
            dialect=self._db.dialect,
        )
        compiled = compile_sql(
            statement,
            {
                "provider_id": mapping.provider_id,
                "tenant_id": mapping.tenant_id,
                "external_group": mapping.external_group,
                "role_name": mapping.role_name,
            },
            self._db.dialect,
        )
        conn = self._db.connection()
        conn.execute(compiled.sql, compiled.params)
        conn.commit()

    def list_for_provider(self, *, provider_id: str, tenant_id: str) -> Iterable[GroupRoleMapping]:
        compiled = compile_sql(
            "SELECT * FROM idp_group_role_mappings WHERE provider_id={{provider_id}} AND tenant_id={{tenant_id}}",
            {"provider_id": provider_id, "tenant_id": tenant_id},
            self._db.dialect,
        )
        rows = self._db.connection().execute(compiled.sql, compiled.params).fetchall()
        return tuple(
            GroupRoleMapping(
                provider_id=str(row["provider_id"]),
                tenant_id=str(row["tenant_id"]),
                external_group=str(row["external_group"]),
                role_name=str(row["role_name"]),
            )
            for row in rows
        )


class SQLClaimAttributeMappingRepository(ClaimAttributeMappingRepository):
    def __init__(self, dsn: str) -> None:
        self._db = create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        conn = self._db.connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS idp_claim_attribute_mappings (
                provider_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                claim_name TEXT NOT NULL,
                attribute_name TEXT NOT NULL,
                required INTEGER NOT NULL,
                transform TEXT NOT NULL,
                PRIMARY KEY (provider_id, tenant_id, claim_name, attribute_name)
            )
            """
        )
        conn.commit()

    def add(self, mapping: ClaimAttributeMapping) -> None:
        statement = upsert_sql(
            table="idp_claim_attribute_mappings",
            columns=(
                "provider_id",
                "tenant_id",
                "claim_name",
                "attribute_name",
                "required",
                "transform",
            ),
            conflict_columns=("provider_id", "tenant_id", "claim_name", "attribute_name"),
            dialect=self._db.dialect,
        )
        compiled = compile_sql(
            statement,
            {
                "provider_id": mapping.provider_id,
                "tenant_id": mapping.tenant_id,
                "claim_name": mapping.claim_name,
                "attribute_name": mapping.attribute_name,
                "required": int(mapping.required),
                "transform": mapping.transform,
            },
            self._db.dialect,
        )
        conn = self._db.connection()
        conn.execute(compiled.sql, compiled.params)
        conn.commit()

    def list_for_provider(
        self,
        *,
        provider_id: str,
        tenant_id: str,
    ) -> Iterable[ClaimAttributeMapping]:
        compiled = compile_sql(
            "SELECT * FROM idp_claim_attribute_mappings WHERE provider_id={{provider_id}} AND tenant_id={{tenant_id}}",
            {"provider_id": provider_id, "tenant_id": tenant_id},
            self._db.dialect,
        )
        rows = self._db.connection().execute(compiled.sql, compiled.params).fetchall()
        return tuple(
            ClaimAttributeMapping(
                provider_id=str(row["provider_id"]),
                tenant_id=str(row["tenant_id"]),
                claim_name=str(row["claim_name"]),
                attribute_name=str(row["attribute_name"]),
                required=bool(row["required"]),
                transform=cast(ClaimTransform, row["transform"]),
            )
            for row in rows
        )


class SQLOIDCLoginStateRepository(OIDCLoginStateRepository):
    def __init__(self, dsn: str) -> None:
        self._db = create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        conn = self._db.connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS idp_oidc_login_states (
                state_id VARCHAR(255) NOT NULL PRIMARY KEY,
                provider_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_verifier TEXT NOT NULL,
                nonce TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        conn.commit()

    def save(self, state: OIDCLoginState) -> None:
        statement = upsert_sql(
            table="idp_oidc_login_states",
            columns=(
                "state_id",
                "provider_id",
                "tenant_id",
                "redirect_uri",
                "code_verifier",
                "nonce",
                "created_at",
                "expires_at",
            ),
            conflict_columns=("state_id",),
            dialect=self._db.dialect,
        )
        compiled = compile_sql(
            statement,
            {
                "state_id": state.state_id,
                "provider_id": state.provider_id,
                "tenant_id": state.tenant_id,
                "redirect_uri": state.redirect_uri,
                "code_verifier": state.code_verifier,
                "nonce": state.nonce,
                "created_at": state.created_at.isoformat(),
                "expires_at": state.expires_at.isoformat(),
            },
            self._db.dialect,
        )
        conn = self._db.connection()
        conn.execute(compiled.sql, compiled.params)
        conn.commit()

    def get(self, state_id: str) -> OIDCLoginState | None:
        compiled = compile_sql(
            "SELECT * FROM idp_oidc_login_states WHERE state_id={{state_id}}",
            {"state_id": state_id},
            self._db.dialect,
        )
        row = self._db.connection().execute(compiled.sql, compiled.params).fetchone()
        return None if row is None else _login_state_from_row(dict(row))

    def delete(self, state_id: str) -> None:
        compiled = compile_sql(
            "DELETE FROM idp_oidc_login_states WHERE state_id={{state_id}}",
            {"state_id": state_id},
            self._db.dialect,
        )
        conn = self._db.connection()
        conn.execute(compiled.sql, compiled.params)
        conn.commit()


class SQLFederationAuditRepository(FederationAuditRepository):
    def __init__(self, dsn: str) -> None:
        self._db = create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        conn = self._db.connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS idp_federation_audit (
                audit_id VARCHAR(255) NOT NULL PRIMARY KEY,
                event_type TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                state_id TEXT NULL,
                client_id TEXT NULL,
                subject_id TEXT NULL,
                external_subject TEXT NULL,
                reason TEXT NULL,
                details_json TEXT NOT NULL
            )
            """
        )
        conn.commit()

    def save(self, record: FederationAuditRecord) -> None:
        statement = upsert_sql(
            table="idp_federation_audit",
            columns=(
                "audit_id",
                "event_type",
                "provider_id",
                "tenant_id",
                "status",
                "created_at",
                "state_id",
                "client_id",
                "subject_id",
                "external_subject",
                "reason",
                "details_json",
            ),
            conflict_columns=("audit_id",),
            dialect=self._db.dialect,
        )
        compiled = compile_sql(
            statement,
            {
                "audit_id": record.audit_id,
                "event_type": record.event_type,
                "provider_id": record.provider_id,
                "tenant_id": record.tenant_id,
                "status": record.status,
                "created_at": record.created_at.isoformat(),
                "state_id": record.state_id,
                "client_id": record.client_id,
                "subject_id": record.subject_id,
                "external_subject": record.external_subject,
                "reason": record.reason,
                "details_json": json.dumps(record.details),
            },
            self._db.dialect,
        )
        conn = self._db.connection()
        conn.execute(compiled.sql, compiled.params)
        conn.commit()

    def list_for_tenant(
        self, *, tenant_id: str, provider_id: str | None = None
    ) -> Iterable[FederationAuditRecord]:
        if provider_id is None:
            compiled = compile_sql(
                "SELECT * FROM idp_federation_audit WHERE tenant_id={{tenant_id}} ORDER BY created_at",
                {"tenant_id": tenant_id},
                self._db.dialect,
            )
        else:
            compiled = compile_sql(
                "SELECT * FROM idp_federation_audit WHERE tenant_id={{tenant_id}} AND provider_id={{provider_id}} ORDER BY created_at",
                {"tenant_id": tenant_id, "provider_id": provider_id},
                self._db.dialect,
            )
        rows = self._db.connection().execute(compiled.sql, compiled.params).fetchall()
        return tuple(_audit_from_row(dict(row)) for row in rows)


def _link_from_row(row: dict[str, Any]) -> ExternalIdentityLink:
    return ExternalIdentityLink(
        provider_id=str(row["provider_id"]),
        external_subject=str(row["external_subject"]),
        subject_id=str(row["subject_id"]),
        tenant_id=str(row["tenant_id"]),
        created_at=datetime.fromisoformat(str(row["created_at"])).astimezone(UTC),
        updated_at=datetime.fromisoformat(str(row["updated_at"])).astimezone(UTC),
        email=str(row["email"]) if row["email"] is not None else None,
        email_verified=bool(row["email_verified"]) if row["email_verified"] is not None else None,
        claims=cast(dict[str, Any], json.loads(str(row["claims_json"]))),
    )


def _login_state_from_row(row: dict[str, Any]) -> OIDCLoginState:
    return OIDCLoginState(
        state_id=str(row["state_id"]),
        provider_id=str(row["provider_id"]),
        tenant_id=str(row["tenant_id"]),
        redirect_uri=str(row["redirect_uri"]),
        code_verifier=str(row["code_verifier"]),
        nonce=str(row["nonce"]),
        created_at=datetime.fromisoformat(str(row["created_at"])).astimezone(UTC),
        expires_at=datetime.fromisoformat(str(row["expires_at"])).astimezone(UTC),
    )


def _audit_from_row(row: dict[str, Any]) -> FederationAuditRecord:
    return FederationAuditRecord(
        audit_id=str(row["audit_id"]),
        event_type=str(row["event_type"]),
        provider_id=str(row["provider_id"]),
        tenant_id=str(row["tenant_id"]),
        status=cast(AuditStatus, row["status"]),
        created_at=datetime.fromisoformat(str(row["created_at"])).astimezone(UTC),
        state_id=str(row["state_id"]) if row["state_id"] is not None else None,
        client_id=str(row["client_id"]) if row["client_id"] is not None else None,
        subject_id=str(row["subject_id"]) if row["subject_id"] is not None else None,
        external_subject=str(row["external_subject"])
        if row["external_subject"] is not None
        else None,
        reason=str(row["reason"]) if row["reason"] is not None else None,
        details=cast(dict[str, str | int | float | bool], json.loads(str(row["details_json"]))),
    )
