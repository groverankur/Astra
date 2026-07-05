from datetime import UTC, datetime, timedelta

import pytest

from astraauth.core.mfa import AsyncSQLMFAChallengeStore, MFAChallenge, MFAFactorType
from astraauth.core.plugins import AsyncSQLTenantPluginRegistryStore
from astraauth.core.sessions import AsyncSQLSessionStore, Session


@pytest.mark.asyncio
async def test_async_sql_session_store_roundtrip() -> None:
    store = AsyncSQLSessionStore(":memory:")
    await store.ensure_schema()
    session = Session.create(
        subject_id="u1",
        tenant_id="t1",
        client_id="c1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )

    await store.save(session)
    fetched = await store.get(session.session_id)

    assert fetched is not None
    assert fetched.session_id == session.session_id
    assert fetched.tenant_id == "t1"

    await store.revoke(session.session_id)
    revoked = await store.get(session.session_id)
    assert revoked is not None
    assert revoked.revoked is True
    await store.close()


@pytest.mark.asyncio
async def test_async_sql_mfa_challenge_store_roundtrip() -> None:
    store = AsyncSQLMFAChallengeStore(":memory:")
    await store.ensure_schema()
    challenge = MFAChallenge(
        challenge_id="ch_1",
        session_id="s1",
        subject_id="u1",
        tenant_id="t1",
        factor_type=MFAFactorType.TOTP,
        required_acr=2,
        purpose="step_up",
        created_at=datetime.now(tz=UTC),
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
    )

    await store.save(challenge)
    fetched = await store.get(challenge.challenge_id)

    assert fetched is not None
    assert fetched.challenge_id == challenge.challenge_id
    assert fetched.factor_type == MFAFactorType.TOTP
    await store.close()


@pytest.mark.asyncio
async def test_async_sql_plugin_registry_roundtrip() -> None:
    store = AsyncSQLTenantPluginRegistryStore(":memory:")
    await store.ensure_schema()

    await store.enable(tenant_id="t1", plugin_name="geo")
    await store.enable(tenant_id="t1", plugin_name="audit")
    await store.enable(tenant_id="t2", plugin_name="risk")

    assert await store.enabled_for_tenant(tenant_id="t1") == {"geo", "audit"}
    assert await store.all_tenants() == {"t1": {"geo", "audit"}, "t2": {"risk"}}

    await store.disable(tenant_id="t1", plugin_name="geo")
    assert await store.enabled_for_tenant(tenant_id="t1") == {"audit"}
    await store.close()
