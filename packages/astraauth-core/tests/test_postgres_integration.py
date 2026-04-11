from __future__ import annotations

import os

import pytest
from astraauth_core.config.settings import PersistenceConfig, RelationalStoreConfig
from astraauth_core.mfa import MFAChallenge, MFAFactorType, SQLMFAChallengeStore
from astraauth_core.plugins import SQLTenantPluginRegistryStore
from astraauth_core.sessions import Session, SQLSessionStore


def _postgres_sync_dsn() -> str:
    dsn = os.getenv("ASTRAAUTH_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("set ASTRAAUTH_TEST_POSTGRES_DSN to run Postgres integration tests")
    return dsn


def test_postgres_persistence_settings_can_be_overridden_by_explicit_dsn() -> None:
    dsn = "postgresql://astraauth:secret@localhost:5432/astraauth_test"
    settings = PersistenceConfig(
        default_database=RelationalStoreConfig.postgres(database="ignored"),
        postgres_test_dsn=dsn,
    )

    assert settings.postgres_test_dsn == dsn


@pytest.mark.integration
def test_postgres_session_store_roundtrip() -> None:
    store = SQLSessionStore(_postgres_sync_dsn())
    session = Session.create(
        subject_id="u-postgres",
        tenant_id="t-postgres",
        client_id="c-postgres",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )

    store.save(session)
    fetched = store.get(session.session_id)

    assert fetched is not None
    assert fetched.session_id == session.session_id
    assert fetched.tenant_id == "t-postgres"


@pytest.mark.integration
def test_postgres_mfa_and_plugin_roundtrip() -> None:
    dsn = _postgres_sync_dsn()
    challenge_store = SQLMFAChallengeStore(dsn)
    plugin_store = SQLTenantPluginRegistryStore(dsn)

    challenge = MFAChallenge.issue(
        session_id="s-postgres",
        subject_id="u-postgres",
        tenant_id="t-postgres",
        factor_type=MFAFactorType.TOTP,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    challenge_store.save(challenge)
    assert challenge_store.get(challenge.challenge_id) is not None

    plugin_store.enable(tenant_id="t-postgres", plugin_name="risk")
    assert plugin_store.enabled_for_tenant(tenant_id="t-postgres") == {"risk"}
