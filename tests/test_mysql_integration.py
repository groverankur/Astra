from __future__ import annotations

import os

import pytest

from astraauth.core.config.settings import PersistenceConfig, RelationalStoreConfig
from astraauth.core.mfa import MFAChallenge, MFAFactorType, SQLMFAChallengeStore
from astraauth.core.plugins import SQLTenantPluginRegistryStore
from astraauth.core.sessions import Session, SQLSessionStore


def _mysql_sync_dsn() -> str:
    dsn = os.getenv("ASTRAAUTH_TEST_MYSQL_DSN")
    if not dsn:
        pytest.skip("set ASTRAAUTH_TEST_MYSQL_DSN to run MySQL integration tests")
    return dsn


def test_mysql_persistence_settings_can_be_overridden_by_explicit_dsn() -> None:
    dsn = "mysql://astraauth:secret@localhost:3306/astraauth_test"
    settings = PersistenceConfig(
        default_database=RelationalStoreConfig.mysql(database="ignored"),
        mysql_test_dsn=dsn,
    )

    assert settings.mysql_test_dsn == dsn


@pytest.mark.integration
def test_mysql_session_store_roundtrip() -> None:
    store = SQLSessionStore(_mysql_sync_dsn())
    session = Session.create(
        subject_id="u-mysql",
        tenant_id="t-mysql",
        client_id="c-mysql",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )

    store.save(session)
    fetched = store.get(session.session_id)

    assert fetched is not None
    assert fetched.session_id == session.session_id
    assert fetched.tenant_id == "t-mysql"


@pytest.mark.integration
def test_mysql_mfa_and_plugin_roundtrip() -> None:
    dsn = _mysql_sync_dsn()
    challenge_store = SQLMFAChallengeStore(dsn)
    plugin_store = SQLTenantPluginRegistryStore(dsn)

    challenge = MFAChallenge.issue(
        session_id="s-mysql",
        subject_id="u-mysql",
        tenant_id="t-mysql",
        factor_type=MFAFactorType.TOTP,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    challenge_store.save(challenge)
    assert challenge_store.get(challenge.challenge_id) is not None

    plugin_store.enable(tenant_id="t-mysql", plugin_name="risk")
    assert plugin_store.enabled_for_tenant(tenant_id="t-mysql") == {"risk"}
