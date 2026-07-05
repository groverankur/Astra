from collections.abc import Iterable

from astraauth.core.config.settings import AuthConfig
from astraauth.core.events.inmemory import InMemoryEventBus
from astraauth.core.sessions.models import Session
from astraauth.core.sessions.redis_store import RedisSessionStore
from astraauth.core.sessions.services import (
    issue_session_and_refresh_token,
    logout_by_refresh_token,
    rotate_refresh_token,
)
from astraauth.core.sessions.sql_store import SQLSessionStore
from astraauth.core.token.token_manager import TokenKeyManager


class FakeRedisClient:
    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def get(self, key: str) -> str | bytes | None:
        return self._data.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        _ = ex
        self._data[key] = value

    def scan_iter(self, match: str) -> Iterable[str | bytes]:
        prefix = match.removesuffix("*")
        for key in self._data:
            if key.startswith(prefix):
                yield key


def test_sql_session_store_roundtrip() -> None:
    store = SQLSessionStore(":memory:")
    session = Session.create(
        subject_id="u1",
        tenant_id="t1",
        client_id="c1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    session.upgrade_authentication(target_acr=2, methods={"pwd", "totp"})

    store.save(session)
    fetched = store.get(session.session_id)
    assert fetched is not None
    assert fetched.session_id == session.session_id
    assert fetched.tenant_id == "t1"
    assert fetched.acr == 2
    assert set(fetched.amr) == {"pwd", "totp"}
    assert fetched.upgraded_at is not None

    active = list(store.list_active_for_subject("u1"))
    assert len(active) == 1
    store.revoke(session.session_id)
    assert list(store.list_active_for_subject("u1")) == []


def test_redis_session_store_roundtrip() -> None:
    store = RedisSessionStore(FakeRedisClient())
    session = Session.create(
        subject_id="u1",
        tenant_id="t1",
        client_id="c1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    session.upgrade_authentication(target_acr=2, methods={"pwd", "totp"})

    store.save(session)
    fetched = store.get(session.session_id)
    assert fetched is not None
    assert fetched.session_id == session.session_id
    assert fetched.acr == 2
    assert set(fetched.amr) == {"pwd", "totp"}

    active = list(store.list_active_for_subject("u1"))
    assert len(active) == 1
    store.revoke(session.session_id)
    assert list(store.list_active_for_subject("u1")) == []


def test_session_events_are_emitted_for_issue_rotate_revoke() -> None:
    token_manager = TokenKeyManager(AuthConfig())
    store = SQLSessionStore(":memory:")
    bus = InMemoryEventBus()
    seen: list[tuple[str, dict[str, object]]] = []

    for topic in ["session.created", "token.issued", "session.rotated", "session.revoked"]:
        bus.subscribe(topic, lambda payload, t=topic: seen.append((t, payload)))

    session, refresh_token = issue_session_and_refresh_token(
        subject_id="u1",
        client_id="c1",
        tenant_id="t1",
        requested_scopes={"openid"},
        session_store=store,
        token_manager=token_manager,
        session_ttl_seconds=300,
        event_bus=bus,
    )
    assert session.tenant_id == "t1"

    rotate_refresh_token(
        refresh_token=refresh_token,
        session_store=store,
        token_manager=token_manager,
        session_ttl_seconds=300,
        event_bus=bus,
    )

    logout_by_refresh_token(
        refresh_token=refresh_token,
        session_store=store,
        token_manager=token_manager,
        event_bus=bus,
    )

    topics = [topic for topic, _ in seen]
    assert "session.created" in topics
    assert "token.issued" in topics
    assert "session.rotated" in topics
    assert "session.revoked" in topics
    assert any(payload.get("tid") == "t1" for _, payload in seen if "tid" in payload)
