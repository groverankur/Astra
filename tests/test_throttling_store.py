from pathlib import Path

import pytest

from astraauth.core.security import SharedThrottleStore


def test_shared_throttle_store_shares_state_across_instances(workspace_tmp_path: Path) -> None:
    dsn = str(workspace_tmp_path / "throttle.db")
    first = SharedThrottleStore(dsn)
    second = SharedThrottleStore(dsn)

    assert (
        first.record(
            bucket="login|127.0.0.1|tenant|user",
            max_events=1,
            window_seconds=300.0,
            block_seconds=600.0,
            now=1000.0,
        )
        == 0
    )
    assert (
        second.record(
            bucket="login|127.0.0.1|tenant|user",
            max_events=1,
            window_seconds=300.0,
            block_seconds=600.0,
            now=1001.0,
        )
        == 600
    )
    assert (
        first.retry_after(
            bucket="login|127.0.0.1|tenant|user",
            window_seconds=300.0,
            now=1002.0,
        )
        >= 1
    )


def test_shared_throttle_store_reset_clears_shared_bucket(workspace_tmp_path: Path) -> None:
    dsn = str(workspace_tmp_path / "throttle.db")
    first = SharedThrottleStore(dsn)
    second = SharedThrottleStore(dsn)

    first.record(
        bucket="mfa|127.0.0.1|challenge",
        max_events=1,
        window_seconds=300.0,
        block_seconds=600.0,
        now=1000.0,
    )
    first.record(
        bucket="mfa|127.0.0.1|challenge",
        max_events=1,
        window_seconds=300.0,
        block_seconds=600.0,
        now=1001.0,
    )
    second.reset(bucket="mfa|127.0.0.1|challenge")

    assert (
        first.retry_after(
            bucket="mfa|127.0.0.1|challenge",
            window_seconds=300.0,
            now=1002.0,
        )
        == 0
    )


def test_shared_throttle_store_snapshot_redacts_bucket_identity(workspace_tmp_path: Path) -> None:
    dsn = str(workspace_tmp_path / "throttle.db")
    store = SharedThrottleStore(dsn)
    store.record(
        bucket="oauth-token|127.0.0.1|tenant-1|alice",
        max_events=1,
        window_seconds=300.0,
        block_seconds=600.0,
        now=1000.0,
    )
    store.record(
        bucket="oauth-token|127.0.0.1|tenant-1|alice",
        max_events=1,
        window_seconds=300.0,
        block_seconds=600.0,
        now=1001.0,
    )

    snapshot = store.snapshot(now=1002.0)

    assert snapshot.storage_kind == "sqlite"
    assert snapshot.blocked_bucket_count == 1
    assert snapshot.buckets[0].scope == "oauth-token"
    assert snapshot.buckets[0].fingerprint
    assert snapshot.buckets[0].retry_after_seconds >= 1


def test_shared_throttle_store_rejects_unsafe_table_name(workspace_tmp_path: Path) -> None:
    dsn = str(workspace_tmp_path / "throttle.db")
    with pytest.raises(ValueError, match="Invalid SQL identifier"):
        SharedThrottleStore(dsn, table_name="astraauth_throttle_state; DROP TABLE sessions")
