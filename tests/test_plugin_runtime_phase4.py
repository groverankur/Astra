import time
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from astraauth.plugins.contracts import (
    ColumnExtension,
    EndpointExecutionReport,
    EndpointExtension,
    HookErrorClass,
    HookName,
    PluginExecutionError,
    PluginManifest,
    TableExtension,
)
from astraauth.plugins.runtime import PluginRuntime, PluginTrustPolicy, sign_plugin_manifest


def _rsa_keypair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@dataclass
class DummyPlugin:
    name: str
    order: int
    _hooks: dict[HookName, Any]
    _endpoints: tuple[EndpointExtension, ...] = ()
    _tables: tuple[TableExtension, ...] = ()
    _columns: tuple[ColumnExtension, ...] = ()

    def hooks(self) -> dict[HookName, Any]:
        return self._hooks

    def register_endpoints(self) -> tuple[EndpointExtension, ...]:
        return self._endpoints

    def register_tables(self) -> tuple[TableExtension, ...]:
        return self._tables

    def register_columns(self) -> tuple[ColumnExtension, ...]:
        return self._columns


def test_deterministic_hook_execution_order_per_tenant() -> None:
    runtime = PluginRuntime()
    seen: list[str] = []

    p1 = DummyPlugin(
        name="risk",
        order=20,
        _hooks={"auth.pre_authenticate": lambda p: seen.append("risk") or None},
    )
    p2 = DummyPlugin(
        name="geo",
        order=10,
        _hooks={"auth.pre_authenticate": lambda p: seen.append("geo") or None},
    )

    runtime.register(p1)
    runtime.register(p2)
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="risk")
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="geo")

    report = runtime.execute_hook(
        hook="auth.pre_authenticate",
        tenant_id="t1",
        payload={"x": 1},
    )

    assert seen == ["geo", "risk"]
    assert report.executed_plugins == ("geo", "risk")


def test_hook_failure_modes_fail_open_and_fail_closed() -> None:
    runtime = PluginRuntime()
    runtime.register(
        DummyPlugin(
            name="bad",
            order=1,
            _hooks={"auth.pre_authorize": lambda p: (_ for _ in ()).throw(ValueError("boom"))},
        )
    )
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="bad")

    report = runtime.execute_hook(
        hook="auth.pre_authorize",
        tenant_id="t1",
        payload={},
        fail_closed=False,
    )
    assert report.errors

    with pytest.raises(PluginExecutionError):
        runtime.execute_hook(
            hook="auth.pre_authorize",
            tenant_id="t1",
            payload={},
            fail_closed=True,
        )


def test_plugin_allowlist_denies_unlisted_plugin_and_audits() -> None:
    runtime = PluginRuntime(
        trust_policy=PluginTrustPolicy(allowed_plugins=frozenset({"geo"})),
    )
    plugin = DummyPlugin(name="risk", order=1, _hooks={})

    with pytest.raises(ValueError, match="allowlist"):
        runtime.register(plugin)

    audit = runtime.audit_records()
    assert audit[-1].execution_type == "lifecycle"
    assert audit[-1].target == "register"
    assert audit[-1].status == "failed"
    assert audit[-1].error_classification == HookErrorClass.TRUST.value


def test_plugin_register_requires_signed_manifest_when_configured() -> None:
    runtime = PluginRuntime(
        trust_policy=PluginTrustPolicy(
            allowed_plugins=frozenset({"geo"}),
            require_signatures=True,
        ),
    )
    plugin = DummyPlugin(name="geo", order=1, _hooks={})

    with pytest.raises(ValueError, match="signed manifest"):
        runtime.register(plugin)


def test_plugin_register_accepts_trusted_signed_manifest_and_audits_lifecycle() -> None:
    private_pem, public_pem = _rsa_keypair()
    manifest = sign_plugin_manifest(
        PluginManifest(
            name="geo",
            version="1.0.0",
            digest="sha256:abc",
            hooks=("auth.pre_authenticate",),
            endpoints=("/auth/ext/geo/health",),
            requested_permissions=("tenant.signal.read",),
            source_fingerprint="pkg:geo@sha256:source",
        ),
        private_pem,
    )
    runtime = PluginRuntime(
        trust_policy=PluginTrustPolicy(
            allowed_plugins=frozenset({"geo"}),
            require_signatures=True,
            trusted_public_keys=(public_pem,),
        ),
    )

    runtime.register(DummyPlugin(name="geo", order=1, _hooks={}), manifest=manifest)
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="geo")
    runtime.disable_for_tenant(tenant_id="t1", plugin_name="geo")

    lifecycle = [
        record for record in runtime.audit_records() if record.execution_type == "lifecycle"
    ]
    assert [(record.target, record.status) for record in lifecycle] == [
        ("register", "succeeded"),
        ("enable", "succeeded"),
        ("disable", "succeeded"),
    ]


def test_plugin_manifest_policy_rejects_unapproved_version_digest_and_source() -> None:
    runtime = PluginRuntime(
        trust_policy=PluginTrustPolicy(
            allowed_plugins=frozenset({"geo"}),
            allowed_versions={"geo": ">=2.0,<3.0"},
            allowed_digests={"geo": frozenset({"sha256:expected"})},
            allowed_source_fingerprints={"geo": frozenset({"pkg:geo@sha256:expected"})},
        ),
    )

    with pytest.raises(ValueError, match="outside allowed range"):
        runtime.register(
            DummyPlugin(name="geo", order=1, _hooks={}),
            manifest=PluginManifest(
                name="geo",
                version="1.0.0",
                digest="sha256:expected",
                source_fingerprint="pkg:geo@sha256:expected",
            ),
        )

    with pytest.raises(ValueError, match="digest is not allowed"):
        runtime.register(
            DummyPlugin(name="geo", order=1, _hooks={}),
            manifest=PluginManifest(
                name="geo",
                version="2.1.0",
                digest="sha256:unexpected",
                source_fingerprint="pkg:geo@sha256:expected",
            ),
        )

    with pytest.raises(ValueError, match="source fingerprint is not allowed"):
        runtime.register(
            DummyPlugin(name="geo", order=1, _hooks={}),
            manifest=PluginManifest(
                name="geo",
                version="2.1.0",
                digest="sha256:expected",
                source_fingerprint="pkg:geo@sha256:unexpected",
            ),
        )


def test_tenant_plugin_policy_rejects_unapproved_enablement_and_audits() -> None:
    runtime = PluginRuntime(
        trust_policy=PluginTrustPolicy(
            allowed_plugins=frozenset({"geo"}),
            tenant_allowed_plugins={"tenant-1": frozenset({"risk"})},
        ),
    )

    runtime.register(DummyPlugin(name="geo", order=1, _hooks={}))

    with pytest.raises(ValueError, match="not allowed for tenant"):
        runtime.enable_for_tenant(tenant_id="tenant-1", plugin_name="geo")

    audit = runtime.audit_records()
    assert audit[-1].execution_type == "lifecycle"
    assert audit[-1].target == "enable"
    assert audit[-1].status == "failed"
    assert audit[-1].error_classification == HookErrorClass.TRUST.value


def test_endpoint_extension_must_be_namespaced_and_not_core() -> None:
    runtime = PluginRuntime()
    runtime.register(
        DummyPlugin(
            name="risk",
            order=1,
            _hooks={},
            _endpoints=(EndpointExtension("risk", "/token", ("GET",), lambda p: {"ok": True}),),
        )
    )
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="risk")

    with pytest.raises(ValueError):
        runtime.endpoint_extensions(tenant_id="t1")


def test_endpoint_extension_rejects_duplicate_route_and_method() -> None:
    runtime = PluginRuntime()
    runtime.register(
        DummyPlugin(
            name="geo",
            order=1,
            _hooks={},
            _endpoints=(
                EndpointExtension("geo", "/auth/ext/geo/health", ("GET",), lambda p: {"ok": True}),
            ),
        )
    )
    runtime.register(
        DummyPlugin(
            name="geo-dup",
            order=2,
            _hooks={},
            _endpoints=(
                EndpointExtension(
                    "geo-dup", "/auth/ext/geo/health", ("GET",), lambda p: {"ok": True}
                ),
            ),
        )
    )
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="geo")
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="geo-dup")

    with pytest.raises(ValueError):
        runtime.endpoint_extensions(tenant_id="t1")


def test_table_and_column_extension_rules() -> None:
    runtime = PluginRuntime(allowed_column_tables={"plugin_risk_extension"})
    runtime.register(
        DummyPlugin(
            name="risk",
            order=1,
            _hooks={},
            _tables=(TableExtension("risk", "plugin_risk_events"),),
            _columns=(ColumnExtension("risk", "plugin_risk_extension", "risk_score"),),
        )
    )
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="risk")

    tables = runtime.table_extensions(tenant_id="t1")
    columns = runtime.column_extensions(tenant_id="t1")
    assert tables[0].table_name == "plugin_risk_events"
    assert columns[0].column_name == "risk_score"


def test_timeout_and_error_classification() -> None:
    runtime = PluginRuntime(default_timeout_ms=10)

    @dataclass
    class SlowPlugin:
        name: str = "slow"
        order: int = 1
        timeout_ms: int = 5

        def hooks(self) -> dict[HookName, Any]:
            return {"auth.post_authorize": self._slow_hook}

        def register_endpoints(self) -> tuple[EndpointExtension, ...]:
            return ()

        def register_tables(self) -> tuple[TableExtension, ...]:
            return ()

        def register_columns(self) -> tuple[ColumnExtension, ...]:
            return ()

        def _slow_hook(self, payload: dict[str, Any]) -> dict[str, Any]:
            time.sleep(0.05)
            return payload

    runtime.register(SlowPlugin())
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="slow")

    report = runtime.execute_hook(
        hook="auth.post_authorize",
        tenant_id="t1",
        payload={},
        fail_closed=False,
    )
    assert report.errors
    assert report.errors[0].classification == HookErrorClass.TIMEOUT


def test_timeout_cap_returns_promptly_without_waiting_for_worker_completion() -> None:
    runtime = PluginRuntime(
        default_timeout_ms=1000,
        trust_policy=PluginTrustPolicy(max_timeout_ms=10),
    )

    @dataclass
    class SlowPlugin:
        name: str = "slow"
        order: int = 1
        timeout_ms: int = 1000

        def hooks(self) -> dict[HookName, Any]:
            return {"auth.post_authorize": self._slow_hook}

        def register_endpoints(self) -> tuple[EndpointExtension, ...]:
            return ()

        def register_tables(self) -> tuple[TableExtension, ...]:
            return ()

        def register_columns(self) -> tuple[ColumnExtension, ...]:
            return ()

        def _slow_hook(self, payload: dict[str, Any]) -> dict[str, Any]:
            time.sleep(0.25)
            return payload

    runtime.register(SlowPlugin())
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="slow")

    started = time.monotonic()
    report = runtime.execute_hook(
        hook="auth.post_authorize",
        tenant_id="t1",
        payload={},
        fail_closed=False,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 0.15
    assert report.errors[0].classification == HookErrorClass.TIMEOUT
    assert "10ms" in (runtime.audit_records()[-1].message or "")


def test_endpoint_invocation_records_audit_and_returns_report() -> None:
    runtime = PluginRuntime()
    runtime.register(
        DummyPlugin(
            name="geo",
            order=1,
            _hooks={},
            _endpoints=(
                EndpointExtension(
                    "geo", "/auth/ext/geo/health", ("GET",), lambda p: {"plugin": "geo"}
                ),
            ),
        )
    )
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="geo")
    extension = runtime.endpoint_extensions(tenant_id="t1")[0]

    report = runtime.invoke_endpoint(tenant_id="t1", extension=extension, payload={"method": "GET"})

    assert isinstance(report, EndpointExecutionReport)
    assert report.result == {"plugin": "geo"}
    audit = runtime.audit_records()
    assert audit[-1].execution_type == "endpoint"
    assert audit[-1].status == "succeeded"


def test_endpoint_invocation_fail_closed_is_audited() -> None:
    runtime = PluginRuntime()
    runtime.register(
        DummyPlugin(
            name="bad",
            order=1,
            _hooks={},
            _endpoints=(
                EndpointExtension(
                    "bad",
                    "/auth/ext/bad/fail",
                    ("GET",),
                    lambda p: (_ for _ in ()).throw(ValueError("nope")),
                ),
            ),
        )
    )
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="bad")
    extension = runtime.endpoint_extensions(tenant_id="t1")[0]

    with pytest.raises(PluginExecutionError):
        runtime.invoke_endpoint(tenant_id="t1", extension=extension, payload={}, fail_closed=True)

    audit = runtime.audit_records()
    assert audit[-1].execution_type == "endpoint"
    assert audit[-1].status == "failed"
    assert audit[-1].error_classification == HookErrorClass.VALIDATION.value
