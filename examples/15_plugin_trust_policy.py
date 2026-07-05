from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from astraauth_plugins import (
    EndpointExtension,
    HookName,
    PluginManifest,
    PluginRuntime,
    PluginTrustPolicy,
)

TENANT_ID = "tenant-1"


class DemoTrustedPlugin:
    name = "trusted-demo"
    order = 10

    def hooks(self) -> Mapping[HookName, Any]:
        return {"auth.post_authenticate": lambda payload: {"trusted_demo_seen": True, **payload}}

    def register_endpoints(self) -> Sequence[EndpointExtension]:
        return ()

    def register_tables(self) -> Sequence[Any]:
        return ()

    def register_columns(self) -> Sequence[Any]:
        return ()


def main() -> None:
    trust_policy = PluginTrustPolicy(
        allowed_plugins=frozenset({"trusted-demo"}),
        allowed_versions={"trusted-demo": ">=1.0,<2.0"},
        allowed_digests={"trusted-demo": frozenset({"sha256:demo-only-digest"})},
        tenant_allowed_plugins={TENANT_ID: frozenset({"trusted-demo"})},
        require_signatures=False,
        max_timeout_ms=500,
    )
    runtime = PluginRuntime(trust_policy=trust_policy)
    manifest = PluginManifest(
        name="trusted-demo",
        version="1.0.0",
        digest="sha256:demo-only-digest",
        hooks=("auth.post_authenticate",),
    )
    runtime.register(DemoTrustedPlugin(), manifest=manifest)
    runtime.enable_for_tenant(tenant_id=TENANT_ID, plugin_name="trusted-demo")

    report = runtime.execute_hook(
        hook="auth.post_authenticate",
        tenant_id=TENANT_ID,
        payload={"subject_id": "user-1"},
    )

    print(f"executed_plugins={report.executed_plugins}")
    print(f"payload={report.payload}")
    print("Production deployments should require signed manifests and a configured trust root.")


if __name__ == "__main__":
    main()
