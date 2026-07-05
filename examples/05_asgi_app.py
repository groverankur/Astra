from __future__ import annotations

import asyncio
from typing import Any, cast

import httpx

from astraauth.adapters import AdapterOriginPolicy, create_asgi_app
from astraauth.service import build_inmemory_service


async def run_e2e_tests() -> None:
    # 1. Initialize the in-memory service
    service = build_inmemory_service(default_plugins_enabled=False)

    # 2. Configure CORS/Origin settings
    origin_policy = AdapterOriginPolicy(
        allowed_origins=frozenset({"http://127.0.0.1:8000"}),
        allowed_callback_origins=frozenset({"http://127.0.0.1:8000"}),
    )

    # 3. Construct the ASGI App
    app = create_asgi_app(
        adapter=service.adapter,
        issuer="https://auth.local",
        origin_policy=origin_policy,
    )

    print("Created ASGI app:", type(app).__name__)

    # 4. Perform an E2E roundtrip test using httpx in-memory transport
    transport = httpx.ASGITransport(app=cast(Any, app))
    async with httpx.AsyncClient(transport=transport, base_url="https://auth.local") as client:
        print("\n[E2E] Requesting OpenID Configuration...")
        resp = await client.get("/.well-known/openid-configuration")

        print("Status Code:", resp.status_code)
        assert resp.status_code == 200

        config_data = resp.json()
        print("Response Keys:", list(config_data.keys()))
        assert "token_endpoint" in config_data
        assert "issuer" in config_data
        assert config_data["issuer"] == "https://auth.local"

        print("\n[E2E] ASGI adapter verification successful!")


def main() -> None:
    asyncio.run(run_e2e_tests())


if __name__ == "__main__":
    main()
