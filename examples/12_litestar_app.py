from __future__ import annotations

import pprint
from os import getenv
from typing import Any

from astraauth.adapters import AdapterOriginPolicy
from astraauth.service import build_inmemory_service


def build_app() -> Any:
    from litestar import Litestar

    from astraauth.adapters.litestar.wiring import mount_oauth

    service = build_inmemory_service(default_plugins_enabled=False)
    app = Litestar(route_handlers=[])
    origin_policy = AdapterOriginPolicy(
        allowed_origins=frozenset({"http://127.0.0.1:8000"}),
        allowed_callback_origins=frozenset({"http://127.0.0.1:8000"}),
    )
    mount_oauth(app, service.adapter, origin_policy=origin_policy)
    return app


def main() -> None:
    try:
        app = build_app()
    except ImportError:
        print("Install the Litestar extra first: uv sync --all-groups")
        return

    print("Created Litestar app:", type(app).__name__)

    # E2E Test Client Execution
    from litestar.testing import TestClient

    with TestClient(app) as client:
        print("\n[E2E] Requesting Litestar mounted OpenID Configuration...")
        resp = client.get("/.well-known/openid-configuration")
        print("Status Code:", resp.status_code)
        assert resp.status_code == 200

        config_data = resp.json()
        pprint.pprint(config_data)
        assert "token_endpoint" in config_data

        print("\n[E2E] Litestar adapter verification successful!")

    if getenv("ASTRAAUTH_EXAMPLE_SERVE") != "1":
        return
    try:
        import uvicorn
    except ImportError:
        print("Install Uvicorn first: uv sync --all-groups")
        return

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
