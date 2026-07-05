from __future__ import annotations

import pprint
import threading
import time
from os import getenv
from typing import Any

import httpx

from astraauth.adapters import AdapterOriginPolicy
from astraauth.service import build_inmemory_service


def build_app() -> Any:
    from robyn import Robyn

    from astraauth.adapters.robyn.wiring import mount_oauth

    service = build_inmemory_service(default_plugins_enabled=False)
    app = Robyn(__file__)
    origin_policy = AdapterOriginPolicy(
        allowed_origins=frozenset({"http://127.0.0.1:8080"}),
        allowed_callback_origins=frozenset({"http://127.0.0.1:8080"}),
    )
    mount_oauth(app, service.adapter, origin_policy=origin_policy)
    return app


def main() -> None:
    try:
        app = build_app()
    except ImportError:
        print("Install the Robyn extra first: uv sync --all-groups")
        return

    print("Created Robyn app:", type(app).__name__)

    # 1. Run Robyn server in a background daemon thread
    def run_server():
        try:
            app.start(host="127.0.0.1", port=8080)
        except Exception as e:
            print("Server exception:", e)

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Wait for the Rust/Python port bindings to complete
    print("Waiting for Robyn server to initialize...")
    time.sleep(1.5)

    # 2. Execute E2E HTTP client request roundtrip
    print("\n[E2E] Requesting Robyn mounted OpenID Configuration...")
    try:
        resp = httpx.get("http://127.0.0.1:8080/.well-known/openid-configuration", timeout=5.0)
        print("Status Code:", resp.status_code)
        assert resp.status_code == 200

        config_data = resp.json()
        pprint.pprint(config_data)
        assert "token_endpoint" in config_data

        print("\n[E2E] Robyn adapter verification successful!")
    except Exception as e:
        print("Robyn E2E call failed:", e)

    if getenv("ASTRAAUTH_EXAMPLE_SERVE") == "1":
        print("Keeping server alive. Press Ctrl+C to exit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
