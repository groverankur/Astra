from __future__ import annotations

import pprint
from typing import Any

from astraauth.adapters import AdapterOriginPolicy, mount_oauth_flask
from astraauth.core.authorization.models import Role
from astraauth.core.oauth.models import OAuthClient, Subject
from astraauth.service import build_inmemory_service


def build_app() -> Any:
    from flask import Flask

    # 1. Initialize the service and populate test credentials
    service = build_inmemory_service(default_plugins_enabled=False)

    subject = Subject(subject_id="user-1", tenants={"tenant-1"}, username="bob")
    service.add_subject_password(
        subject=subject,
        tenant_id="tenant-1",
        username="bob",
        password="secret-password",
    )
    service.add_role(Role(name="user", permissions={"openid"}))
    service.assign_roles(subject_id="user-1", tenant_id="tenant-1", roles={"user"})

    service.add_client(
        OAuthClient(
            client_id="client-1",
            redirect_uris={"https://app.local/callback"},
            allowed_scopes={"openid"},
            client_type="public",
            auth_method="none",
            require_pkce=False,
        )
    )

    # 2. Build and mount on Flask
    app = Flask(__name__)
    origin_policy = AdapterOriginPolicy(
        allowed_origins=frozenset({"http://127.0.0.1:5000"}),
        allowed_callback_origins=frozenset({"http://127.0.0.1:5000"}),
    )
    mount_oauth_flask(
        app, service.adapter, issuer="https://auth.local", origin_policy=origin_policy
    )
    return app


def main() -> None:
    try:
        app = build_app()
    except ImportError:
        print("Install the Flask extra first: uv sync --all-groups")
        return

    print("Created Flask app:", app.name)

    # 3. Perform Flask E2E Client Request verification
    with app.test_client() as client:
        print("\n[E2E] Requesting OpenID Configuration...")
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        print("Discovery config fetched successfully!")

        print("\n[E2E] Requesting Access Token...")
        token_resp = client.post(
            "/token",
            data={
                "grant_type": "password",
                "client_id": "client-1",
                "tenant_id": "tenant-1",
                "username": "bob",
                "password": "secret-password",
                "scope": "openid",
            },
        )
        print("Status Code:", token_resp.status_code)
        assert token_resp.status_code == 200

        token_data = token_resp.json
        print("Token Response:")
        pprint.pprint(token_data)
        assert "access_token" in token_data

        print("\n[E2E] Flask adapter verification successful!")


if __name__ == "__main__":
    main()
