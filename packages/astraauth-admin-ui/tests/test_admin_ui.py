import json
import re
import time
from pathlib import Path

import astraauth_admin_ui.app as admin_app_module
import pytest
from astraauth_admin_ui import create_admin_app
from fastapi.testclient import TestClient

from astraauth.service import build_service_from_home, create_bootstrap_setup_token


def test_admin_ui_css_readability_guardrails() -> None:
    css_path = Path(admin_app_module.__file__).parent / "static" / "admin.css"
    css = css_path.read_text(encoding="utf-8")

    assert "radial-gradient" not in css
    letter_spacing_values = re.findall(r"letter-spacing:\s*([^;]+);", css)
    assert letter_spacing_values
    assert all(value.strip() == "0" for value in letter_spacing_values)
    assert "border-radius: 1rem" not in css
    assert "border-radius: 1.1rem" not in css
    assert "border-radius: 1.25rem" not in css
    assert "overflow-wrap: anywhere" in css


def test_admin_ui_setup_mode_allows_initial_bootstrap(workspace_tmp_path: Path) -> None:
    client = TestClient(create_admin_app(home=workspace_tmp_path))

    response = client.get("/")
    assert response.status_code == 200
    assert "Astra Netra" in response.text
    assert "/static/vendor/basecoat/basecoat.min.css" in response.text
    assert "/static/vendor/htmx/htmx.min.js" in response.text
    assert "/static/vendor/basecoat/js/all.min.js" in response.text
    assert "/static/admin.js" in response.text
    assert "Admin Console" not in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

    session = client.get("/api/session")
    assert session.status_code == 200
    session_payload = session.json()
    assert session_payload["authenticated"] is False
    assert session_payload["setup"]["setup_required"] is True
    csrf = session_payload["csrf_token"]
    _, setup_token = create_bootstrap_setup_token(home=workspace_tmp_path, ttl_seconds=600)
    initial_manifest = (workspace_tmp_path / "bootstrap.json").read_text(encoding="utf-8")
    assert setup_token not in initial_manifest

    config_init = client.post(
        "/api/actions/config-init",
        headers={"X-CSRF-Token": csrf},
        json={
            "project_name": "AstraAuth",
            "environment": "test",
            "persistence_backend": "sqlite",
            "issuer": "https://admin-ui.local",
            "force": True,
            "encrypt_values": False,
            "bootstrap_token": setup_token,
        },
    )
    assert config_init.status_code == 200
    assert json.loads(config_init.content)["ok"] is True

    admin_init = client.post(
        "/api/actions/init-admin",
        headers={"X-CSRF-Token": csrf},
        json={
            "tenant_id": "tenant-1",
            "username": "admin",
            "password": "secret",
            "email": "admin@example.com",
            "bootstrap_token": setup_token,
        },
    )
    assert admin_init.status_code == 200
    assert json.loads(admin_init.content)["ok"] is True

    session_after = client.get("/api/session")
    assert session_after.status_code == 200
    assert session_after.json()["setup"]["setup_required"] is False
    final_manifest = (workspace_tmp_path / "bootstrap.json").read_text(encoding="utf-8")
    assert '"setup_tokens": []' in final_manifest


def test_admin_ui_requires_authentication_after_setup(workspace_tmp_path: Path) -> None:
    client = TestClient(create_admin_app(home=workspace_tmp_path))
    csrf = client.get("/api/session").json()["csrf_token"]
    _, setup_token = create_bootstrap_setup_token(home=workspace_tmp_path, ttl_seconds=600)

    client.post(
        "/api/actions/config-init",
        headers={"X-CSRF-Token": csrf},
        json={
            "project_name": "AstraAuth",
            "environment": "test",
            "persistence_backend": "sqlite",
            "issuer": "https://admin-ui.local",
            "force": True,
            "encrypt_values": False,
            "bootstrap_token": setup_token,
        },
    )
    client.post(
        "/api/actions/init-admin",
        headers={"X-CSRF-Token": csrf},
        json={
            "tenant_id": "tenant-1",
            "username": "admin",
            "password": "secret",
            "email": "admin@example.com",
            "bootstrap_token": setup_token,
        },
    )

    unauth_dashboard = client.get("/api/dashboard")
    assert unauth_dashboard.status_code == 401

    partial_sidebar = client.get("/partials/sidebar")
    assert partial_sidebar.status_code == 200
    assert partial_sidebar.text == ""

    partial_main = client.get("/partials/main")
    assert partial_main.status_code == 200
    assert "Admin Sign In" in partial_main.text
    assert "Health, keys, audits" not in partial_main.text

    login = client.post(
        "/api/session/login",
        headers={"X-CSRF-Token": client.get("/api/session").json()["csrf_token"]},
        json={"tenant_id": "tenant-1", "username": "admin", "password": "secret"},
    )
    assert login.status_code == 200
    login_payload = login.json()
    assert login_payload["ok"] is True
    auth_csrf = login_payload["csrf_token"]

    missing_csrf = client.post("/api/actions/key-rotate", json={"use": "sig"})
    assert missing_csrf.status_code == 403

    wrong_login_csrf = client.post(
        "/api/session/login",
        headers={"X-CSRF-Token": "invalid-token"},
        json={"tenant_id": "tenant-1", "username": "admin", "password": "secret"},
    )
    assert wrong_login_csrf.status_code == 403
    assert wrong_login_csrf.json()["detail"] == "csrf_token_invalid"

    rotate = client.post(
        "/api/actions/key-rotate",
        headers={"X-CSRF-Token": auth_csrf},
        json={"use": "sig"},
    )
    assert rotate.status_code == 200
    rotate_payload = json.loads(rotate.content)
    assert rotate_payload["ok"] is True
    assert rotate_payload["keys"]

    dashboard_after = client.get("/api/dashboard")
    payload = dashboard_after.json()
    assert payload["inventory"]["configured"] is True
    assert payload["inventory"]["environment"] == "test"
    assert payload["bootstrap"]["admins"][0]["username"] == "admin"

    audit = client.get("/api/oidc-audit", params={"tenant_id": "tenant-1"})
    assert audit.status_code == 200
    assert audit.json()["tenant_id"] == "tenant-1"

    admin_audit = client.get("/api/admin-audit")
    assert admin_audit.status_code == 200
    admin_events = admin_audit.json()["records"]
    event_types = {record["event_type"] for record in admin_events}
    assert "admin_ui.session.login" in event_types
    assert "admin_ui.keys.rotate" in event_types

    observability = client.get("/api/observability")
    assert observability.status_code == 200
    observability_payload = observability.json()
    assert observability_payload["configured"] is True
    assert observability_payload["correlation_header_name"] == "X-Correlation-ID"

    security = client.get("/api/security")
    assert security.status_code == 200
    security_payload = security.json()
    assert security_payload["configured"] is True
    assert "runtime_throttle" in security_payload
    assert "recent_plugin_audit_records" in security_payload

    service = build_service_from_home(home=workspace_tmp_path)
    service.plugin_runtime.execute_hook(
        hook="auth.pre_authenticate",
        tenant_id="Default",
        payload={"username": "alice"},
        fail_closed=False,
    )
    plugin_audit = client.get("/api/plugin-audit", params={"plugin_name": "geo"})
    assert plugin_audit.status_code == 200
    plugin_audit_payload = plugin_audit.json()
    assert plugin_audit_payload["records"]
    assert plugin_audit_payload["records"][0]["plugin_name"] == "geo"

    static_css = client.get("/static/vendor/basecoat/basecoat.min.css")
    assert static_css.status_code == 200
    assert "cache-control" not in static_css.headers


def test_admin_ui_htmx_partials_update_dashboard_in_place(workspace_tmp_path: Path) -> None:
    client = TestClient(create_admin_app(home=workspace_tmp_path))
    csrf = client.get("/api/session").json()["csrf_token"]
    _, setup_token = create_bootstrap_setup_token(home=workspace_tmp_path, ttl_seconds=600)

    client.post(
        "/api/actions/config-init",
        headers={"X-CSRF-Token": csrf},
        json={
            "project_name": "AstraAuth",
            "environment": "test",
            "persistence_backend": "sqlite",
            "issuer": "https://admin-ui.local",
            "force": True,
            "encrypt_values": False,
            "bootstrap_token": setup_token,
        },
    )
    client.post(
        "/api/actions/init-admin",
        headers={"X-CSRF-Token": csrf},
        json={
            "tenant_id": "tenant-1",
            "username": "admin",
            "password": "secret",
            "email": "admin@example.com",
            "bootstrap_token": setup_token,
        },
    )

    partial_login = client.post(
        "/partials/session/login",
        data={
            "tenant_id": "tenant-1",
            "username": "admin",
            "password": "secret",
            "csrf_token": client.get("/api/session").json()["csrf_token"],
        },
    )
    assert partial_login.status_code == 200
    assert "Runtime Overview" in partial_login.text
    assert "hx-swap-oob" in partial_login.text

    partial_sidebar = client.get("/partials/sidebar")
    assert partial_sidebar.status_code == 200
    assert "OIDC Audit" in partial_sidebar.text
    assert "Admin Audit" in partial_sidebar.text
    assert "Core" in partial_sidebar.text
    assert "OIDC" in partial_sidebar.text

    partial_rotate = client.post(
        "/partials/actions/key-rotate",
        data={"use": "sig", "csrf_token": client.get("/api/session").json()["csrf_token"]},
    )
    assert partial_rotate.status_code == 200
    assert "Rotated sig runtime keys." in partial_rotate.text
    assert "hx-swap-oob" in partial_rotate.text

    oidc_panel = client.get("/partials/dashboard/oidc-audit", params={"tenant_id": "tenant-1"})
    assert oidc_panel.status_code == 200
    assert "OIDC Audit" in oidc_panel.text

    admin_panel = client.get("/partials/dashboard/admin-audit", params={"tenant_id": "tenant-1"})
    assert admin_panel.status_code == 200
    assert "Admin Audit" in admin_panel.text

    service = build_service_from_home(home=workspace_tmp_path)
    service.plugin_runtime.execute_hook(
        hook="auth.pre_authenticate",
        tenant_id="Default",
        payload={"username": "alice"},
        fail_closed=False,
    )
    now = time.monotonic()
    service.throttle_store.record(
        bucket="oauth-token|127.0.0.1|tenant-1|alice",
        max_events=1,
        window_seconds=300.0,
        block_seconds=600.0,
        now=now,
    )
    service.throttle_store.record(
        bucket="oauth-token|127.0.0.1|tenant-1|alice",
        max_events=1,
        window_seconds=300.0,
        block_seconds=600.0,
        now=now + 1,
    )

    infrastructure_filtered = client.get(
        "/partials/dashboard/infrastructure",
        params={"throttle_scope": "oauth-token", "plugin_status": "succeeded"},
    )
    assert infrastructure_filtered.status_code == 200
    assert "oauth-token" in infrastructure_filtered.text
    assert "succeeded" in infrastructure_filtered.text

    partial_logout = client.post(
        "/partials/session/logout",
        data={"csrf_token": client.get("/api/session").json()["csrf_token"]},
    )
    assert partial_logout.status_code == 204
    assert partial_logout.headers["hx-redirect"] == "/"


def test_admin_ui_throttles_repeated_login_failures(
    workspace_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_admin_app(home=workspace_tmp_path)
    monkeypatch.setattr(admin_app_module, "_LOGIN_MAX_FAILURES", 1)
    client = TestClient(app)
    csrf = client.get("/api/session").json()["csrf_token"]
    _, setup_token = create_bootstrap_setup_token(home=workspace_tmp_path, ttl_seconds=600)

    client.post(
        "/api/actions/config-init",
        headers={"X-CSRF-Token": csrf},
        json={
            "project_name": "AstraAuth",
            "environment": "test",
            "persistence_backend": "sqlite",
            "issuer": "https://admin-ui.local",
            "force": True,
            "encrypt_values": False,
            "bootstrap_token": setup_token,
        },
    )
    client.post(
        "/api/actions/init-admin",
        headers={"X-CSRF-Token": csrf},
        json={
            "tenant_id": "tenant-1",
            "username": "admin",
            "password": "secret",
            "email": "admin@example.com",
            "bootstrap_token": setup_token,
        },
    )

    denied = client.post(
        "/api/session/login",
        headers={"X-CSRF-Token": client.get("/api/session").json()["csrf_token"]},
        json={"tenant_id": "tenant-1", "username": "admin", "password": "wrong-secret"},
    )
    assert denied.status_code == 401

    denied_again = client.post(
        "/api/session/login",
        headers={"X-CSRF-Token": client.get("/api/session").json()["csrf_token"]},
        json={"tenant_id": "tenant-1", "username": "admin", "password": "wrong-secret"},
    )
    assert denied_again.status_code == 401

    throttled = client.post(
        "/api/session/login",
        headers={"X-CSRF-Token": client.get("/api/session").json()["csrf_token"]},
        json={"tenant_id": "tenant-1", "username": "admin", "password": "wrong-secret"},
    )
    assert throttled.status_code == 429
    assert throttled.json()["detail"] == "rate_limited"
    assert int(throttled.headers["retry-after"]) >= 1


def test_admin_ui_throttles_sensitive_actions(
    workspace_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_admin_app(home=workspace_tmp_path)
    monkeypatch.setattr(admin_app_module, "_ACTION_MAX_EVENTS", 1)
    client = TestClient(app)
    csrf = client.get("/api/session").json()["csrf_token"]
    _, setup_token = create_bootstrap_setup_token(home=workspace_tmp_path, ttl_seconds=600)

    client.post(
        "/api/actions/config-init",
        headers={"X-CSRF-Token": csrf},
        json={
            "project_name": "AstraAuth",
            "environment": "test",
            "persistence_backend": "sqlite",
            "issuer": "https://admin-ui.local",
            "force": True,
            "encrypt_values": False,
            "bootstrap_token": setup_token,
        },
    )
    client.post(
        "/api/actions/init-admin",
        headers={"X-CSRF-Token": csrf},
        json={
            "tenant_id": "tenant-1",
            "username": "admin",
            "password": "secret",
            "email": "admin@example.com",
            "bootstrap_token": setup_token,
        },
    )
    login = client.post(
        "/api/session/login",
        headers={"X-CSRF-Token": client.get("/api/session").json()["csrf_token"]},
        json={"tenant_id": "tenant-1", "username": "admin", "password": "secret"},
    )
    auth_csrf = login.json()["csrf_token"]

    first = client.post(
        "/api/actions/key-rotate",
        headers={"X-CSRF-Token": auth_csrf},
        json={"use": "sig"},
    )
    assert first.status_code == 200

    throttled = client.post(
        "/api/actions/key-rotate",
        headers={"X-CSRF-Token": auth_csrf},
        json={"use": "sig"},
    )
    assert throttled.status_code == 429
    assert throttled.json()["detail"] == "rate_limited"
    assert int(throttled.headers["retry-after"]) >= 1
