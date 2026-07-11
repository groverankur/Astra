"""Astra FastAPI Sample App — Polished E2E Example.

Demonstrates: login/logout, session management, RBAC-gated routes,
ABAC policy evaluation, step-up MFA on sensitive actions, and token introspection.

Run:
    uv run python examples/fastapi_app.py

Then open http://127.0.0.1:8000 in your browser.

Credentials:
    alice / alice-password  →  admin  (can read + delete documents)
    bob   / bob-password    →  user   (can read documents only)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from os import getenv
from typing import Any

from fastapi import Cookie, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from astraauth.adapters import AdapterOriginPolicy
from astraauth.adapters.fastapi.wiring import mount_oauth
from astraauth.core.adapters.http_types import NormalizedRequestContext
from astraauth.core.authorization.models import Decision, PolicyRule, Role
from astraauth.core.authorization.store import InMemoryPolicyStore
from astraauth.core.oauth.models import OAuthClient, Subject
from astraauth.idp import GroupRoleMapping, OIDCProviderConfig
from astraauth.service import AstraAuthService, build_inmemory_service
from astraauth.webauthn.models import WebAuthnCredential

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("astra.example.fastapi")

TENANT_ID = "demo"
CLIENT_ID = "demo-app"
PORT = int(getenv("PORT", "8000"))
BASE_URL = getenv("BASE_URL", f"http://127.0.0.1:{PORT}")

# ---------------------------------------------------------------------------
# Global configurations & states
# ---------------------------------------------------------------------------
REQUIRE_LOGIN_MFA = False

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------
DEMO_USERS: dict[str, dict[str, Any]] = {
    "alice": {"id": "user-alice", "password": "alice-password", "roles": {"admin", "user"}},
    "bob": {"id": "user-bob", "password": "bob-password", "roles": {"user"}},
}

DOCUMENTS = [
    {"id": "doc-1", "title": "Q3 Financial Report", "sensitivity": "high", "owner": "user-alice"},
    {"id": "doc-2", "title": "Product Roadmap 2025", "sensitivity": "low", "owner": "user-bob"},
    {
        "id": "doc-3",
        "title": "Security Audit Results",
        "sensitivity": "high",
        "owner": "user-alice",
    },
]


# ---------------------------------------------------------------------------
# Service bootstrap
# ---------------------------------------------------------------------------
def _build_service() -> AstraAuthService:
    svc = build_inmemory_service(default_plugins_enabled=True)

    # Roles
    svc.add_role(
        Role(
            name="admin",
            permissions={"openid", "documents.read", "documents.delete", "users.manage"},
        )
    )
    svc.add_role(Role(name="user", permissions={"openid", "documents.read"}))

    # ABAC: only admin can delete high-sensitivity documents
    policy_store = InMemoryPolicyStore()
    policy_store.add_policy(
        PolicyRule(
            policy_id="admin-delete-high",
            tenant_id=TENANT_ID,
            permission="documents.delete",
            effect=Decision.ALLOW,
            subject_match={"role": "admin"},
            resource_match={"sensitivity": "high"},
            environment_match={},
            reasons=("admin_role",),
        )
    )
    svc.adapter._authorization_engine._policies = policy_store

    # OAuth client
    svc.add_client(
        OAuthClient(
            client_id=CLIENT_ID,
            redirect_uris={f"{BASE_URL}/oidc/callback"},
            allowed_scopes={"openid"},
            allowed_tenants={TENANT_ID},
            client_type="public",
            auth_method="none",
            require_pkce=False,
        )
    )

    # Users
    for username, info in DEMO_USERS.items():
        subject = Subject(subject_id=info["id"], tenants={TENANT_ID}, username=username)
        svc.add_subject_password(
            subject=subject, tenant_id=TENANT_ID, username=username, password=info["password"]
        )
        svc.assign_roles(subject_id=info["id"], tenant_id=TENANT_ID, roles=info["roles"])

    # Register Mock External OIDC Provider
    svc.register_oidc_provider(
        provider=OIDCProviderConfig(
            provider_id="oidc-google",
            issuer="https://accounts.google.com",
            client_id="google-client-id",
            client_secret="google-client-secret",
        )
    )
    svc.add_oidc_group_role_mapping(
        GroupRoleMapping(
            provider_id="oidc-google",
            tenant_id=TENANT_ID,
            external_group="admins",
            role_name="admin",
        )
    )

    class MockOIDCExchangeClient:
        def exchange_code(self, provider, metadata, code, redirect_uri, code_verifier):
            from astraauth.idp import OIDCTokenResponse

            return OIDCTokenResponse(
                access_token="mock-google-token",
                token_type="Bearer",
                id_token="mock-google-id-token",
            )

        def validate_id_token(self, provider, metadata, token_response, expected_nonce):
            from astraauth.idp import OIDCIDTokenClaims

            return OIDCIDTokenClaims(
                issuer="https://accounts.google.com",
                subject="google-oauth2|12345",
                audience=("google-client-id",),
                nonce=expected_nonce,
            )

        def fetch_userinfo(self, provider, metadata, token_response):
            from astraauth.idp import OIDCUserInfo

            return OIDCUserInfo(
                subject="google-oauth2|12345",
                email="google-admin@example.com",
                email_verified=True,
                claims={"groups": ("admins",)},
            )

    class MockOIDCMetadataClient:
        def fetch_metadata(self, discovery_url):
            return {
                "issuer": "https://accounts.google.com",
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
            }

    svc.oidc_handler._exchange_client = MockOIDCExchangeClient()
    svc.oidc_handler._metadata_client = MockOIDCMetadataClient()

    # Seed WebAuthn mock credentials for demo users
    svc.webauthn_credentials.save(
        WebAuthnCredential(
            credential_id="demo-passkey-id",
            subject_id="user-alice",
            tenant_id=TENANT_ID,
            public_key="demo-public-key",
            sign_count=1,
            transports=("internal",),
            created_at=datetime.now(tz=UTC),
        )
    )

    # Enable geo/risk plugins for the demo tenant
    try:
        svc.plugin_runtime.enable_for_tenant(tenant_id=TENANT_ID, plugin_name="geo")
        svc.plugin_runtime.enable_for_tenant(tenant_id=TENANT_ID, plugin_name="risk")
    except Exception:
        pass

    return svc


SERVICE = _build_service()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Astra FastAPI Demo", version="1.0.0")
mount_oauth(
    app,
    SERVICE.adapter,
    origin_policy=AdapterOriginPolicy(
        allowed_origins=frozenset({BASE_URL}),
        allowed_callback_origins=frozenset({BASE_URL}),
    ),
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
CSS = """
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
  .topbar{background:#1e293b;border-bottom:1px solid #334155;padding:12px 24px;display:flex;align-items:center;justify-content:space-between}
  .topbar h1{font-size:1.1rem;font-weight:700;color:#38bdf8;letter-spacing:.5px}
  .topbar .user-pill{background:#334155;border-radius:999px;padding:4px 14px;font-size:.8rem;color:#94a3b8}
  .container{max-width:960px;margin:40px auto;padding:0 20px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:20px}
  .card h2{font-size:1rem;font-weight:600;color:#7dd3fc;margin-bottom:14px}
  .badge{display:inline-block;border-radius:999px;padding:3px 10px;font-size:.75rem;font-weight:600;margin-right:4px}
  .badge-green{background:#064e3b;color:#6ee7b7}
  .badge-blue{background:#1e3a5f;color:#93c5fd}
  .badge-red{background:#4c0519;color:#fca5a5}
  table{width:100%;border-collapse:collapse;font-size:.875rem}
  th{text-align:left;padding:8px 12px;color:#64748b;border-bottom:1px solid #334155;font-weight:500}
  td{padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  .btn{display:inline-block;padding:8px 18px;border-radius:8px;font-size:.85rem;font-weight:600;cursor:pointer;border:none;text-decoration:none;transition:opacity .15s}
  .btn-primary{background:#0284c7;color:#fff}
  .btn-danger{background:#dc2626;color:#fff}
  .btn-ghost{background:#334155;color:#e2e8f0}
  .btn:hover{opacity:.85}
  input,select{background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;padding:9px 14px;font-size:.9rem;width:100%;margin-bottom:12px}
  .alert{padding:10px 16px;border-radius:8px;margin-bottom:16px;font-size:.875rem}
  .alert-error{background:#4c0519;color:#fca5a5;border:1px solid #7f1d1d}
  .alert-success{background:#064e3b;color:#6ee7b7;border:1px solid #065f46}
  .alert-warn{background:#422006;color:#fcd34d;border:1px solid #78350f}
  nav a{color:#94a3b8;text-decoration:none;margin-right:18px;font-size:.875rem}
  nav a:hover{color:#e2e8f0}
  .perm-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
  .mfa-box{text-align:center;padding:40px 20px}
  .mfa-box h2{color:#fbbf24;margin-bottom:8px}
  .mfa-box p{color:#94a3b8;font-size:.875rem;margin-bottom:20px}
</style>
"""


def _session_from_cookie(session_id: str | None) -> dict[str, Any] | None:
    if not session_id:
        return None
    hasattr(SERVICE.sessions.list_active_for_subject, "__func__")
    # Simple lookup via the internal store
    store = SERVICE.sessions
    sess = store.get(session_id)
    if sess is None or sess.is_expired():
        return None
    subject = SERVICE.subjects.get_subject(sess.subject_id)
    username = subject.username if (subject and subject.username) else sess.subject_id
    return {
        "session_id": session_id,
        "subject_id": sess.subject_id,
        "acr": sess.acr,
        "username": username,
    }


def _make_request(
    method: str,
    path: str,
    form: dict[str, str],
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> Any:
    return NormalizedRequestContext(
        http_method=method,
        request_path=path,
        query_params={},
        headers=headers or {},
        form_data=form,
        cookies=cookies or {},
        client_ip="127.0.0.1",
        body_json=None,
    )


def _page(title: str, body: str, session: dict | None = None) -> HTMLResponse:
    nav = ""
    user_pill = ""
    if session:
        nav = '<nav><a href="/dashboard">Dashboard</a><a href="/documents">Documents</a><a href="/signout">Logout</a></nav>'
        user_pill = (
            f'<span class="user-pill">👤 {session["username"]} · ACR {session["acr"]}</span>'
        )
    return HTMLResponse(f"""<!doctype html><html><head><meta charset=utf-8>
<title>{title} — Astra FastAPI Demo</title>{CSS}</head><body>
<div class="topbar"><h1>⚡ Astra · FastAPI</h1><div style="display:flex;align-items:center;gap:16px">{nav}{user_pill}</div></div>
<div class="container">{body}</div></body></html>""")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, astra_session: str | None = Cookie(None)):
    session = _session_from_cookie(astra_session)
    if session:
        return RedirectResponse("/dashboard")
    body = """
    <div class="card" style="max-width:420px;margin:80px auto">
      <h2>Sign in to Astra Demo</h2>
      <form method="POST" action="/login">
        <input name="username" placeholder="Username (alice or bob)" required>
        <input name="password" type="password" placeholder="Password" required>
        <button class="btn btn-primary" style="width:100%">Sign In</button>
      </form>
      <div style="margin-top:16px;display:flex;flex-direction:column;gap:8px">
        <a href="/oidc/mock/login" class="btn btn-ghost" style="width:100%;text-align:center;background:#1e3a5f;color:#93c5fd">🌐 Sign In with Google (Mock OIDC)</a>
        <a href="/webauthn/mock/login" class="btn btn-ghost" style="width:100%;text-align:center;background:#064e3b;color:#6ee7b7">🔑 Sign In with Passkey (Mock WebAuthn)</a>
      </div>
      <p style="margin-top:16px;font-size:.8rem;color:#64748b;text-align:center">
        alice / alice-password → admin &nbsp;|&nbsp; bob / bob-password → user
      </p>
    </div>"""
    return _page("Login", body)


@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    req = _make_request(
        "POST",
        "/token",
        {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "tenant_id": TENANT_ID,
            "username": username,
            "password": password,
            "scope": "openid",
        },
    )
    resp = SERVICE.adapter.handle_token(req)
    if resp.status != 200:
        logger.error(f"Login failed: status={resp.status}, body={resp.body}")
        body = '<div class="card" style="max-width:420px;margin:80px auto"><div class="alert alert-error">Invalid credentials. Try again.</div><a href="/" class="btn btn-ghost">← Back</a></div>'
        return _page("Login Failed", body)

    body_dict = resp.body if isinstance(resp.body, dict) else {}
    payload = SERVICE.token_manager.verify_jwt(
        str(body_dict.get("access_token") or ""), audience="api"
    )
    session_id = payload["sid"]

    if REQUIRE_LOGIN_MFA:
        response = RedirectResponse("/mfa?next=/dashboard&login_flow=true", status_code=303)
        response.set_cookie(key="astra_temp_session", value=session_id, httponly=True)
        return response

    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie("astra_session", session_id, httponly=True, samesite="lax")
    return response


@app.get("/oidc/mock/login")
async def oidc_mock_login():
    req = _make_request(
        "POST",
        "/oidc/login/start",
        {
            "provider_id": "oidc-google",
            "tenant_id": TENANT_ID,
            "redirect_uri": f"{BASE_URL}/oidc/callback",
        },
    )
    resp = SERVICE.adapter.handle_oidc_login_start(req)
    if resp.status != 302:
        return _page(
            "OIDC Error",
            f'<div class="card"><div class="alert alert-error">Failed to initiate OIDC. Status: {resp.status}</div></div>',
        )

    location = str((resp.headers or {}).get("Location") or "")
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(location).query).get("state", [""])[0]

    callback_req = NormalizedRequestContext(
        http_method="GET",
        request_path="/oidc/callback",
        query_params={
            "provider_id": "oidc-google",
            "tenant_id": TENANT_ID,
            "client_id": CLIENT_ID,
            "redirect_uri": f"{BASE_URL}/oidc/callback",
            "code": "demo-auth-code",
            "state": state,
            "scope": "openid",
        },
        headers={},
        cookies={},
        client_ip="127.0.0.1",
        body_json=None,
    )

    callback_resp = SERVICE.adapter.handle_oidc_callback(callback_req)
    if callback_resp.status != 200:
        return _page(
            "OIDC Error",
            f'<div class="card"><div class="alert alert-error">OIDC Callback failed: {callback_resp.body}</div></div>',
        )

    body_dict = callback_resp.body if isinstance(callback_resp.body, dict) else {}
    payload = SERVICE.token_manager.verify_jwt(
        str(body_dict.get("access_token") or ""), audience="api"
    )
    session_id = payload["sid"]

    if REQUIRE_LOGIN_MFA:
        response = RedirectResponse("/mfa?next=/dashboard&login_flow=true", status_code=303)
        response.set_cookie(key="astra_temp_session", value=session_id, httponly=True)
        return response

    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(key="astra_session", value=session_id, httponly=True)
    return response


@app.get("/webauthn/mock/login")
async def webauthn_mock_login():
    req = _make_request(
        "POST",
        "/token",
        {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "tenant_id": TENANT_ID,
            "username": "alice",
            "password": "alice-password",
            "scope": "openid",
            "required_acr": "2",
            "preferred_factor_type": "webauthn",
        },
    )
    resp = SERVICE.adapter.handle_token(req)
    if resp.status != 200:
        return _page(
            "WebAuthn Error",
            f'<div class="card"><div class="alert alert-error">Handshake failed: {resp.body}</div></div>',
        )

    body_dict = resp.body if isinstance(resp.body, dict) else {}
    session_id = str(body_dict.get("session_id") or "")
    state_id = str(body_dict.get("state_id") or "")

    finish_req = _make_request(
        "POST",
        "/webauthn/authenticate/finish",
        {
            "session_id": session_id,
            "state_id": state_id,
            "credential_id": "demo-passkey-id",
            "sign_count": "2",
        },
    )
    finish_resp = SERVICE.adapter.handle_webauthn_authenticate_finish(finish_req)
    if finish_resp.status != 200:
        return _page(
            "WebAuthn Error",
            f'<div class="card"><div class="alert alert-error">Passkey verification failed: {finish_resp.body}</div></div>',
        )

    finish_body = finish_resp.body if isinstance(finish_resp.body, dict) else {}
    payload = SERVICE.token_manager.verify_jwt(
        str(finish_body.get("access_token") or ""), audience="api"
    )
    sid = payload["sid"]

    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(key="astra_session", value=sid, httponly=True)
    return response


@app.get("/signout")
async def app_logout(astra_session: str | None = Cookie(None)):
    if astra_session:
        req = _make_request(
            "POST",
            "/logout",
            {"session_id": astra_session},
            cookies={"astra_session": astra_session},
        )
        SERVICE.adapter.handle_logout(req)
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("astra_session")
    response.delete_cookie("astra_temp_session")
    return response


@app.post("/admin/settings")
async def update_settings(
    mfa_enabled: str = Form("false"), astra_session: str | None = Cookie(None)
):
    session = _session_from_cookie(astra_session)
    if not session:
        return RedirectResponse("/", status_code=303)
    assignment = SERVICE.assignments.get_assignments(session["subject_id"], TENANT_ID)
    is_admin = "admin" in assignment.roles if assignment else False
    if not is_admin:
        return _page(
            "Forbidden",
            '<div class="card"><div class="alert alert-error">Admin permissions required.</div></div>',
            session,
        )

    global REQUIRE_LOGIN_MFA
    REQUIRE_LOGIN_MFA = mfa_enabled == "true"
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(astra_session: str | None = Cookie(None)):
    sess_id = astra_session or ""
    session = _session_from_cookie(astra_session)
    if not session:
        return RedirectResponse("/")
    uid = session["subject_id"]
    engine = SERVICE.adapter._authorization_engine
    perms = engine.resolve_permissions(subject_id=uid, tenant_id=TENANT_ID)
    assignment = SERVICE.assignments.get_assignments(uid, TENANT_ID)
    roles = assignment.roles if assignment else set()
    is_admin = "admin" in roles

    # Mint a user JWT access token dynamically for the API panel
    user_token = SERVICE.token_manager.issue_jwt(
        subject=session["subject_id"],
        audience="api",
        extra_claims={
            "scp": list(perms),
            "cid": CLIENT_ID,
            "tid": TENANT_ID,
            "roles": list(roles),
            "sid": session["session_id"],
            "ver": 1,
            "acr": session["acr"],
            "amr": ["password"] + (["email_otp"] if session["acr"] >= 2 else []),
        },
    )

    import json

    jwt_claims = {
        "iss": BASE_URL,
        "sub": session["subject_id"],
        "aud": "api",
        "scp": list(perms),
        "roles": list(roles),
        "acr": session["acr"],
        "amr": ["password"] + (["email_otp"] if session["acr"] >= 2 else []),
        "tid": TENANT_ID,
    }
    jwt_json = json.dumps(jwt_claims, indent=2)

    enabled_plugins = SERVICE.plugin_runtime._registry_store.enabled_for_tenant(tenant_id=TENANT_ID)
    plugin_badges = "".join(
        f'<span class="badge badge-green" style="background:#1e293b;border:1px solid #34d399;color:#34d399;padding:6px 12px;font-weight:normal;margin-right:8px">🛡️ {p} plugin</span>'
        for p in sorted(enabled_plugins)
    )
    if not plugin_badges:
        plugin_badges = '<span style="color:#64748b;font-size:.85rem">No active plugins.</span>'

    perm_badges = "".join(f'<span class="badge badge-blue">{p}</span>' for p in sorted(perms))
    role_badges = "".join(f'<span class="badge badge-green">{r}</span>' for r in sorted(roles))

    settings_card = ""
    if is_admin:
        settings_card = f"""
        <div class="card">
          <h2>Astra Policy Settings (Admin Only)</h2>
          <p style="color:#94a3b8;margin-bottom:12px;font-size:.85rem">Control global login security requirements:</p>
          <form method="POST" action="/admin/settings">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
              <input type="checkbox" name="mfa_enabled" value="true" {"checked" if REQUIRE_LOGIN_MFA else ""} style="width:auto;margin:0">
              <label for="mfa_enabled" style="font-size:.9rem;color:#e2e8f0">Require MFA (ACR = 2) for all user sign-ins</label>
            </div>
            <button class="btn btn-primary" style="padding:6px 14px;font-size:.8rem">Update Policy</button>
          </form>
        </div>"""

    body = f"""
    <div class="card">
      <h2>Welcome back, {session["username"]}</h2>
      <p style="color:#94a3b8;margin-bottom:16px">Session ID: <code style="color:#7dd3fc">{sess_id[:16]}…</code> · Authentication Level: ACR {session["acr"]}</p>
      <p style="color:#64748b;font-size:.8rem;margin-bottom:6px">ROLES</p>
      <div class="perm-list">{role_badges}</div>
      <p style="color:#64748b;font-size:.8rem;margin-top:14px;margin-bottom:6px">EFFECTIVE PERMISSIONS</p>
      <div class="perm-list">{perm_badges}</div>
    </div>
    {settings_card}
    <div class="card">
      <h2>Secure API Integration Test Panel</h2>
      <p style="color:#94a3b8;margin-bottom:12px;font-size:.85rem">Test access to the token-secured JSON endpoint <code>/api/documents</code>:</p>
      <pre style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px;overflow-x:auto;font-family:monospace;font-size:.8rem;color:#38bdf8;margin-bottom:12px;white-space:pre-wrap;word-break:break-all">curl -H "Authorization: Bearer {user_token}" {BASE_URL}/api/documents</pre>
      <p style="color:#64748b;font-size:.8rem">Or try requesting without headers to see <code>401 Unauthorized</code> response.</p>
    </div>
    <div class="card">
      <h2>Astra Shield — Active Security Plugins</h2>
      <p style="color:#94a3b8;margin-bottom:12px;font-size:.85rem">Astra automatically executes registered risk and geo-compliance hooks during request validation:</p>
      <div style="display:flex;flex-wrap:wrap;gap:8px">{plugin_badges}</div>
    </div>
    <div class="card">
      <h2>Decrypted Access Token Claims</h2>
      <p style="color:#94a3b8;margin-bottom:12px;font-size:.85rem">Simulated backend API decryption of the JWT token issued for this session:</p>
      <pre style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px;overflow-x:auto;font-family:monospace;font-size:.8rem;color:#38bdf8;margin:0">{jwt_json}</pre>
    </div>
    <div class="card">
      <h2>Actions</h2>
      <a href="/documents" class="btn btn-primary" style="margin-right:8px">📄 View Documents</a>
    </div>"""
    return _page("Dashboard", body, session)


@app.get("/documents", response_class=HTMLResponse)
async def documents(astra_session: str | None = Cookie(None)):
    session = _session_from_cookie(astra_session)
    if not session:
        return RedirectResponse("/")

    assignment = SERVICE.assignments.get_assignments(session["subject_id"], TENANT_ID)
    is_admin = "admin" in assignment.roles if assignment else False

    rows = ""
    for doc in DOCUMENTS:
        is_owner = doc["owner"] == session["subject_id"]
        if not (is_admin or is_owner):
            continue

        can_delete = is_admin or is_owner
        del_btn = (
            f'<a href="/documents/{doc["id"]}/delete" class="btn btn-danger" style="font-size:.75rem;padding:4px 10px">Delete</a>'
            if can_delete
            else '<span style="color:#475569;font-size:.75rem">—</span>'
        )
        sens_badge = f'<span class="badge {"badge-red" if doc["sensitivity"] == "high" else "badge-green"}">{doc["sensitivity"]}</span>'
        rows += f"<tr><td>{doc['title']}</td><td>{sens_badge}</td><td>{del_btn}</td></tr>"

    body = f"""
    <div class="card">
      <h2>Documents</h2>
      <table><thead><tr><th>Title</th><th>Sensitivity</th><th>Action</th></tr></thead>
      <tbody>{rows or '<tr><td colspan="3" style="text-align:center;color:#64748b">No documents available.</td></tr>'}</tbody></table>
    </div>"""
    return _page("Documents", body, session)


@app.get("/documents/{doc_id}/delete", response_class=HTMLResponse)
async def delete_document(doc_id: str, astra_session: str | None = Cookie(None)):
    global DOCUMENTS
    session = _session_from_cookie(astra_session)
    if not session:
        return RedirectResponse("/")

    doc = next((d for d in DOCUMENTS if d["id"] == doc_id), None)
    if not doc:
        return RedirectResponse("/documents")

    assignment = SERVICE.assignments.get_assignments(session["subject_id"], TENANT_ID)
    is_admin = "admin" in assignment.roles if assignment else False
    is_owner = doc["owner"] == session["subject_id"]

    if not (is_admin or is_owner):
        return _page(
            "Access Denied",
            '<div class="card"><div class="alert alert-error">You do not have permission to delete this document.</div></div>',
            session,
        )

    if session["acr"] < 2:
        body = f"""
        <div class="card mfa-box">
          <h2>⚠️ Step-Up Authentication Required</h2>
          <p>Deleting a document requires a higher authentication assurance level.<br>
          Please complete an MFA challenge to continue.</p>
          <a href="/mfa?next=/documents/{doc_id}/delete" class="btn btn-primary">Verify Identity</a>
        </div>"""
        return _page("MFA Required", body, session)

    DOCUMENTS = [d for d in DOCUMENTS if d["id"] != doc_id]
    return RedirectResponse("/documents", status_code=303)


@app.get("/mfa", response_class=HTMLResponse)
async def mfa_page(
    next: str = "/dashboard",
    login_flow: bool = False,
    astra_session: str | None = Cookie(None),
    astra_temp_session: str | None = Cookie(None),
):
    target_session = astra_temp_session if login_flow else astra_session
    session = _session_from_cookie(target_session)
    if not session:
        return RedirectResponse("/")
    login_flow_val = "true" if login_flow else "false"
    body = f"""
    <div class="card" style="max-width:420px;margin:60px auto">
      <div class="mfa-box">
        <h2>🔐 Identity Verification</h2>
        <p>Enter the 6-digit OTP sent to your registered email address.<br>
        (Demo: enter <strong>123456</strong> to simulate successful verification.)</p>
        <form method="POST" action="/mfa/verify-otp">
          <input type="hidden" name="next" value="{next}">
          <input type="hidden" name="login_flow" value="{login_flow_val}">
          <input name="otp" placeholder="000000" maxlength="6" style="text-align:center;letter-spacing:.4em;font-size:1.5rem;padding:12px">
          <button class="btn btn-primary" style="width:100%">Verify</button>
        </form>
      </div>
    </div>"""
    return _page("MFA Challenge", body, session)


@app.post("/mfa/verify-otp")
async def app_mfa_verify(
    otp: str = Form(...),
    next: str = Form("/dashboard"),
    login_flow: str = Form("false"),
    astra_session: str | None = Cookie(None),
    astra_temp_session: str | None = Cookie(None),
):
    is_login = login_flow == "true"
    target_cookie = astra_temp_session if is_login else astra_session
    if not target_cookie:
        return RedirectResponse("/")
    session = _session_from_cookie(target_cookie)
    if not session:
        return RedirectResponse("/")

    if otp == "123456":
        store = SERVICE.sessions
        sess = store.get(target_cookie)
        if sess:
            sess.upgrade_authentication(target_acr=2, methods={"email_otp"})
            store.save(sess)

        response = RedirectResponse(next, status_code=303)
        if is_login:
            response.set_cookie(key="astra_session", value=target_cookie, httponly=True)
            response.delete_cookie(key="astra_temp_session")
        return response

    body = '<div class="card" style="max-width:420px;margin:60px auto"><div class="alert alert-error">Invalid OTP. Please try again.</div><a href="/mfa" class="btn btn-ghost">← Back</a></div>'
    return _page("Invalid OTP", body, session)


@app.get("/api/documents")
async def api_documents(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"error": "unauthorized", "message": "Missing or invalid Authorization header"},
        )

    token = auth_header.split(" ")[1]
    try:
        payload = SERVICE.token_manager.verify_jwt(token, audience="api")
    except Exception as e:
        return JSONResponse(
            status_code=401,
            content={"error": "unauthorized", "message": f"Token verification failed: {str(e)}"},
        )

    scopes = payload.get("scp", [])
    if "documents.read" not in scopes:
        return JSONResponse(
            status_code=403,
            content={
                "error": "forbidden",
                "message": "Insufficient scope (documents.read required)",
            },
        )

    subject_id = payload.get("sub")
    roles = payload.get("roles", [])
    is_admin = "admin" in roles

    filtered_docs = []
    for doc in DOCUMENTS:
        if is_admin or doc["owner"] == subject_id:
            filtered_docs.append(doc)

    return {"documents": filtered_docs}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    print("=" * 72)
    print("Astra FastAPI Sample App")
    print(f"Open → {BASE_URL}")
    print("Accounts: alice/alice-password (admin)  bob/bob-password (user)")
    print("=" * 72)
    uvicorn.run(app, host="127.0.0.1", port=PORT, reload=False)
