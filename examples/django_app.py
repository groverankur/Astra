# ruff: noqa: E402
"""Astra Django Sample App — Polished E2E Example.

Demonstrates: login/logout, session management, RBAC-gated routes,
and step-up MFA on sensitive actions using Django served via ASGI (Uvicorn).

Run:
    uv run python examples/django_app.py

Then open http://127.0.0.1:8080 in your browser.

Credentials:
    alice / alice-password  →  admin  (can read + delete documents)
    bob   / bob-password    →  user   (can read documents only)
"""

from __future__ import annotations

import logging
from os import getenv
from typing import Any

from django.conf import settings

# ---------------------------------------------------------------------------
# Setup logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("astra.example.django")

TENANT_ID = "demo"
CLIENT_ID = "demo-app"
PORT = int(getenv("PORT", "8080"))
BASE_URL = getenv("BASE_URL", f"http://127.0.0.1:{PORT}")

# ---------------------------------------------------------------------------
# Global configurations & states
# ---------------------------------------------------------------------------
REQUIRE_LOGIN_MFA = False

# ---------------------------------------------------------------------------
# Hardcoded demo data
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
# Configure Django Settings before importing anything else from Django
# ---------------------------------------------------------------------------
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY="demo-only-change-in-production",
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["*"],
        MIDDLEWARE=[
            "django.middleware.common.CommonMiddleware",
        ],
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
        ],
        TEMPLATES=[
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "APP_DIRS": True,
            }
        ],
    )

import django

django.setup()

from datetime import UTC, datetime

from django.core.asgi import get_asgi_application
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.template import Context, Template
from django.urls import path
from django.utils.http import url_has_allowed_host_and_scheme

from astraauth.adapters import AdapterOriginPolicy
from astraauth.adapters.django.wiring import build_urlpatterns as build_astra_urlpatterns
from astraauth.core.adapters.http_types import NormalizedRequestContext
from astraauth.core.authorization.models import Decision, PolicyRule, Role
from astraauth.core.authorization.store import InMemoryPolicyStore
from astraauth.core.oauth.models import OAuthClient, Subject
from astraauth.idp import GroupRoleMapping, OIDCProviderConfig
from astraauth.service import AstraAuthService, build_inmemory_service
from astraauth.webauthn.models import WebAuthnCredential


# ---------------------------------------------------------------------------
# Service bootstrap
# ---------------------------------------------------------------------------
def _build_service() -> AstraAuthService:
    svc = build_inmemory_service(default_plugins_enabled=True)
    svc.add_role(
        Role(
            name="admin",
            permissions={"openid", "documents.read", "documents.delete", "users.manage"},
        )
    )
    svc.add_role(Role(name="user", permissions={"openid", "documents.read"}))

    # ABAC Policy
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

    # Seed WebAuthn mock credentials
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
# UI Helpers & CSS
# ---------------------------------------------------------------------------
CSS = """
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
  .topbar{background:#1e293b;border-bottom:1px solid #334155;padding:12px 24px;display:flex;align-items:center;justify-content:space-between}
  .topbar h1{font-size:1.1rem;font-weight:700;color:#3b82f6;letter-spacing:.5px}
  .user-pill{background:#334155;border-radius:999px;padding:4px 14px;font-size:.8rem;color:#94a3b8}
  .container{max-width:900px;margin:40px auto;padding:0 20px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:20px}
  .card h2{font-size:1rem;font-weight:600;color:#93c5fd;margin-bottom:14px}
  .badge{display:inline-block;border-radius:999px;padding:3px 10px;font-size:.75rem;font-weight:600;margin:2px}
  .badge-green{background:#064e3b;color:#6ee7b7}.badge-blue{background:#1e3a5f;color:#93c5fd}.badge-red{background:#4c0519;color:#fca5a5}
  table{width:100%;border-collapse:collapse;font-size:.875rem}
  th{text-align:left;padding:8px 12px;color:#64748b;border-bottom:1px solid #334155;font-weight:500}
  td{padding:10px 12px;border-bottom:1px solid #1e293b}
  tr:last-child td{border-bottom:none}
  .btn{display:inline-block;padding:8px 18px;border-radius:8px;font-size:.85rem;font-weight:600;cursor:pointer;border:none;text-decoration:none;transition:opacity .15s}
  .btn-primary{background:#2563eb;color:#fff}.btn-danger{background:#dc2626;color:#fff}.btn-ghost{background:#334155;color:#e2e8f0}
  .btn:hover{opacity:.85}
  input{background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;padding:9px 14px;font-size:.9rem;width:100%;margin-bottom:12px}
  .alert-error{background:#4c0519;color:#fca5a5;border:1px solid #7f1d1d;padding:10px 16px;border-radius:8px;margin-bottom:16px}
  nav a{color:#94a3b8;text-decoration:none;margin-right:18px;font-size:.875rem}
  nav a:hover{color:#e2e8f0}
</style>
"""


def _session_info(request: HttpRequest) -> dict[str, Any] | None:
    sid = request.COOKIES.get("astra_session")
    if not sid:
        return None
    store = SERVICE.sessions
    sess = store.get(sid)
    if sess is None or sess.is_expired():
        return None
    subject = SERVICE.subjects.get_subject(sess.subject_id)
    username = subject.username if (subject and subject.username) else sess.subject_id
    return {"session_id": sid, "subject_id": sess.subject_id, "acr": sess.acr, "username": username}


class HTMLResponse(HttpResponse):
    def __init__(self, content: str = "", *args: Any, **kwargs: Any) -> None:
        super().__init__(content, *args, content_type="text/html; charset=utf-8", **kwargs)


def _page(title: str, body: str, session: dict | None = None) -> HttpResponse:
    nav = user_pill = ""
    if session:
        nav = '<nav><a href="/dashboard">Dashboard</a><a href="/documents">Documents</a><a href="/signout">Logout</a></nav>'
        user_pill = (
            f'<span class="user-pill">👤 {session["username"]} · ACR {session["acr"]}</span>'
        )
    template_str = """<!doctype html><html><head><meta charset=utf-8><title>{{ title }} — Astra Django</title>{{ css|safe }}</head><body>
<div class="topbar"><h1>🛡️ Astra · Django</h1><div style="display:flex;align-items:center;gap:16px">{{ nav|safe }}{{ user_pill|safe }}</div></div>
<div class="container">{{ body|safe }}</div></body></html>"""
    t = Template(template_str)
    c = Context(
        {
            "title": title,
            "css": CSS,
            "nav": nav,
            "user_pill": user_pill,
            "body": body,
        }
    )
    return HTMLResponse(t.render(c))


# ---------------------------------------------------------------------------
def index_view(request: HttpRequest) -> HttpResponse:
    if _session_info(request):
        return HttpResponseRedirect("/dashboard")
    body = """<div class="card" style="max-width:400px;margin:80px auto">
      <h2>Sign In</h2>
      <form method="POST" action="/login">
        <input name="username" placeholder="Username (alice or bob)" required>
        <input name="password" type="password" placeholder="Password" required>
        <button class="btn btn-primary" style="width:100%">Sign In</button>
      </form>
      <div style="margin-top:16px;display:flex;flex-direction:column;gap:8px">
        <a href="/oidc/mock/login" class="btn btn-ghost" style="width:100%;text-align:center;background:#1e3a5f;color:#93c5fd">🌐 Sign In with Google (Mock OIDC)</a>
        <a href="/webauthn/mock/login" class="btn btn-ghost" style="width:100%;text-align:center;background:#064e3b;color:#6ee7b7">🔑 Sign In with Passkey (Mock WebAuthn)</a>
      </div>
      <p style="margin-top:12px;font-size:.78rem;color:#64748b;text-align:center">alice/alice-password → admin &nbsp;|&nbsp; bob/bob-password → user</p>
    </div>"""
    return _page("Login", body)


def login_view(request: HttpRequest) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseRedirect("/")
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    req = NormalizedRequestContext(
        http_method="POST",
        request_path="/token",
        query_params={},
        headers={},
        cookies={},
        client_ip="127.0.0.1",
        body_json=None,
        form_data={
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
        body = '<div class="card" style="max-width:400px;margin:80px auto"><div class="alert-error">Invalid credentials.</div><a href="/" class="btn btn-ghost">← Back</a></div>'
        return _page("Login Failed", body)
    body_dict = resp.body if isinstance(resp.body, dict) else {}
    payload = SERVICE.token_manager.verify_jwt(
        str(body_dict.get("access_token") or ""), audience="api"
    )
    sid = payload["sid"]

    if REQUIRE_LOGIN_MFA:
        response = HttpResponseRedirect("/mfa?next=/dashboard&login_flow=true")
        response.set_cookie("astra_temp_session", sid, httponly=True, samesite="Lax", secure=False)
        return response

    response = HttpResponseRedirect("/dashboard")
    response.set_cookie("astra_session", sid, httponly=True, samesite="Lax", secure=False)
    return response


def oidc_mock_login_view(request: HttpRequest) -> HttpResponse:
    req = NormalizedRequestContext(
        http_method="POST",
        request_path="/oidc/login/start",
        query_params={},
        headers={},
        client_ip="127.0.0.1",
        body_json={
            "provider_id": "oidc-google",
            "tenant_id": TENANT_ID,
            "redirect_uri": f"{BASE_URL}/oidc/callback",
        },
    )
    resp = SERVICE.adapter.handle_oidc_login_start(req)
    if resp.status != 302:
        return _page(
            "OIDC Error",
            f'<div class="card"><div class="alert-error">OIDC Init failed. Status: {resp.status}</div></div>',
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
    )
    callback_resp = SERVICE.adapter.handle_oidc_callback(callback_req)
    if callback_resp.status != 200:
        return _page(
            "OIDC Error",
            f'<div class="card"><div class="alert-error">Callback failed: {callback_resp.body}</div></div>',
        )

    body_dict = callback_resp.body if isinstance(callback_resp.body, dict) else {}
    payload = SERVICE.token_manager.verify_jwt(
        str(body_dict.get("access_token") or ""), audience="api"
    )
    sid = payload["sid"]

    if REQUIRE_LOGIN_MFA:
        response = HttpResponseRedirect("/mfa?next=/dashboard&login_flow=true")
        response.set_cookie("astra_temp_session", sid, httponly=True, samesite="Lax", secure=False)
        return response

    response = HttpResponseRedirect("/dashboard")
    response.set_cookie("astra_session", sid, httponly=True, samesite="Lax", secure=False)
    return response


def webauthn_mock_login_view(request: HttpRequest) -> HttpResponse:
    req = NormalizedRequestContext(
        http_method="POST",
        request_path="/token",
        query_params={},
        headers={},
        cookies={},
        client_ip="127.0.0.1",
        body_json=None,
        form_data={
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
            f'<div class="card"><div class="alert-error">Handshake failed: {resp.body}</div></div>',
        )

    body_dict = resp.body if isinstance(resp.body, dict) else {}
    session_id = str(body_dict.get("session_id") or "")
    state_id = str(body_dict.get("state_id") or "")

    finish_req = NormalizedRequestContext(
        http_method="POST",
        request_path="/webauthn/authenticate/finish",
        query_params={},
        headers={},
        cookies={},
        client_ip="127.0.0.1",
        body_json=None,
        form_data={
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
            f'<div class="card"><div class="alert-error">Passkey verification failed: {finish_resp.body}</div></div>',
        )

    finish_body = finish_resp.body if isinstance(finish_resp.body, dict) else {}
    payload = SERVICE.token_manager.verify_jwt(
        str(finish_body.get("access_token") or ""), audience="api"
    )
    sid = payload["sid"]

    response = HttpResponseRedirect("/dashboard")
    response.set_cookie("astra_session", sid, httponly=True, samesite="Lax", secure=False)
    return response


def signout_view(request: HttpRequest) -> HttpResponse:
    sid = request.COOKIES.get("astra_session")
    if sid:
        req = NormalizedRequestContext(
            http_method="POST",
            request_path="/logout",
            query_params={},
            headers={},
            form_data={"astra_session": sid},
            cookies={"astra_session": sid},
            client_ip="127.0.0.1",
            body_json={"session_id": sid},
        )
        SERVICE.adapter.handle_logout(req)
    response = HttpResponseRedirect("/")
    response.delete_cookie("astra_session")
    response.delete_cookie("astra_temp_session")
    return response


def update_settings_view(request: HttpRequest) -> HttpResponse:
    session = _session_info(request)
    if not session:
        return HttpResponseRedirect("/")
    assignment = SERVICE.assignments.get_assignments(session["subject_id"], TENANT_ID)
    is_admin = "admin" in assignment.roles if assignment else False
    if not is_admin:
        return _page(
            "Forbidden",
            '<div class="card"><div class="alert-error">Admin permissions required.</div></div>',
        )

    global REQUIRE_LOGIN_MFA
    REQUIRE_LOGIN_MFA = request.POST.get("mfa_enabled") == "true"
    return HttpResponseRedirect("/dashboard")


def dashboard_view(request: HttpRequest) -> HttpResponse:
    session = _session_info(request)
    if not session:
        return HttpResponseRedirect("/")
    uid = session["subject_id"]
    engine = SERVICE.adapter._authorization_engine
    perms = engine.resolve_permissions(subject_id=uid, tenant_id=TENANT_ID)
    assignment = SERVICE.assignments.get_assignments(uid, TENANT_ID)
    roles = assignment.roles if assignment else set()
    is_admin = "admin" in roles

    user_token = SERVICE.token_manager.issue_jwt(
        subject=uid,
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
        "sub": uid,
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

    body = f"""<div class="card"><h2>Welcome, {session["username"]}</h2>
      <p style="color:#94a3b8;margin-bottom:14px">ACR level: {session["acr"]}</p>
      <p style="color:#64748b;font-size:.8rem">ROLES</p><div>{role_badges}</div>
      <p style="color:#64748b;font-size:.8rem;margin-top:12px">PERMISSIONS</p><div>{perm_badges}</div></div>
    {settings_card}
    <div class="card">
      <h2>Secure API Integration Test Panel</h2>
      <p style="color:#94a3b8;margin-bottom:12px;font-size:.85rem">Test access to the token-secured JSON endpoint <code>/api/documents</code>:</p>
      <pre style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px;overflow-x:auto;font-family:monospace;font-size:.8rem;color:#38bdf8;margin-bottom:12px;white-space:pre-wrap;word-break:break-all">curl -H "Authorization: Bearer {user_token}" {BASE_URL}/api/documents</pre>
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
    <div class="card"><h2>Actions</h2><a href="/documents" class="btn btn-primary">📄 View Documents</a></div>"""
    return _page("Dashboard", body, session)


def documents_view(request: HttpRequest) -> HttpResponse:
    session = _session_info(request)
    if not session:
        return HttpResponseRedirect("/")

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
            else "—"
        )
        sens = f'<span class="badge {"badge-red" if doc["sensitivity"] == "high" else "badge-green"}">{doc["sensitivity"]}</span>'
        rows += f"<tr><td>{doc['title']}</td><td>{sens}</td><td>{del_btn}</td></tr>"
    body = f'<div class="card"><h2>Documents</h2><table><thead><tr><th>Title</th><th>Sensitivity</th><th>Action</th></tr></thead><tbody>{rows or "<tr><td colspan=3 style='text-align:center;color:#64748b'>No documents available.</td></tr>"}</tbody></table></div>'
    return _page("Documents", body, session)


def delete_document_view(request: HttpRequest, doc_id: str) -> HttpResponse:
    global DOCUMENTS
    session = _session_info(request)
    if not session:
        return HttpResponseRedirect("/")

    doc = next((d for d in DOCUMENTS if d["id"] == doc_id), None)
    if not doc:
        return HttpResponseRedirect("/documents")

    assignment = SERVICE.assignments.get_assignments(session["subject_id"], TENANT_ID)
    is_admin = "admin" in assignment.roles if assignment else False
    is_owner = doc["owner"] == session["subject_id"]

    if not (is_admin or is_owner):
        return _page(
            "Access Denied",
            '<div class="card"><div class="alert-error">You do not have permission to delete this document.</div></div>',
        )

    if session["acr"] < 2:
        body = f"""<div class="card" style="max-width:420px;margin:60px auto;text-align:center">
          <h2 style="color:#fbbf24;margin-bottom:8px">⚠️ Step-Up Required</h2>
          <p style="color:#94a3b8;margin-bottom:20px">MFA verification required to delete documents.</p>
          <a href="/mfa?next=/documents/{doc_id}/delete" class="btn btn-primary">Verify Identity</a></div>"""
        return _page("MFA Required", body, session)
    DOCUMENTS = [d for d in DOCUMENTS if d["id"] != doc_id]
    return HttpResponseRedirect("/documents")


def mfa_view(request: HttpRequest) -> HttpResponse:
    login_flow = request.GET.get("login_flow") == "true"
    target_cookie = "astra_temp_session" if login_flow else "astra_session"

    sid = request.COOKIES.get(target_cookie)
    if not sid:
        return HttpResponseRedirect("/")

    store = SERVICE.sessions
    sess = store.get(sid)
    if not sess or sess.is_expired():
        return HttpResponseRedirect("/")

    subject = SERVICE.subjects.get_subject(sess.subject_id)
    username = subject.username if (subject and subject.username) else sess.subject_id
    session = {"session_id": sid, "username": username, "acr": sess.acr}

    next_url = request.GET.get("next", "/dashboard")
    login_flow_val = "true" if login_flow else "false"
    body = f"""<div class="card" style="max-width:400px;margin:60px auto;text-align:center">
      <h2 style="color:#fbbf24;margin-bottom:8px">🔐 Verify Identity</h2>
      <p style="color:#94a3b8;margin-bottom:20px">Enter OTP (demo: use <strong>123456</strong>)</p>
      <form method="POST" action="/mfa/verify-otp">
        <input type="hidden" name="next" value="{next_url}">
        <input type="hidden" name="login_flow" value="{login_flow_val}">
        <input name="otp" placeholder="000000" maxlength="6" style="text-align:center;letter-spacing:.4em;font-size:1.4rem">
        <button class="btn btn-primary" style="width:100%">Verify</button>
      </form></div>"""
    return _page("MFA", body, session)


def mfa_verify_otp_view(request: HttpRequest) -> HttpResponse:
    login_flow = request.POST.get("login_flow") == "true"
    target_cookie = "astra_temp_session" if login_flow else "astra_session"

    sid = request.COOKIES.get(target_cookie)
    if not sid:
        return HttpResponseRedirect("/")

    store = SERVICE.sessions
    sess = store.get(sid)
    if not sess or sess.is_expired():
        return HttpResponseRedirect("/")

    subject = SERVICE.subjects.get_subject(sess.subject_id)
    username = subject.username if (subject and subject.username) else sess.subject_id
    session = {"session_id": sid, "username": username, "acr": sess.acr}

    if request.method != "POST":
        return HttpResponseRedirect("/mfa")

    otp = request.POST.get("otp", "")
    next_url = request.POST.get("next", "/dashboard")
    if otp == "123456":
        sess.upgrade_authentication(target_acr=2, methods={"email_otp"})
        store.save(sess)
        # Ensure next_url is safe to prevent open redirect
        is_safe = url_has_allowed_host_and_scheme(
            url=next_url,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure(),
        )
        if not is_safe:
            next_url = "/dashboard"
        response = HttpResponseRedirect(next_url)
        if login_flow:
            response.set_cookie("astra_session", sid, httponly=True, samesite="Lax", secure=False)
            response.delete_cookie("astra_temp_session")
        return response
    return _page(
        "Invalid OTP",
        '<div class="card" style="max-width:400px;margin:60px auto"><div class="alert-error">Wrong OTP.</div><a href="/mfa" class="btn btn-ghost">Retry</a></div>',
        session,
    )


def api_documents_view(request: HttpRequest) -> HttpResponse:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JsonResponse(
            {"error": "unauthorized", "message": "Missing or invalid Authorization header"},
            status=401,
        )

    token = auth_header.split(" ")[1]
    try:
        payload = SERVICE.token_manager.verify_jwt(token, audience="api")
    except Exception as e:
        return JsonResponse(
            {"error": "unauthorized", "message": f"Token verification failed: {str(e)}"}, status=401
        )

    scopes = payload.get("scp", [])
    if "documents.read" not in scopes:
        return JsonResponse(
            {"error": "forbidden", "message": "Insufficient scope (documents.read required)"},
            status=403,
        )

    subject_id = payload.get("sub")
    roles = payload.get("roles", [])
    is_admin = "admin" in roles

    filtered_docs = []
    for doc in DOCUMENTS:
        if is_admin or doc["owner"] == subject_id:
            filtered_docs.append(doc)

    return JsonResponse({"documents": filtered_docs})


# ---------------------------------------------------------------------------
# URL Patterns
# ---------------------------------------------------------------------------
urlpatterns = [
    path("", index_view),
    path("login", login_view),
    path("oidc/mock/login", oidc_mock_login_view),
    path("webauthn/mock/login", webauthn_mock_login_view),
    path("signout", signout_view),
    path("admin/settings", update_settings_view),
    path("dashboard", dashboard_view),
    path("documents", documents_view),
    path("documents/<str:doc_id>/delete", delete_document_view),
    path("mfa", mfa_view),
    path("mfa/verify-otp", mfa_verify_otp_view),
    path("api/documents", api_documents_view),
] + build_astra_urlpatterns(
    adapter=SERVICE.adapter,
    issuer=BASE_URL,
    origin_policy=AdapterOriginPolicy(
        allowed_origins=frozenset({BASE_URL}),
        allowed_callback_origins=frozenset({BASE_URL}),
    ),
)

# ---------------------------------------------------------------------------
# ASGI application
# ---------------------------------------------------------------------------
application = get_asgi_application()

if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print("Astra Django Sample App")
    print(f"Open → {BASE_URL}")
    print("Accounts: alice/alice-password (admin)  bob/bob-password (user)")
    print("=" * 60)
    uvicorn.run("django_app:application", host="127.0.0.1", port=PORT, log_level="info")
