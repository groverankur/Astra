# ruff: noqa: E402
"""Better-Auth style demo and security dashboard for Astra.

Showcases advanced user profile cards, active session audits, real-time revocation,
multi-factor auth factor settings, and organization directories in an obsidian-themed
modern HTML5 SPA.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from os import getenv
from typing import Any

# ReBAC imports
from astraauth_policy import CheckEngine, RelationTuple, RelationTupleStore, SchemaParser
from fastapi import Cookie, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from astraauth.adapters import AdapterOriginPolicy
from astraauth.adapters.fastapi.wiring import mount_oauth
from astraauth.core.adapters.http_types import NormalizedRequestContext
from astraauth.core.authorization.models import Role
from astraauth.core.oauth.models import OAuthClient, Subject
from astraauth.service import AstraAuthService, build_inmemory_service

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("astraauth.better_auth_demo")

APP_BASE_URL = getenv("ASTRAAUTH_EXAMPLE_BASE_URL", "http://127.0.0.1:8000")
TENANT_ID = "tenant-1"
CLIENT_ID = "client-1"

# Hardcoded demo credentials
DEMO_USERS: dict[str, dict[str, Any]] = {
    "alice": {
        "id": "user-1",
        "password": "password123",
        "department": "Platform",
        "roles": {"admin", "user"},
        "email": "alice@example.com",
    },
    "bob": {
        "id": "user-2",
        "password": "password123",
        "department": "Sales",
        "roles": {"user"},
        "email": "bob@example.com",
    },
}

# Session metadata (stores user-agent and IP)
SESSION_METADATA: dict[str, dict[str, str]] = {}

# Zanzibar Schema Definition
ZANZIBAR_SCHEMA = """
definition user {}

definition organization {
    relation owner: user
    relation admin: user
    relation member: user

    permission manage = owner | admin
    permission view = manage | member
}
"""


def _request(
    *,
    method: str,
    path: str,
    form_data: Mapping[str, str] | None = None,
    query_params: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    cookies: Mapping[str, str] | None = None,
) -> NormalizedRequestContext:
    return NormalizedRequestContext(
        http_method=method,
        request_path=path,
        query_params=dict(query_params or {}),
        headers=dict(headers or {}),
        form_data=dict(form_data or {}),
        cookies=dict(cookies or {}),
    )


def _seed_service() -> tuple[AstraAuthService, CheckEngine]:
    service = build_inmemory_service(default_plugins_enabled=True)

    # Seed core auth profiles
    for username, data in DEMO_USERS.items():
        subject = Subject(
            subject_id=data["id"],
            tenants={TENANT_ID},
            username=username,
        )
        service.add_subject_password(
            subject=subject,
            tenant_id=TENANT_ID,
            username=username,
            password=data["password"],
        )
        service.assign_roles(subject_id=data["id"], tenant_id=TENANT_ID, roles=data["roles"])
        email_factor_id = service.enroll_subject_email_otp(
            subject_id=data["id"],
            tenant_id=TENANT_ID,
            email=data["email"],
        )
        service.activate_subject_email_otp(factor_id=email_factor_id)

    # Add core roles
    service.add_role(Role(name="user", permissions={"openid", "org.view"}))
    service.add_role(
        Role(name="admin", permissions={"openid", "org.view", "org.manage", "org.invite"})
    )

    # Add client
    service.add_client(
        OAuthClient(
            client_id=CLIENT_ID,
            redirect_uris={f"{APP_BASE_URL}/oidc/callback"},
            allowed_scopes={"openid"},
            allowed_tenants={TENANT_ID},
            client_type="public",
            auth_method="none",
            require_pkce=False,
        )
    )

    # Compile ReBAC/Zanzibar schemas
    parsed_schema = SchemaParser.parse(ZANZIBAR_SCHEMA)
    tuple_store = RelationTupleStore()

    # Seed initial ReBAC relationship tuples
    tuple_store.tuples.append(
        RelationTuple(
            id="t-1",
            tenant_id=TENANT_ID,
            object_type="organization",
            object_id="org-1",
            relation="owner",
            subject_type="user",
            subject_id="user-1",
        )
    )
    tuple_store.tuples.append(
        RelationTuple(
            id="t-2",
            tenant_id=TENANT_ID,
            object_type="organization",
            object_id="org-1",
            relation="member",
            subject_type="user",
            subject_id="user-2",
        )
    )

    rebac_engine = CheckEngine(store=tuple_store, schema=parsed_schema)
    return service, rebac_engine


SERVICE, CHECK_ENGINE = _seed_service()
APP = FastAPI(
    title="Astra Better-Auth Demo",
    version="1.0.0",
)

ORIGIN_POLICY = AdapterOriginPolicy(
    allowed_origins=frozenset({APP_BASE_URL}),
    allowed_callback_origins=frozenset({APP_BASE_URL}),
)
mount_oauth(APP, SERVICE.adapter, origin_policy=ORIGIN_POLICY)


# ============================================================
# Helpers & Session Parsing
# ============================================================


def get_current_session(session_id: str | None) -> Any | None:
    if not session_id:
        return None
    return SERVICE.sessions.get(session_id)


def get_session_context(session_id: str | None) -> dict[str, Any] | None:
    session = get_current_session(session_id)
    if not session or session.revoked or session.is_expired():
        return None

    subject_id = session.subject_id
    username = "unknown"
    department = "none"
    email = ""
    roles = []

    # Try looking in DEMO_USERS
    for uname, data in DEMO_USERS.items():
        if data["id"] == subject_id:
            username = uname
            department = data["department"]
            email = data["email"]
            roles = list(data["roles"])
            break

    return {
        "session_id": session.session_id,
        "subject_id": subject_id,
        "username": username,
        "email": email,
        "department": department,
        "roles": roles,
        "acr": session.acr,
    }


def parse_user_agent(ua_string: str) -> dict[str, str]:
    ua = ua_string.lower()
    # Detect Browser
    if "edge" in ua or "edg/" in ua:
        browser = "Edge"
    elif "chrome" in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua:
        browser = "Safari"
    else:
        browser = "Browser"

    # Detect OS
    if "windows" in ua:
        os = "Windows"
    elif "macintosh" in ua or "mac os x" in ua:
        os = "macOS"
    elif "linux" in ua:
        os = "Linux"
    elif "android" in ua:
        os = "Android"
    elif "iphone" in ua or "ipad" in ua:
        os = "iOS"
    else:
        os = "OS"

    return {"browser": browser, "os": os}


# ============================================================
# Frontend HTML5 SPA Template (Obsidian Themed)
# ============================================================

HTML_SPA_TEMPLATE = """<!DOCTYPE html>
<html lang="en" class="h-full bg-[#161616] text-[#e0e0e0]">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Astra Vault Console</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }
        .code-font {
            font-family: 'Fira Code', monospace;
        }
        /* Obsidian specific styles */
        .obsidian-sidebar {
            background-color: #1e1e1e;
            border-right: 1px solid #2e2e2e;
        }
        .obsidian-border {
            border: 1px solid #2e2e2e;
        }
        .obsidian-card {
            background-color: #242424;
            border: 1px solid #2e2e2e;
        }
        .obsidian-input {
            background-color: #1a1a1a;
            border: 1px solid #3a3a3a;
            color: #e0e0e0;
        }
        .obsidian-input:focus {
            border-color: #7c3aed;
            outline: none;
        }
        .active-tab {
            background-color: rgba(124, 58, 237, 0.08);
            color: #a78bfa;
            border-left: 2px solid #7c3aed;
        }
    </style>
</head>
<body class="h-full flex flex-col antialiased">
    <div id="app" class="min-h-screen flex flex-col">
        <!-- Auth View Container -->
        <div id="auth-container" class="hidden flex-1 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 bg-[#161616]">
            <div class="max-w-md w-full space-y-8 obsidian-card p-8 rounded-xl shadow-2xl">
                <div class="text-center">
                    <div class="inline-flex p-3 rounded-full bg-purple-500/10 text-purple-400 mb-3 border border-purple-500/20">
                        <i data-lucide="shield-check" class="w-8 h-8"></i>
                    </div>
                    <h2 class="text-3xl font-extrabold tracking-tight text-white">Astra Vault Console</h2>
                    <p class="mt-2 text-xs text-slate-400">Enter credentials to decrypt security configuration</p>
                </div>
                <div id="auth-error-banner" class="hidden p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-semibold rounded-lg text-center"></div>
                <!-- Tabs Selector -->
                <div class="flex border-b border-[#2e2e2e]">
                    <button onclick="toggleAuthMode('signin')" id="btn-tab-signin" class="w-1/2 py-2.5 text-sm font-semibold border-b-2 border-purple-500 text-white">Decrypt Vault (Sign In)</button>
                    <button onclick="toggleAuthMode('signup')" id="btn-tab-signup" class="w-1/2 py-2.5 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200">Initialize Identity (Sign Up)</button>
                </div>
                <!-- Form Login -->
                <form id="auth-form" onsubmit="handleAuthSubmit(event)" class="space-y-4">
                    <div id="signup-fields" class="hidden space-y-4">
                        <div>
                            <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider">Email Address</label>
                            <input type="email" id="auth-email" placeholder="you@example.com" class="mt-1 block w-full px-4 py-2.5 rounded-lg obsidian-input text-sm">
                        </div>
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider">Username</label>
                        <input type="text" id="auth-username" required placeholder="e.g. alice" class="mt-1 block w-full px-4 py-2.5 rounded-lg obsidian-input text-sm">
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider">Password</label>
                        <input type="password" id="auth-password" required placeholder="••••••••" class="mt-1 block w-full px-4 py-2.5 rounded-lg obsidian-input text-sm">
                    </div>
                    <button type="submit" id="auth-submit-btn" class="w-full py-3 bg-purple-600 hover:bg-purple-500 transition text-sm font-semibold rounded-lg text-white shadow-lg shadow-purple-600/25 mt-2">
                        Open Vault
                    </button>
                </form>
                <div class="relative flex py-2 items-center">
                    <div class="flex-grow border-t border-[#2e2e2e]"></div>
                    <span class="flex-shrink mx-4 text-slate-500 text-[10px] font-bold uppercase tracking-wider">Default Users</span>
                    <div class="flex-grow border-t border-[#2e2e2e]"></div>
                </div>
                <div class="text-center text-xs text-slate-400 space-y-1">
                    <p>alice / password123 (admin)</p>
                    <p>bob / password123 (user)</p>
                </div>
            </div>
        </div>

        <!-- Dashboard View Container -->
        <div id="dashboard-container" class="hidden flex-1 flex overflow-hidden">
            <!-- Sidebar -->
            <div class="w-64 obsidian-sidebar flex flex-col justify-between">
                <div>
                    <div class="p-6 border-b border-[#2e2e2e] flex items-center gap-3">
                        <div class="p-2 rounded-lg bg-purple-600 text-white">
                            <i data-lucide="shield" class="w-5 h-5"></i>
                        </div>
                        <div>
                            <h1 class="font-bold text-white text-sm leading-none">Astra Vault</h1>
                            <span class="text-[9px] text-slate-500 uppercase tracking-widest font-extrabold">Obsidian Portal</span>
                        </div>
                    </div>
                    <!-- File Navigation Explorer -->
                    <div class="p-4 space-y-4">
                        <div class="space-y-1">
                            <div class="flex items-center gap-2 px-2 py-1.5 text-xs font-bold text-slate-500 uppercase tracking-wider">
                                <i data-lucide="folder" class="w-3.5 h-3.5 text-yellow-500/80"></i> Vault Explorer
                            </div>
                            <div class="pl-3 space-y-0.5">
                                <button onclick="showPanel('profile')" id="nav-btn-profile" class="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg text-slate-400 hover:bg-[#2d2d2d] hover:text-slate-100 transition text-left">
                                    <i data-lucide="file-json" class="w-3.5 h-3.5 text-purple-400"></i> user_profile.json
                                </button>
                                <button onclick="showPanel('sessions')" id="nav-btn-sessions" class="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg text-slate-400 hover:bg-[#2d2d2d] hover:text-slate-100 transition text-left">
                                    <i data-lucide="database" class="w-3.5 h-3.5 text-blue-400"></i> active_sessions.db
                                </button>
                                <button onclick="showPanel('mfa')" id="nav-btn-mfa" class="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg text-slate-400 hover:bg-[#2d2d2d] hover:text-slate-100 transition text-left">
                                    <i data-lucide="shield-check" class="w-3.5 h-3.5 text-green-400"></i> mfa_settings.yaml
                                </button>
                                <button onclick="showPanel('org')" id="nav-btn-org" class="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg text-slate-400 hover:bg-[#2d2d2d] hover:text-slate-100 transition text-left">
                                    <i data-lucide="network" class="w-3.5 h-3.5 text-amber-400"></i> org_directory.toml
                                </button>
                                <button onclick="showPanel('system')" id="nav-btn-system" class="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg text-slate-400 hover:bg-[#2d2d2d] hover:text-slate-100 transition text-left">
                                    <i data-lucide="key" class="w-3.5 h-3.5 text-red-400"></i> jwks_rotation.pem
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Bottom Profile Summary -->
                <div class="p-4 border-t border-[#2e2e2e] bg-[#1a1a1a]/50 space-y-3">
                    <div class="flex items-center gap-3">
                        <div class="w-9 h-9 rounded-lg bg-[#2e2e2e] border border-[#3e3e3e] flex items-center justify-center font-bold text-purple-400" id="profile-avatar">
                            U
                        </div>
                        <div class="flex-1 min-w-0">
                            <p class="text-xs font-semibold text-white truncate" id="profile-name">User</p>
                            <p class="text-[10px] text-slate-500 truncate" id="profile-email">email@example.com</p>
                        </div>
                    </div>
                    <button onclick="handleLogout()" class="w-full flex items-center justify-center gap-2 py-2 px-3 text-xs font-semibold rounded-lg text-red-400 border border-red-500/20 hover:bg-red-500/10 transition">
                        <i data-lucide="log-out" class="w-3.5 h-3.5"></i> Lock Vault
                    </button>
                </div>
            </div>
            <!-- Content Workspace -->
            <div class="flex-1 overflow-y-auto p-8 bg-[#161616] relative" id="workspace">
                <!-- User Profile Dashboard Panel -->
                <div id="panel-profile" class="panel-view space-y-6">
                    <div>
                        <h2 class="text-2xl font-bold text-white tracking-tight">user_profile.json</h2>
                        <p class="text-xs text-slate-400">Decrypted subject identity details and cryptographic claims mapping</p>
                    </div>
                    <div class="grid grid-cols-3 gap-6">
                        <!-- Frontmatter metadata -->
                        <div class="col-span-2 space-y-6">
                            <div class="obsidian-card p-6 rounded-lg space-y-4">
                                <h3 class="font-bold text-xs uppercase tracking-wider text-slate-400 flex items-center gap-2">
                                    <i data-lucide="info" class="w-4 h-4 text-purple-400"></i> Metadata Properties
                                </h3>
                                <div class="grid grid-cols-2 gap-4 text-xs">
                                    <div class="bg-[#1a1a1a] p-3.5 rounded-lg border border-[#2d2d2d]">
                                        <span class="text-slate-500 block uppercase font-bold tracking-widest text-[9px] mb-1">Subject ID</span>
                                        <code class="text-white font-mono" id="card-subject-id">user-x</code>
                                    </div>
                                    <div class="bg-[#1a1a1a] p-3.5 rounded-lg border border-[#2d2d2d]">
                                        <span class="text-slate-500 block uppercase font-bold tracking-widest text-[9px] mb-1">Department</span>
                                        <span class="text-white font-semibold" id="card-department">Platform</span>
                                    </div>
                                    <div class="bg-[#1a1a1a] p-3.5 rounded-lg border border-[#2d2d2d] col-span-2">
                                        <span class="text-slate-500 block uppercase font-bold tracking-widest text-[9px] mb-1">Roles Assigned</span>
                                        <div class="flex gap-2 mt-1" id="card-roles">
                                            <!-- Dynamic roles badges -->
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <!-- Decoded Token Inspector -->
                            <div class="obsidian-card p-6 rounded-lg space-y-4">
                                <div class="flex items-center justify-between">
                                    <h3 class="font-bold text-xs uppercase tracking-wider text-slate-400 flex items-center gap-2">
                                        <i data-lucide="code-2" class="w-4 h-4 text-blue-400"></i> Decoded ID Token Claims
                                    </h3>
                                    <button onclick="copyTokenClaims()" class="py-1 px-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] font-bold transition flex items-center gap-1.5">
                                        <i data-lucide="copy" class="w-3 h-3"></i> Copy JSON
                                    </button>
                                </div>
                                <pre class="bg-[#101010] p-4 rounded-lg border border-[#2a2a2a] text-xs text-green-400 code-font overflow-x-auto whitespace-pre" id="card-token-claims">{}</pre>
                            </div>
                        </div>

                        <!-- Right Panel Profile Card -->
                        <div class="space-y-6">
                            <div class="obsidian-card p-6 rounded-lg space-y-6 text-center">
                                <div class="w-20 h-20 mx-auto rounded-full bg-purple-600/10 border border-purple-500/20 flex items-center justify-center text-purple-400 text-2xl font-bold" id="card-avatar">
                                    U
                                </div>
                                <div>
                                    <h4 class="text-base font-bold text-white" id="card-name">Username</h4>
                                    <p class="text-xs text-slate-500" id="card-email">email@example.com</p>
                                </div>
                                <div class="border-t border-[#2e2e2e] pt-4 text-left text-xs space-y-2.5 text-slate-300">
                                    <div class="flex justify-between">
                                        <span class="text-slate-500">Security State</span>
                                        <span class="text-green-400 flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span> Decrypted</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-slate-500">Origin Policy</span>
                                        <span class="text-purple-400">Same-Origin Gated</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Active Sessions List Panel -->
                <div id="panel-sessions" class="panel-view hidden space-y-6">
                    <div>
                        <h2 class="text-2xl font-bold text-white tracking-tight">active_sessions.db</h2>
                        <p class="text-xs text-slate-400">Inspect device session registrations and revoke authentication contexts</p>
                    </div>
                    <div class="obsidian-card rounded-lg overflow-hidden">
                        <div class="p-5 border-b border-[#2e2e2e] flex items-center justify-between">
                            <h3 class="font-bold text-xs uppercase tracking-wider text-slate-400">Audited Logins</h3>
                            <span class="text-[9px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded uppercase">Live sessions audit</span>
                        </div>
                        <div class="divide-y divide-[#2e2e2e]" id="sessions-list">
                            <!-- Dynamic rows loaded here -->
                        </div>
                    </div>
                </div>

                <!-- MFA Management Settings Panel -->
                <div id="panel-mfa" class="panel-view hidden space-y-6">
                    <div>
                        <h2 class="text-2xl font-bold text-white tracking-tight">mfa_settings.yaml</h2>
                        <p class="text-xs text-slate-400">Configure multi-factor authentication and upgrade authentication levels</p>
                    </div>

                    <div class="grid grid-cols-3 gap-6">
                        <div class="col-span-2 space-y-6">
                            <!-- Security Shield Strength -->
                            <div class="obsidian-card p-6 rounded-lg flex items-center gap-6">
                                <div class="p-4 rounded-xl" id="acr-shield-container">
                                    <i data-lucide="shield-alert" class="w-12 h-12" id="acr-shield-icon"></i>
                                </div>
                                <div>
                                    <span class="text-[9px] font-bold text-slate-500 uppercase tracking-widest block">Authentication Level</span>
                                    <h3 class="text-xl font-bold text-white mt-0.5" id="acr-status-title">ACR Level 1 (Single Factor)</h3>
                                    <p class="text-xs text-slate-400 mt-1" id="acr-status-desc">Your session is only secured by username and password. Complete TOTP/OTP verification to upgrade.</p>
                                </div>
                            </div>

                            <!-- Available MFA Factors -->
                            <div class="obsidian-card p-6 rounded-lg space-y-4">
                                <h3 class="font-bold text-xs uppercase tracking-wider text-slate-400">Authentication Factors</h3>
                                <div class="space-y-3">
                                    <!-- Email OTP Status -->
                                    <div class="p-4 rounded-lg bg-[#1a1a1a] border border-[#2e2e2e] flex items-center justify-between">
                                        <div class="flex items-center gap-3">
                                            <div class="p-2 bg-purple-500/10 text-purple-400 rounded-lg">
                                                <i data-lucide="mail" class="w-5 h-5"></i>
                                            </div>
                                            <div>
                                                <p class="text-sm font-semibold text-white">Email OTP Code Verification</p>
                                                <span class="text-[9px] text-green-400 uppercase font-bold tracking-wider">Activated</span>
                                            </div>
                                        </div>
                                    </div>
                                    <!-- TOTP Factor Status -->
                                    <div class="p-4 rounded-lg bg-[#1a1a1a] border border-[#2e2e2e] flex items-center justify-between">
                                        <div class="flex items-center gap-3">
                                            <div class="p-2 bg-[#2d2d2d] text-slate-400 rounded-lg" id="totp-icon-container">
                                                <i data-lucide="smartphone" class="w-5 h-5"></i>
                                            </div>
                                            <div>
                                                <p class="text-sm font-semibold text-white">Time-based One-time Password (TOTP)</p>
                                                <span class="text-[9px] text-slate-500 uppercase font-bold tracking-wider" id="mfa-totp-status">Not Configured</span>
                                            </div>
                                        </div>
                                        <button onclick="enrollTOTP()" id="btn-totp-enroll" class="py-1.5 px-3 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold transition">
                                            Configure Factor
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- MFA sidebar details -->
                        <div class="space-y-6">
                            <div class="obsidian-card p-6 rounded-lg space-y-4">
                                <h4 class="font-bold text-xs uppercase tracking-wider text-slate-400 flex items-center gap-2">
                                    <i data-lucide="key-round" class="w-4 h-4 text-purple-400"></i> What is ACR?
                                </h4>
                                <p class="text-xs text-slate-400 leading-relaxed">
                                    <strong>Authentication Context Class Reference (ACR)</strong> defines the assurance level of your login session.
                                </p>
                                <ul class="text-xs text-slate-400 list-disc pl-4 space-y-1.5">
                                    <li><strong>ACR 1:</strong> Single factor (password only)</li>
                                    <li><strong>ACR 2:</strong> Multi-factor (completed password + second factor verification)</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Organization Directory Panel -->
                <div id="panel-org" class="panel-view hidden space-y-6">
                    <div>
                        <h2 class="text-2xl font-bold text-white tracking-tight">org_directory.toml</h2>
                        <p class="text-xs text-slate-400">Zanzibar-style Relationship-Based Access Control (ReBAC) mappings and tenant members list</p>
                    </div>

                    <div class="grid grid-cols-3 gap-6">
                        <!-- Members list -->
                        <div class="col-span-2 space-y-6">
                            <div class="obsidian-card rounded-lg overflow-hidden">
                                <div class="p-5 border-b border-[#2e2e2e] flex items-center justify-between">
                                    <h3 class="font-bold text-xs uppercase tracking-wider text-slate-400">Tenant Directory</h3>
                                    <span class="text-[9px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20 px-2 py-0.5 rounded uppercase">tenant-1 registry</span>
                                </div>
                                <div class="divide-y divide-[#2e2e2e]" id="members-list">
                                    <!-- Dynamic member list loaded here -->
                                </div>
                            </div>

                            <!-- Zanzibar ReBAC Policy check tester -->
                            <div class="obsidian-card p-6 rounded-lg space-y-4">
                                <h3 class="font-bold text-xs uppercase tracking-wider text-slate-400 flex items-center gap-2">
                                    <i data-lucide="file-check" class="w-4 h-4 text-blue-400"></i> Zanzibar Relation check engine
                                </h3>
                                <p class="text-xs text-slate-400">Directly query the relationship graph compiler using Zanzibar's schema logic.</p>
                                <div class="grid grid-cols-3 gap-4">
                                    <div>
                                        <label class="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Subject ID</label>
                                        <select id="rebac-subject" class="mt-1 block w-full px-3 py-2 rounded obsidian-input text-xs">
                                            <option value="user-1">user-1 (alice)</option>
                                            <option value="user-2">user-2 (bob)</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label class="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Relation / Perm</label>
                                        <select id="rebac-relation" class="mt-1 block w-full px-3 py-2 rounded obsidian-input text-xs">
                                            <option value="manage">manage (owner | admin)</option>
                                            <option value="view">view (manage | member)</option>
                                            <option value="owner">owner (direct relationship)</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label class="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Target Object</label>
                                        <select id="rebac-object" class="mt-1 block w-full px-3 py-2 rounded obsidian-input text-xs">
                                            <option value="org-1">organization:org-1</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="flex items-center justify-between border-t border-[#2e2e2e] pt-4 mt-2">
                                    <button onclick="testRebac()" class="py-2 px-4 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold transition">
                                        Run Query
                                    </button>
                                    <div id="rebac-result-banner" class="hidden px-3.5 py-1.5 rounded text-xs font-bold uppercase tracking-wider"></div>
                                </div>
                            </div>
                        </div>

                        <!-- Organization sidebar admin invite and Zanzibar rule info -->
                        <div class="space-y-6">
                            <!-- Invite Card -->
                            <div class="obsidian-card p-6 rounded-lg space-y-4">
                                <h3 class="font-bold text-xs uppercase tracking-wider text-slate-400">Update Organization Role</h3>
                                <form onsubmit="handleOrgInvite(event)" class="space-y-4">
                                    <div>
                                        <label class="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">User Profile</label>
                                        <select id="invite-subject" class="mt-1 block w-full px-4 py-2 rounded obsidian-input text-xs">
                                            <option value="alice">alice</option>
                                            <option value="bob">bob</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label class="block text-[10px] font-bold text-slate-500 uppercase tracking-widest">Assigned Role</label>
                                        <select id="invite-role" class="mt-1 block w-full px-4 py-2 rounded obsidian-input text-xs">
                                            <option value="user">User (Standard member)</option>
                                            <option value="admin">Admin (Manage access)</option>
                                        </select>
                                    </div>
                                    <button type="submit" class="w-full py-2 bg-purple-600 hover:bg-purple-500 transition text-xs font-semibold rounded-lg text-white">
                                        Update Role Mapping
                                    </button>
                                </form>
                            </div>

                            <!-- Zanzibar DSL Info Card -->
                            <div class="obsidian-card p-6 rounded-lg space-y-3">
                                <h4 class="font-bold text-xs uppercase tracking-wider text-slate-400 flex items-center gap-2">
                                    <i data-lucide="network" class="w-4 h-4 text-purple-400"></i> Zanzibar Relation Rules
                                </h4>
                                <pre class="bg-[#101010] p-3 rounded border border-[#2c2c2c] text-[10px] text-purple-300 code-font block whitespace-pre overflow-x-auto leading-tight">definition organization {
  relation owner: user
  relation admin: user
  relation member: user

  permission manage = owner | admin
  permission view = manage | member
}</pre>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Settings Diagnostics Panel -->
                <div id="panel-settings" class="panel-view hidden space-y-6">
                    <div>
                        <h2 class="text-2xl font-bold text-white tracking-tight">jwks_rotation.pem</h2>
                        <p class="text-xs text-slate-400">Rotate cryptographic keys and inspect in-memory JWKS configurations</p>
                    </div>

                    <div class="obsidian-card p-6 rounded-lg space-y-4">
                        <h3 class="font-bold text-xs uppercase tracking-wider text-slate-400">Rotational Operations</h3>
                        <p class="text-xs text-slate-400">Generate fresh signature key pairs. Verification keys are automatically published to the server's OpenID discovery endpoints.</p>
                        <div class="flex gap-4">
                            <button onclick="rotateKeys('sig')" class="py-2.5 px-4 bg-[#1a1a1a] border border-[#2e2e2e] text-slate-200 hover:bg-[#2d2d2d] rounded-lg text-xs font-semibold transition">
                                Rotate Signing Keys (RS256)
                            </button>
                            <button onclick="rotateKeys('enc')" class="py-2.5 px-4 bg-[#1a1a1a] border border-[#2e2e2e] text-slate-200 hover:bg-[#2d2d2d] rounded-lg text-xs font-semibold transition">
                                Rotate Encryption Keys (RSA_OAEP)
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- MFA TOTP Setup Dialog Modal -->
    <div id="mfa-setup-modal" class="fixed inset-0 bg-black/85 flex items-center justify-center hidden z-50 backdrop-blur-sm">
        <div class="obsidian-card max-w-sm w-full rounded-xl shadow-2xl p-6 space-y-6 text-center">
            <h3 class="text-lg font-bold text-white">Enroll Authenticator factor</h3>
            <p class="text-xs text-slate-400">Scan this code or manually enter the private key secret inside Google Authenticator or Duo.</p>
            <div class="bg-white p-3 rounded-lg inline-block" id="totp-qr-container">
                <!-- QR code simulated indicator -->
                <div class="w-36 h-36 border-4 border-slate-900 border-dashed flex items-center justify-center font-bold text-slate-900 text-xs">QR Code Mock</div>
            </div>
            <div class="text-left space-y-1">
                <span class="text-[9px] font-bold text-slate-500 uppercase tracking-widest">Secret Key</span>
                <code class="block bg-slate-950 p-2.5 rounded-lg border border-slate-900 text-xs font-mono text-center text-purple-400 select-all" id="totp-secret-key">SECRET_KEY_HERE</code>
            </div>
            <form onsubmit="handleTOTPVerify(event)" class="space-y-3">
                <input type="hidden" id="totp-enroll-factor-id">
                <input type="text" id="totp-code" required placeholder="000000" class="text-center tracking-widest text-base font-bold block w-full px-4 py-2.5 rounded-lg obsidian-input">
                <div class="flex gap-3">
                    <button type="button" onclick="closeMfaModal()" class="w-1/2 py-2.5 border border-[#2e2e2e] bg-[#1e1e1e] rounded-lg text-xs font-semibold text-slate-400">Cancel</button>
                    <button type="submit" class="w-1/2 py-2.5 bg-purple-600 hover:bg-purple-500 transition text-xs font-semibold rounded-lg text-white">Verify & Activate</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        let currentAuthMode = 'signin';
        let currentPanel = 'profile';
        let cachedToken = '';

        // Check if authenticated on page load
        document.addEventListener('DOMContentLoaded', () => {
            checkSession();
        });

        function toggleAuthMode(mode) {
            currentAuthMode = mode;
            const signinBtn = document.getElementById('btn-tab-signin');
            const signupBtn = document.getElementById('btn-tab-signup');
            const signupFields = document.getElementById('signup-fields');
            const submitBtn = document.getElementById('auth-submit-btn');
            if (mode === 'signup') {
                signinBtn.className = 'w-1/2 py-2.5 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200';
                signupBtn.className = 'w-1/2 py-2.5 text-sm font-semibold border-b-2 border-purple-500 text-white';
                signupFields.classList.remove('hidden');
                submitBtn.innerText = 'Initialize Identity';
            } else {
                signinBtn.className = 'w-1/2 py-2.5 text-sm font-semibold border-b-2 border-purple-500 text-white';
                signupBtn.className = 'w-1/2 py-2.5 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200';
                signupFields.classList.add('hidden');
                submitBtn.innerText = 'Open Vault';
            }
            lucide.createIcons();
        }

        function checkSession() {
            fetch('/api/user/session')
            .then(res => {
                if (res.ok) {
                    return res.json().then(data => {
                        showAppDashboard(data);
                    });
                } else {
                    showAppAuth();
                }
            })
            .catch(() => showAppAuth());
        }
        function showAppAuth() {
            document.getElementById('dashboard-container').classList.add('hidden');
            document.getElementById('auth-container').classList.remove('hidden');
            lucide.createIcons();
        }
        function showAppDashboard(user) {
            document.getElementById('auth-container').classList.add('hidden');
            document.getElementById('dashboard-container').classList.remove('hidden');
            // Set user profile sidebar details
            document.getElementById('profile-name').innerText = user.username;
            document.getElementById('profile-email').innerText = user.email;
            document.getElementById('profile-avatar').innerText = user.username.substring(0, 2).toUpperCase();
            // Set dashboard card details
            document.getElementById('card-name').innerText = user.username;
            document.getElementById('card-email').innerText = user.email;
            document.getElementById('card-avatar').innerText = user.username.substring(0, 2).toUpperCase();
            document.getElementById('card-subject-id').innerText = user.subject_id;
            document.getElementById('card-department').innerText = user.department;
            // Load Roles badges
            const rolesContainer = document.getElementById('card-roles');
            rolesContainer.innerHTML = '';
            user.roles.forEach(r => {
                const badge = document.createElement('span');
                badge.className = 'px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 uppercase font-bold tracking-wider text-[9px]';
                badge.innerText = r;
                rolesContainer.appendChild(badge);
            });
            // Set ACR indicators
            const shieldContainer = document.getElementById('acr-shield-container');
            const shieldIcon = document.getElementById('acr-shield-icon');
            const statusTitle = document.getElementById('acr-status-title');
            const statusDesc = document.getElementById('acr-status-desc');
            const totpStatus = document.getElementById('mfa-totp-status');
            const btnTotp = document.getElementById('btn-totp-enroll');
            const iconContainer = document.getElementById('totp-icon-container');

            if (user.acr >= 2) {
                shieldContainer.className = 'p-4 rounded-xl bg-purple-600/10 text-purple-400 border border-purple-500/20';
                shieldIcon.setAttribute('data-lucide', 'shield-check');
                statusTitle.innerText = 'ACR Level 2 (High Security)';
                statusDesc.innerText = 'Vault state is fully encrypted and protected under dynamic multi-factor checkpoints.';
                totpStatus.innerText = 'Activated';
                totpStatus.className = 'text-[9px] text-green-400 uppercase font-bold tracking-wider';
                btnTotp.classList.add('hidden');
                iconContainer.className = 'p-2 bg-green-500/10 text-green-400 rounded-lg border border-green-500/20';
            } else {
                shieldContainer.className = 'p-4 rounded-xl bg-amber-600/10 text-amber-500 border border-amber-500/20';
                shieldIcon.setAttribute('data-lucide', 'shield-alert');
                statusTitle.innerText = 'ACR Level 1 (Single Factor)';
                statusDesc.innerText = 'Your session is only secured by username and password. Complete TOTP/OTP verification to upgrade.';
                totpStatus.innerText = 'Not Configured';
                totpStatus.className = 'text-[9px] text-slate-500 uppercase font-bold tracking-wider';
                btnTotp.classList.remove('hidden');
                iconContainer.className = 'p-2 bg-[#2d2d2d] text-slate-400 rounded-lg';
            }

            // Create formatted JSON payload of claims
            const claims = {
                sub: user.subject_id,
                name: user.username,
                email: user.email,
                roles: user.roles,
                acr: user.acr,
                iss: window.location.origin,
                aud: "api",
                session_id: user.session_id,
                department: user.department
            };
            cachedToken = JSON.stringify(claims, null, 2);
            document.getElementById('card-token-claims').innerText = cachedToken;

            showPanel(currentPanel);
            loadSessions();
            loadMembers();
            lucide.createIcons();
        }

        function copyTokenClaims() {
            navigator.clipboard.writeText(cachedToken).then(() => {
                alert('Copied profile JSON claims payload to clipboard!');
            });
        }
        function showPanel(panelId) {
            currentPanel = panelId;
            document.querySelectorAll('.panel-view').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.pl-3 button').forEach(btn => {
                btn.className = 'w-full flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg text-slate-400 hover:bg-[#2d2d2d] hover:text-slate-100 transition text-left';
            });
            const activeBtn = document.getElementById('nav-btn-' + panelId);
            if (activeBtn) {
                activeBtn.className = 'w-full flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg text-purple-400 bg-purple-950/20 border border-purple-900/30 text-left';
            }
            document.getElementById('panel-' + panelId).classList.remove('hidden');
            lucide.createIcons();
        }
        function handleAuthSubmit(e) {
            e.preventDefault();
            const username = document.getElementById('auth-username').value;
            const password = document.getElementById('auth-password').value;
            const email = document.getElementById('auth-email').value;
            const errorBanner = document.getElementById('auth-error-banner');
            errorBanner.classList.add('hidden');
            const endpoint = currentAuthMode === 'signup' ? '/api/auth/register' : '/api/auth/login';
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            if (currentAuthMode === 'signup') {
                formData.append('email', email);
            }
            fetch(endpoint, {
                method: 'POST',
                body: formData
            })
            .then(res => {
                if (res.ok) {
                    if (currentAuthMode === 'signup') {
                        toggleAuthMode('signin');
                        alert('Identity registration successful! Decrypt vault to start.');
                    } else {
                        checkSession();
                    }
                } else {
                    res.json().then(data => {
                        errorBanner.innerText = data.detail || 'Authentication failed.';
                        errorBanner.classList.remove('hidden');
                    });
                }
            })
            .catch(err => {
                errorBanner.innerText = 'Network error: failed to submit.';
                errorBanner.classList.remove('hidden');
            });
        }

        function handleLogout() {
            fetch('/api/auth/logout', { method: 'POST' })
            .then(() => {
                showAppAuth();
            });
        }

        function loadSessions() {
            const listContainer = document.getElementById('sessions-list');
            fetch('/api/user/sessions')
            .then(res => res.json())
            .then(sessions => {
                listContainer.innerHTML = '';
                sessions.forEach(s => {
                    const row = document.createElement('div');
                    row.className = 'p-4 flex items-center justify-between hover:bg-purple-950/5 transition';
                    const iconName = s.os === 'macOS' || s.os === 'iOS' ? 'smartphone' : 'monitor';
                    const currentBadge = s.current ? '<span class="ml-2 px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 font-bold text-[9px] tracking-wider uppercase border border-purple-500/20">Current</span>' : '';
                    row.innerHTML = `
                        <div class="flex items-center gap-3.5">
                            <div class="p-2 bg-[#1a1a1a] border border-[#2e2e2e] rounded-lg text-slate-400">
                                <i data-lucide="${iconName}" class="w-4 h-4 text-purple-400/80"></i>
                            </div>
                            <div>
                                <p class="text-xs font-semibold text-white flex items-center">${s.browser} on ${s.os} ${currentBadge}</p>
                                <span class="text-[10px] text-slate-500">${s.ip} • Logged at: ${s.created_at.split('T')[0]}</span>
                            </div>
                        </div>
                        <button onclick="revokeSession('${s.session_id}')" class="py-1.5 px-3 rounded-lg border border-red-500/20 hover:bg-red-500/10 transition text-[10px] font-bold text-red-400">
                            Revoke
                        </button>
                    `;
                    listContainer.appendChild(row);
                });
                lucide.createIcons();
            });
        }

        function revokeSession(sessionId) {
            fetch('/api/user/sessions/' + sessionId, { method: 'DELETE' })
            .then(res => {
                if (res.ok) {
                    loadSessions();
                    checkSession();
                } else {
                    alert('Failed to revoke session.');
                }
            });
        }

        function loadMembers() {
            const container = document.getElementById('members-list');
            fetch('/api/org/members')
            .then(res => res.json())
            .then(members => {
                container.innerHTML = '';
                members.forEach(m => {
                    const row = document.createElement('div');
                    row.className = 'p-4 flex items-center justify-between';
                    const badgeClass = m.role === 'admin' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-slate-800 text-slate-400 border-slate-700';
                    row.innerHTML = `
                        <div class="flex items-center gap-3">
                            <div class="w-8 h-8 rounded bg-[#2e2e2e] flex items-center justify-center font-bold text-xs text-purple-400">
                                ${m.username.substring(0, 1).toUpperCase()}
                            </div>
                            <div>
                                <p class="text-xs font-semibold text-white">${m.username}</p>
                                <span class="text-[10px] text-slate-500">${m.email}</span>
                            </div>
                        </div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${badgeClass}">${m.role}</span>
                    `;
                    container.appendChild(row);
                });
                lucide.createIcons();
            });
        }

        function handleOrgInvite(e) {
            e.preventDefault();
            const subject = document.getElementById('invite-subject').value;
            const role = document.getElementById('invite-role').value;
            const formData = new FormData();
            formData.append('username', subject);
            formData.append('role', role);
            fetch('/api/org/members/invite', {
                method: 'POST',
                body: formData
            })
            .then(res => {
                if (res.ok) {
                    loadMembers();
                    alert('Successfully assigned ' + subject + ' role: ' + role);
                } else {
                    res.json().then(data => {
                        alert(data.detail || 'Invite assignment failed.');
                    });
                }
            });
        }
        function testRebac() {
            const subject = document.getElementById('rebac-subject').value;
            const relation = document.getElementById('rebac-relation').value;
            const objectId = document.getElementById('rebac-object').value;
            const banner = document.getElementById('rebac-result-banner');
            banner.classList.add('hidden');
            fetch(`/api/org/check?subject_id=${subject}&relation=${relation}&object_id=${objectId}`)
            .then(res => res.json())
            .then(data => {
                banner.classList.remove('hidden');
                if (data.allowed) {
                    banner.innerText = 'Allowed (Zanzibar Verified)';
                    banner.className = 'px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider bg-green-500/10 text-green-400 border border-green-500/20';
                } else {
                    banner.innerText = 'Denied (Restricted Rule)';
                    banner.className = 'px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider bg-red-500/10 text-red-400 border border-red-500/20';
                }
            });
        }
        function enrollTOTP() {
            fetch('/api/mfa/totp/enroll', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                document.getElementById('totp-secret-key').innerText = data.secret;
                document.getElementById('totp-enroll-factor-id').value = data.factor_id;
                document.getElementById('mfa-setup-modal').classList.remove('hidden');
                lucide.createIcons();
            });
        }
        function closeMfaModal() {
            document.getElementById('mfa-setup-modal').classList.add('hidden');
        }
        function handleTOTPVerify(e) {
            e.preventDefault();
            const factorId = document.getElementById('totp-enroll-factor-id').value;
            const code = document.getElementById('totp-code').value;
            const formData = new FormData();
            formData.append('factor_id', factorId);
            formData.append('code', code);
            fetch('/api/mfa/totp/verify', {
                method: 'POST',
                body: formData
            })
            .then(res => {
                if (res.ok) {
                    closeMfaModal();
                    checkSession(); // refresh profile context details
                    alert('MFA Authenticator successfully activated!');
                } else {
                    alert('Verification code invalid.');
                }
            });
        }
        function rotateKeys(use) {
            fetch('/api/settings/rotate/' + use, { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                alert('Token Key Manager successfully rotated ' + use + ' keys!');
            });
        }
    </script>
</body>
</html>
"""


# ============================================================
# API Routes Implementation
# ============================================================


@APP.get("/", response_class=HTMLResponse)
def index_spa() -> HTMLResponse:
    return HTMLResponse(HTML_SPA_TEMPLATE)


@APP.get("/api/user/session")
def get_session(session_id: str | None = Cookie(None)) -> Response:
    ctx = get_session_context(session_id)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return JSONResponse(ctx)


@APP.post("/api/auth/register")
def register_user(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
) -> Response:
    if username in DEMO_USERS:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Generate distinct subject ID
    from astraauth.core.ids import uuid7_str

    subject_id = f"user-{uuid7_str()[:8]}"

    DEMO_USERS[username] = {
        "id": subject_id,
        "password": password,
        "department": "Platform",
        "roles": {"user"},
        "email": email,
    }

    subject = Subject(
        subject_id=subject_id,
        tenants={TENANT_ID},
        username=username,
    )
    SERVICE.add_subject_password(
        subject=subject,
        tenant_id=TENANT_ID,
        username=username,
        password=password,
    )
    SERVICE.assign_roles(subject_id=subject_id, tenant_id=TENANT_ID, roles={"user"})

    return JSONResponse({"status": "success"})


@APP.post("/api/auth/login")
def login_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> Response:
    body = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "tenant_id": TENANT_ID,
        "username": username,
        "password": password,
        "scope": "openid",
    }
    req_ctx = _request(method="POST", path="/token", form_data=body)
    try:
        resp = SERVICE.adapter.handle_token(req_ctx)
        if resp.status != 200:
            raise HTTPException(status_code=400, detail="Invalid credentials")

        body_dict = resp.body if isinstance(resp.body, dict) else {}
        access_token = str(body_dict.get("access_token") or "")
        payload = SERVICE.token_manager.verify_jwt(access_token, audience="api")
        session_id = payload["sid"]

        # Cache session HTTP metadata (Client OS/Browser from User-Agent)
        SESSION_METADATA[session_id] = {
            "ip": request.client.host if request.client else "127.0.0.1",
            "ua": request.headers.get(
                "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
            ),
        }

        redirect = JSONResponse({"status": "success"})
        redirect.set_cookie("session_id", session_id, httponly=True)
        return redirect
    except Exception as e:
        logger.exception("Login failure")
        raise HTTPException(status_code=400, detail=f"Authentication failed: {str(e)}") from e


@APP.post("/api/auth/logout")
def logout_user(session_id: str | None = Cookie(None)) -> Response:
    redirect = Response(status_code=204)
    redirect.delete_cookie("session_id")
    if session_id:
        SERVICE.sessions.revoke(session_id)
    return redirect


@APP.get("/api/user/sessions")
def get_user_sessions(session_id: str | None = Cookie(None)) -> Response:
    ctx = get_session_context(session_id)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")

    active_sessions = SERVICE.sessions.list_active_for_subject(ctx["subject_id"])
    result = []
    for s in active_sessions:
        metadata = SESSION_METADATA.get(
            s.session_id, {"ip": "127.0.0.1", "ua": "Mozilla/5.0 (Windows) Chrome/120.0.0.0"}
        )
        parsed = parse_user_agent(metadata["ua"])
        result.append(
            {
                "session_id": s.session_id,
                "ip": metadata["ip"],
                "os": parsed["os"],
                "browser": parsed["browser"],
                "current": s.session_id == ctx["session_id"],
                "created_at": s.created_at.isoformat() if s.created_at else "",
            }
        )
    return JSONResponse(result)


@APP.delete("/api/user/sessions/{target_id}")
def revoke_user_session(target_id: str, session_id: str | None = Cookie(None)) -> Response:
    ctx = get_session_context(session_id)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Verify target session belongs to the current user
    target_session = SERVICE.sessions.get(target_id)
    if not target_session or target_session.subject_id != ctx["subject_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")

    SERVICE.sessions.revoke(target_id)
    return Response(status_code=204)


@APP.get("/api/org/members")
def get_org_members(session_id: str | None = Cookie(None)) -> Response:
    ctx = get_session_context(session_id)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")

    members = []
    for username, data in DEMO_USERS.items():
        # Get active roles assigned for this tenant
        role_assignment = SERVICE.assignments.get_assignments(data["id"], TENANT_ID)
        role = "none"
        if role_assignment and role_assignment.roles:
            # Pick highest role
            role = "admin" if "admin" in role_assignment.roles else "user"

        members.append({"username": username, "email": data["email"], "role": role})
    return JSONResponse(members)


@APP.post("/api/org/members/invite")
def invite_org_member(
    username: str = Form(...),
    role: str = Form(...),
    session_id: str | None = Cookie(None),
) -> Response:
    ctx = get_session_context(session_id)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Verify if current user holds org.invite permissions
    has_perm = SERVICE.adapter._authorization_engine.has_permission(
        subject_id=ctx["subject_id"],
        tenant_id=TENANT_ID,
        permission="org.invite",
    )
    if not has_perm:
        raise HTTPException(
            status_code=403, detail="Forbidden: Admin privileges required to update roles."
        )

    if username not in DEMO_USERS:
        raise HTTPException(status_code=404, detail="User not found")

    target_user = DEMO_USERS[username]
    target_roles = {"user", "admin"} if role == "admin" else {"user"}
    DEMO_USERS[username]["roles"] = target_roles

    # Assign in engine
    SERVICE.assign_roles(subject_id=target_user["id"], tenant_id=TENANT_ID, roles=target_roles)
    return JSONResponse({"status": "success"})


@APP.get("/api/org/check")
async def check_rebac(
    subject_id: str,
    relation: str,
    object_id: str,
    session_id: str | None = Cookie(None),
) -> Response:
    ctx = get_session_context(session_id)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")

    is_allowed = await CHECK_ENGINE.check(
        tenant_id=TENANT_ID,
        subject_type="user",
        subject_id=subject_id,
        relation_or_permission=relation,
        object_type="organization",
        object_id=object_id,
    )
    return JSONResponse({"allowed": is_allowed})


# ============================================================
# MFA Enrollment Handlers
# ============================================================


@APP.post("/api/mfa/totp/enroll")
def enroll_totp(session_id: str | None = Cookie(None)) -> Response:
    ctx = get_session_context(session_id)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")

    factor_id, provisioning_uri = SERVICE.enroll_subject_totp(
        subject_id=ctx["subject_id"],
        tenant_id=TENANT_ID,
        account_name=f"{ctx['username']}@astraauth.demo",
    )
    # Extract secret key from provisioning URI
    import urllib.parse as urlparse

    parsed = urlparse.urlparse(provisioning_uri)
    secret = urlparse.parse_qs(parsed.query).get("secret", [""])[0]

    return JSONResponse(
        {"factor_id": factor_id, "provisioning_uri": provisioning_uri, "secret": secret}
    )


@APP.post("/api/mfa/totp/verify")
def verify_totp(
    factor_id: str = Form(...),
    code: str = Form(...),
    session_id: str | None = Cookie(None),
) -> Response:
    ctx = get_session_context(session_id)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        SERVICE.activate_subject_totp(factor_id=factor_id, code=code)

        # Upgrade current session
        session = SERVICE.sessions.get(ctx["session_id"])
        if session:
            session.upgrade_authentication(target_acr=2, methods={"totp"})
            SERVICE.sessions.save(session)

        return Response(status_code=204)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"TOTP Verification failed: {str(e)}") from e


@APP.post("/api/settings/rotate/{use}")
def rotate_diagnostics_keys(use: str, session_id: str | None = Cookie(None)) -> Response:
    ctx = get_session_context(session_id)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if use not in ("sig", "enc"):
        raise HTTPException(status_code=400, detail="Invalid key use")

    SERVICE.token_manager.rotate_keys(use=use)
    return JSONResponse({"status": "success"})


# ============================================================
# Main Entry Point
# ============================================================


def main() -> None:
    print("=" * 80)
    print("Starting Astra Better-Auth Style Demo App")
    print(f"Access Portal at {APP_BASE_URL}")
    print("=" * 80)

    if getenv("ASTRAAUTH_EXAMPLE_SERVE") != "1":
        print("\nSet ASTRAAUTH_EXAMPLE_SERVE=1 to run the dashboard server:")
        print("  $env:ASTRAAUTH_EXAMPLE_SERVE=1; python examples/astra_demo.py")
        return

    try:
        import uvicorn
    except ImportError:
        print("Uvicorn is required: uv sync --all-groups")
        return

    uvicorn.run(APP, host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
