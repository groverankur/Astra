from __future__ import annotations

import json
import logging
from pathlib import Path
from secrets import token_urlsafe
from typing import Any, Literal, cast

from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from astraauth.core.config import DEFAULT_ASTRAAUTH_HOME
from astraauth.core.security import SharedThrottleStore, ThrottleStore
from astraauth.service import (
    OperatorAdminPrincipal,
    authenticate_operator_admin,
    export_public_jwks,
    initialize_config_home,
    list_admin_action_audit_records,
    list_oidc_audit_records,
    list_plugin_audit_records,
    load_bootstrap_manifest,
    operator_setup_status,
    persistence_report,
    record_admin_action,
    rotate_runtime_keys,
    runtime_health_report,
    runtime_inventory_report,
    runtime_observability_report,
    runtime_security_report,
    verify_bootstrap_setup_token,
    write_initial_admin_setup,
)
from astraauth_admin_ui.render import STATIC_DIR, create_templates
from astraauth_admin_ui.version import __version__

_SESSION_COOKIE = "astraauth_admin_ui"
_SESSION_KEY = "admin_ui"
_LOGIN_WINDOW_SECONDS = 300.0
_LOGIN_MAX_FAILURES = 5
_LOGIN_BLOCK_SECONDS = 600.0
_ACTION_WINDOW_SECONDS = 60.0
_ACTION_MAX_EVENTS = 10
_ACTION_BLOCK_SECONDS = 120.0


class ConfigInitRequest(BaseModel):
    project_name: str = "Astra"
    environment: Literal["dev", "test", "prod"] = "dev"
    persistence_backend: Literal["sqlite", "postgres", "mysql"] = "sqlite"
    issuer: str | None = None
    force: bool = True
    encrypt_values: bool = True
    bootstrap_token: str | None = None


class AdminInitRequest(BaseModel):
    tenant_id: str
    username: str
    password: str
    email: str | None = None
    subject_id: str | None = None
    role_name: str = "admin"
    client_id: str = "bootstrap-admin-client"
    bootstrap_token: str | None = None


class KeyRotateRequest(BaseModel):
    use: Literal["sig", "enc"]


class LoginRequest(BaseModel):
    tenant_id: str
    username: str
    password: str


class AdminUIState:
    def __init__(self, *, home: Path) -> None:
        self.home = home
        self.throttle_store: ThrottleStore = SharedThrottleStore(
            str(home / "data" / "admin-ui-throttle.db")
        )


def _parse_environment(value: str) -> Literal["dev", "test", "prod"]:
    if value == "dev":
        return "dev"
    if value == "test":
        return "test"
    if value == "prod":
        return "prod"
    raise HTTPException(status_code=400, detail="invalid_environment")


def _parse_persistence_backend(value: str) -> Literal["sqlite", "postgres", "mysql"]:
    if value == "sqlite":
        return "sqlite"
    if value == "postgres":
        return "postgres"
    if value == "mysql":
        return "mysql"
    raise HTTPException(status_code=400, detail="invalid_persistence_backend")


def create_admin_app(*, home: Path | None = None) -> FastAPI:  # noqa: C901
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    templates = create_templates()
    app = FastAPI(title="Astra Netra", version=__version__)
    app.state.admin_ui = AdminUIState(home=target_home)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        return _apply_security_headers(response, request=request)

    @app.get("/")
    def index(request: Request) -> Response:
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="index.html",
            context={"page_title": "Astra Netra"},
        )

    @app.get("/partials/sidebar")
    def partial_sidebar(request: Request) -> Response:
        return _render_sidebar(request=request, home=target_home, templates=templates)

    @app.get("/partials/main")
    def partial_main(request: Request) -> Response:
        return _render_main_content(request=request, home=target_home, templates=templates)

    @app.post("/partials/session/login")
    async def partial_login(request: Request) -> Response:
        form = await request.form()
        _require_csrf_value(str(form.get("csrf_token", "")), request=request, home=target_home)
        tenant_id = str(form.get("tenant_id", ""))
        username = str(form.get("username", ""))
        retry_after = _login_retry_after(
            request, home=target_home, tenant_id=tenant_id, username=username
        )
        if retry_after > 0:
            message = f"Too many login attempts. Wait {retry_after} seconds and try again."
            record_admin_action(
                home=target_home,
                event_type="admin_ui.session.login",
                status="throttled",
                details={
                    "tenant_id": tenant_id,
                    "username": username,
                    "retry_after_seconds": retry_after,
                },
            )
            response = _render_main_content(
                request=request,
                home=target_home,
                templates=templates,
                status_message=message,
                status_kind="error",
            )
            response.headers["Retry-After"] = str(retry_after)
            return _with_oob(
                response=response,
                request=request,
                home=target_home,
                templates=templates,
                status_message=message,
                status_kind="error",
            )
        try:
            principal = authenticate_operator_admin(
                tenant_id=tenant_id,
                username=username,
                password=str(form.get("password", "")),
                home=target_home,
            )
        except PermissionError as exc:
            _record_login_failure(request, home=target_home, tenant_id=tenant_id, username=username)
            record_admin_action(
                home=target_home,
                event_type="admin_ui.session.login",
                status="denied",
                details={"tenant_id": tenant_id, "username": username},
            )
            response = _render_main_content(
                request=request,
                home=target_home,
                templates=templates,
                status_message=str(exc),
                status_kind="error",
            )
            return _with_oob(
                response=response,
                request=request,
                home=target_home,
                templates=templates,
                status_message=str(exc),
                status_kind="error",
            )
        except Exception as exc:
            _record_login_failure(request, home=target_home, tenant_id=tenant_id, username=username)
            record_admin_action(
                home=target_home,
                event_type="admin_ui.session.login",
                status="failed",
                details={"tenant_id": tenant_id, "username": username},
            )
            response = _render_main_content(
                request=request,
                home=target_home,
                templates=templates,
                status_message=str(exc),
                status_kind="error",
            )
            return _with_oob(
                response=response,
                request=request,
                home=target_home,
                templates=templates,
                status_message=str(exc),
                status_kind="error",
            )

        _reset_login_failures(request, home=target_home, tenant_id=tenant_id, username=username)
        _store_principal(request, principal, home=target_home)
        record_admin_action(
            home=target_home,
            event_type="admin_ui.session.login",
            status="succeeded",
            actor=principal,
            details={},
        )
        response = _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/dashboard_shell.html",
            context=_dashboard_view_context(request=request, home=target_home),
        )
        return _with_oob(
            response=response,
            request=request,
            home=target_home,
            templates=templates,
            status_message="Authenticated admin session is active.",
            status_kind="success",
            refresh_sidebar=True,
        )

    @app.post("/partials/session/logout")
    async def partial_logout(request: Request) -> Response:
        form = await request.form()
        _require_csrf_value(str(form.get("csrf_token", "")), request=request, home=target_home)
        principal = _require_admin(request, home=target_home)
        record_admin_action(
            home=target_home,
            event_type="admin_ui.session.logout",
            status="succeeded",
            actor=principal,
            details={},
        )
        _clear_principal(request, home=target_home)
        _ensure_csrf_token(request, home=target_home, rotate=True)
        response = Response(status_code=204)
        response.headers["HX-Redirect"] = "/"
        return _attach_session_cookie(response, request=request, home=target_home)

    @app.get("/partials/dashboard/summary")
    def partial_dashboard_summary(request: Request) -> Response:
        _require_admin(request, home=target_home)
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/summary_cards.html",
            context=_dashboard_panel_context(home=target_home),
        )

    @app.get("/partials/dashboard/runtime")
    def partial_dashboard_runtime(request: Request) -> Response:
        _require_admin(request, home=target_home)
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/runtime_overview.html",
            context=_dashboard_panel_context(home=target_home),
        )

    @app.get("/partials/dashboard/infrastructure")
    def partial_dashboard_infrastructure(
        request: Request,
        throttle_scope: str | None = None,
        plugin_status: str | None = None,
    ) -> Response:
        _require_admin(request, home=target_home)
        context = _dashboard_panel_context(
            home=target_home,
            throttle_scope=throttle_scope or "",
            plugin_status=plugin_status or "",
        )
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/infrastructure.html",
            context=context,
        )

    @app.get("/partials/dashboard/oidc-audit")
    def partial_dashboard_oidc_audit(
        request: Request,
        tenant_id: str | None = None,
        provider_id: str | None = None,
    ) -> Response:
        principal = _require_admin(request, home=target_home)
        actual_tenant_id = tenant_id or principal.tenant_id
        records = list_oidc_audit_records(
            home=target_home, tenant_id=actual_tenant_id, provider_id=provider_id
        )
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/oidc_audit.html",
            context={
                "audit_tenant_id": actual_tenant_id,
                "audit_provider_id": provider_id or "",
                "oidc_records": list(records),
            },
        )

    @app.get("/partials/dashboard/admin-audit")
    def partial_dashboard_admin_audit(
        request: Request,
        tenant_id: str | None = None,
        actor_username: str | None = None,
    ) -> Response:
        principal = _require_admin(request, home=target_home)
        actual_tenant_id = tenant_id or principal.tenant_id
        records = list_admin_action_audit_records(
            home=target_home,
            tenant_id=actual_tenant_id if tenant_id is not None else None,
            actor_username=actor_username,
        )
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/admin_audit.html",
            context={
                "admin_audit_tenant": actual_tenant_id if tenant_id is not None else "",
                "admin_audit_actor": actor_username or "",
                "admin_records": list(records),
            },
        )

    def _load_tenant_tuples(home: Path, tenant_id: str) -> list[dict]:
        import json

        tuples_file = home / "relation_tuples.json"
        if not tuples_file.exists():
            return []
        try:
            data = json.loads(tuples_file.read_text(encoding="utf-8"))
            return [t for t in data if t.get("tenant_id") == tenant_id]
        except Exception:
            return []

    def _save_tuple(home: Path, rtuple: dict) -> None:
        import json

        tuples_file = home / "relation_tuples.json"
        data = []
        if tuples_file.exists():
            try:
                data = json.loads(tuples_file.read_text(encoding="utf-8"))
            except Exception:  # nosec B110
                pass
        data.append(rtuple)
        tuples_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _delete_tuple_file(home: Path, tenant_id: str, tuple_id: str) -> None:
        import json

        tuples_file = home / "relation_tuples.json"
        if not tuples_file.exists():
            return
        try:
            data = json.loads(tuples_file.read_text(encoding="utf-8"))
            data = [
                t for t in data if not (t.get("tenant_id") == tenant_id and t.get("id") == tuple_id)
            ]
            tuples_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:  # nosec B110
            pass

    @app.get("/partials/dashboard/rebac")
    def partial_dashboard_rebac(request: Request) -> Response:
        principal = _require_admin(request, home=target_home)

        # Load active schema
        schema_file = target_home / "rebac_schema.txt"
        if schema_file.exists():
            dsl = schema_file.read_text(encoding="utf-8")
        else:
            dsl = (
                "# Define your ReBAC schemas here\n"
                "definition user {}\n\n"
                "definition document {\n"
                "    relation viewer: user\n"
                "    relation editor: user\n"
                "    permission view = viewer + editor\n"
                "    permission edit = editor\n"
                "}"
            )
            schema_file.write_text(dsl, encoding="utf-8")

        tuples = _load_tenant_tuples(target_home, principal.tenant_id)
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/rebac.html",
            context={
                "dsl": dsl,
                "tuples": tuples,
            },
        )

    @app.post("/partials/dashboard/rebac/schema/compile")
    async def partial_rebac_compile(request: Request) -> Response:
        _require_admin(request, home=target_home)
        form = await request.form()
        dsl = str(form.get("dsl", "")).strip()

        import html as pyhtml

        from astraauth_policy import SchemaParser

        try:
            schema = SchemaParser.parse(dsl)
            # Save the valid schema
            schema_file = target_home / "rebac_schema.txt"
            schema_file.write_text(dsl, encoding="utf-8")

            # Format definitions list for user display
            html_list = [
                '<div style="padding: 10px; margin-top: 10px; border-radius: 4px; background: rgba(40, 167, 69, 0.15); border: 1px solid #28a745; color: #28a745;">'
                "<strong>✓ Schema Compiled & Saved Successfully!</strong>"
                "</div>"
                '<div style="margin-top: 12px;">'
                "<h4>Active Entity Nodes:</h4>"
            ]
            for obj_name, obj in schema.objects.items():
                escaped_name = pyhtml.escape(obj_name)
                html_list.append(
                    '<div style="padding: 8px; margin-bottom: 6px; border: 1px solid var(--border); border-radius: 4px; background: var(--bg-panel);">'
                )
                html_list.append(
                    f"<strong>entity: {escaped_name}</strong><br/>"  # nosemgrep: python.django.security.injection.raw-html-format.raw-html-format
                )
                if obj.relations:
                    escaped_rels = pyhtml.escape(", ".join(obj.relations.keys()))
                    html_list.append(
                        f'<span style="font-size: 0.9em; color: var(--accent);">Relations:</span> <code style="font-size: 0.9em;">{escaped_rels}</code><br/>'  # nosemgrep: python.django.security.injection.raw-html-format.raw-html-format
                    )
                if obj.permissions:
                    escaped_perms = pyhtml.escape(", ".join(obj.permissions.keys()))
                    html_list.append(
                        f'<span style="font-size: 0.9em; color: var(--text);">Permissions:</span> <code style="font-size: 0.9em;">{escaped_perms}</code>'  # nosemgrep: python.django.security.injection.raw-html-format.raw-html-format
                    )
                html_list.append("</div>")
            html_list.append("</div>")
            return Response("".join(html_list), media_type="text/html")
        except Exception as exc:
            escaped_exc = pyhtml.escape(str(exc))
            return Response(
                f'<div style="padding: 10px; margin-top: 10px; border-radius: 4px; background: rgba(220, 53, 69, 0.15); border: 1px solid #dc3545; color: #dc3545;">'
                f'<strong>✗ Compilation Failed:</strong><br/><pre style="font-size: 0.85em; margin: 4px 0 0 0; white-space: pre-wrap;">{escaped_exc}</pre>'  # nosemgrep: python.django.security.injection.raw-html-format.raw-html-format
                f"</div>",
                media_type="text/html",
            )

    @app.post("/partials/dashboard/rebac/tuples/add")
    async def partial_rebac_tuples_add(request: Request) -> Response:
        principal = _require_admin(request, home=target_home)
        form = await request.form()

        obj_type = str(form.get("obj_type", "")).strip()
        obj_id = str(form.get("obj_id", "")).strip()
        relation = str(form.get("rel", "")).strip()
        sub_type = str(form.get("sub_type", "")).strip()
        sub_id = str(form.get("sub_id", "")).strip()
        sub_rel = str(form.get("sub_rel", "")).strip() or None

        if not obj_type or not obj_id or not relation or not sub_type or not sub_id:
            tuples = _load_tenant_tuples(target_home, principal.tenant_id)
            return _template_response(
                request=request,
                home=target_home,
                templates=templates,
                template_name="partials/panels/rebac_tuples_list.html",
                context={"tuples": tuples},
            )

        import uuid

        new_tuple = {
            "id": str(uuid.uuid4()),
            "tenant_id": principal.tenant_id,
            "object_type": obj_type,
            "object_id": obj_id,
            "relation": relation,
            "subject_type": sub_type,
            "subject_id": sub_id,
            "subject_relation": sub_rel,
        }
        _save_tuple(target_home, new_tuple)

        tuples = _load_tenant_tuples(target_home, principal.tenant_id)
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/rebac_tuples_list.html",
            context={"tuples": tuples},
        )

    @app.post("/partials/dashboard/rebac/tuples/delete")
    async def partial_rebac_tuples_delete(request: Request, id: str) -> Response:
        principal = _require_admin(request, home=target_home)
        _delete_tuple_file(target_home, principal.tenant_id, id)

        tuples = _load_tenant_tuples(target_home, principal.tenant_id)
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/rebac_tuples_list.html",
            context={"tuples": tuples},
        )

    @app.post("/partials/dashboard/rebac/check")
    async def partial_rebac_check(request: Request) -> Response:
        principal = _require_admin(request, home=target_home)
        form = await request.form()

        sub_type = str(form.get("subject_type", "")).strip()
        sub_id = str(form.get("subject_id", "")).strip()
        rel_or_perm = str(form.get("relation_or_permission", "")).strip()
        obj_type = str(form.get("object_type", "")).strip()
        obj_id = str(form.get("object_id", "")).strip()

        if not sub_type or not sub_id or not rel_or_perm or not obj_type or not obj_id:
            return Response(
                '<div style="padding: 10px; border-radius: 4px; background: rgba(255, 193, 7, 0.15); border: 1px solid #ffc107; color: #ffc107;">'
                "Please fill all check input fields."
                "</div>",
                media_type="text/html",
            )

        from astraauth_policy import CheckEngine, RelationTuple, RelationTupleStore, SchemaParser

        schema_file = target_home / "rebac_schema.txt"
        if not schema_file.exists():
            return Response(
                '<div style="padding: 10px; border-radius: 4px; background: rgba(220, 53, 69, 0.15); border: 1px solid #dc3545; color: #dc3545;">'
                "No schema defined. Compile a schema first."
                "</div>",
                media_type="text/html",
            )

        try:
            schema = SchemaParser.parse(schema_file.read_text(encoding="utf-8"))
        except Exception as exc:
            return Response(
                f'<div style="padding: 10px; border-radius: 4px; background: rgba(220, 53, 69, 0.15); border: 1px solid #dc3545; color: #dc3545;">'
                f"Active schema has errors: {exc}"
                f"</div>",
                media_type="text/html",
            )

        raw_tuples = _load_tenant_tuples(target_home, principal.tenant_id)
        store = RelationTupleStore()
        for t in raw_tuples:
            await store.add_tuple(RelationTuple(**t))

        engine = CheckEngine(store, schema)
        is_allowed = await engine.check(
            tenant_id=principal.tenant_id,
            subject_type=sub_type,
            subject_id=sub_id,
            relation_or_permission=rel_or_perm,
            object_type=obj_type,
            object_id=obj_id,
        )

        if is_allowed:
            banner = (
                '<div style="padding: 12px; border-radius: 4px; background: rgba(40, 167, 69, 0.15); border: 1px solid #28a745; color: #28a745; text-align: center; font-size: 1.1em;">'
                "<strong>✓ ALLOWED</strong>"
                "</div>"
            )
        else:
            banner = (
                '<div style="padding: 12px; border-radius: 4px; background: rgba(220, 53, 69, 0.15); border: 1px solid #dc3545; color: #dc3545; text-align: center; font-size: 1.1em;">'
                "<strong>✗ DENIED</strong>"
                "</div>"
            )
        return Response(banner, media_type="text/html")

    def _load_tenants(home: Path) -> list[dict]:
        import json

        tenants_file = home / "tenants.json"
        if not tenants_file.exists():
            default_tenants = [
                {
                    "tenant_id": "tenant-1",
                    "name": "Default Tenant",
                    "database_url": "sqlite:///data/tenant-1.db",
                    "max_users": 5000,
                    "max_relation_tuples": 20000,
                }
            ]
            try:
                tenants_file.write_text(json.dumps(default_tenants, indent=2), encoding="utf-8")
            except Exception:  # nosec B110
                pass
            return default_tenants
        try:
            return json.loads(tenants_file.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save_tenant(home: Path, tenant: dict) -> None:
        import json

        tenants_file = home / "tenants.json"
        data = _load_tenants(home)
        data = [t for t in data if t.get("tenant_id") != tenant.get("tenant_id")]
        data.append(tenant)
        tenants_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _delete_tenant(home: Path, tenant_id: str) -> None:
        import json

        tenants_file = home / "tenants.json"
        data = _load_tenants(home)
        data = [t for t in data if t.get("tenant_id") != tenant_id]
        tenants_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @app.get("/partials/dashboard/tenants")
    def partial_dashboard_tenants(request: Request) -> Response:
        _require_admin(request, home=target_home)
        tenants = _load_tenants(target_home)
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/tenants.html",
            context={
                "tenants": tenants,
            },
        )

    @app.post("/partials/dashboard/tenants/add")
    async def partial_tenants_add(request: Request) -> Response:
        _require_admin(request, home=target_home)
        form = await request.form()

        tenant_id = str(form.get("tenant_id", "")).strip()
        name = str(form.get("name", "")).strip()
        database_url = str(form.get("database_url", "")).strip()
        try:
            max_users_val = form.get("max_users")
            max_users = int(str(max_users_val)) if max_users_val else 5000

            max_tuples_val = form.get("max_relation_tuples")
            max_tuples = int(str(max_tuples_val)) if max_tuples_val else 20000
        except ValueError:
            max_users = 5000
            max_tuples = 20000

        if tenant_id and name:
            new_tenant = {
                "tenant_id": tenant_id,
                "name": name,
                "database_url": database_url or f"sqlite:///data/{tenant_id}.db",
                "max_users": max_users,
                "max_relation_tuples": max_tuples,
            }
            _save_tenant(target_home, new_tenant)

        tenants = _load_tenants(target_home)
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/tenants_list.html",
            context={"tenants": tenants},
        )

    @app.post("/partials/dashboard/tenants/delete")
    async def partial_tenants_delete(request: Request, tenant_id: str) -> Response:
        _require_admin(request, home=target_home)
        _delete_tenant(target_home, tenant_id)

        tenants = _load_tenants(target_home)
        return _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/tenants_list.html",
            context={"tenants": tenants},
        )

    @app.post("/partials/actions/config-init")
    async def partial_config_init(request: Request) -> Response:
        form = await request.form()
        _require_csrf_value(str(form.get("csrf_token", "")), request=request, home=target_home)
        setup = operator_setup_status(home=target_home)
        actor = _require_admin(request, home=target_home) if not setup.setup_required else None
        action_limit = _enforce_action_throttle(
            request,
            home=target_home,
            action="config-init",
            actor=actor.username if actor is not None else "bootstrap",
        )
        if action_limit is not None:
            return _partial_throttled_response(
                request=request,
                home=target_home,
                templates=templates,
                response=action_limit,
            )
        payload = ConfigInitRequest(
            project_name=str(form.get("project_name", "Astra")),
            environment=_parse_environment(str(form.get("environment", "dev"))),
            persistence_backend=_parse_persistence_backend(
                str(form.get("persistence_backend", "sqlite"))
            ),
            issuer=str(form.get("issuer", "")) or None,
            force=True,
            encrypt_values=_to_bool(form.get("encrypt_values"), default=True),
            bootstrap_token=str(form.get("bootstrap_token", "")) or None,
        )
        if setup.setup_required:
            try:
                _require_setup_token(payload.bootstrap_token, home=target_home)
            except HTTPException as exc:
                response = _render_main_content(
                    request=request,
                    home=target_home,
                    templates=templates,
                    status_message=str(exc.detail),
                    status_kind="error",
                )
                return _with_oob(
                    response=response,
                    request=request,
                    home=target_home,
                    templates=templates,
                    status_message=str(exc.detail),
                    status_kind="error",
                )
        try:
            initialize_config_home(
                home=target_home,
                project_name=payload.project_name,
                environment=payload.environment,
                persistence_backend=payload.persistence_backend,
                persistence_base_dir=str(target_home / "data"),
                issuer=payload.issuer,
                encrypt_values=payload.encrypt_values,
                force=payload.force,
            )
        except Exception as exc:
            record_admin_action(
                home=target_home,
                event_type="admin_ui.config.initialize",
                status="failed",
                actor=actor,
                details={
                    "environment": payload.environment,
                    "backend": payload.persistence_backend,
                },
            )
            response = _render_main_content(
                request=request,
                home=target_home,
                templates=templates,
                status_message=str(exc),
                status_kind="error",
            )
            return _with_oob(
                response=response,
                request=request,
                home=target_home,
                templates=templates,
                status_message=str(exc),
                status_kind="error",
            )
        record_admin_action(
            home=target_home,
            event_type="admin_ui.config.initialize",
            status="succeeded",
            actor=actor,
            details={"environment": payload.environment, "backend": payload.persistence_backend},
        )
        message = (
            f"Config initialized for {payload.environment} using {payload.persistence_backend}."
        )
        if setup.setup_required:
            response = _render_main_content(
                request=request,
                home=target_home,
                templates=templates,
                status_message=message,
                status_kind="success",
            )
            return _with_oob(
                response=response,
                request=request,
                home=target_home,
                templates=templates,
                status_message=message,
                status_kind="success",
                refresh_sidebar=True,
            )
        response = _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/runtime_overview.html",
            context=_dashboard_panel_context(home=target_home),
        )
        return _with_oob(
            response=response,
            request=request,
            home=target_home,
            templates=templates,
            status_message=message,
            status_kind="success",
            refresh_summary=True,
        )

    @app.post("/partials/actions/init-admin")
    async def partial_init_admin(request: Request) -> Response:
        form = await request.form()
        _require_csrf_value(str(form.get("csrf_token", "")), request=request, home=target_home)
        setup = operator_setup_status(home=target_home)
        actor = _require_admin(request, home=target_home) if not setup.setup_required else None
        action_limit = _enforce_action_throttle(
            request,
            home=target_home,
            action="init-admin",
            actor=actor.username if actor is not None else "bootstrap",
        )
        if action_limit is not None:
            return _partial_throttled_response(
                request=request,
                home=target_home,
                templates=templates,
                response=action_limit,
            )
        payload = AdminInitRequest(
            tenant_id=str(form.get("tenant_id", "")),
            username=str(form.get("username", "")),
            password=str(form.get("password", "")),
            email=str(form.get("email", "")) or None,
            subject_id=str(form.get("subject_id", "")) or None,
            role_name=str(form.get("role_name", "admin")),
            client_id=str(form.get("client_id", "bootstrap-admin-client")),
            bootstrap_token=str(form.get("bootstrap_token", "")) or None,
        )
        if setup.setup_required:
            try:
                _require_setup_token(payload.bootstrap_token, home=target_home)
            except HTTPException as exc:
                response = _render_main_content(
                    request=request,
                    home=target_home,
                    templates=templates,
                    status_message=str(exc.detail),
                    status_kind="error",
                )
                return _with_oob(
                    response=response,
                    request=request,
                    home=target_home,
                    templates=templates,
                    status_message=str(exc.detail),
                    status_kind="error",
                )
        try:
            write_initial_admin_setup(
                home=target_home,
                tenant_id=payload.tenant_id,
                username=payload.username,
                password=payload.password,
                email=payload.email,
                subject_id=payload.subject_id,
                role_name=payload.role_name,
                client_id=payload.client_id,
            )
        except Exception as exc:
            record_admin_action(
                home=target_home,
                event_type="admin_ui.bootstrap.init_admin",
                status="failed",
                actor=actor,
                details={"tenant_id": payload.tenant_id, "username": payload.username},
            )
            response = _render_main_content(
                request=request,
                home=target_home,
                templates=templates,
                status_message=str(exc),
                status_kind="error",
            )
            return _with_oob(
                response=response,
                request=request,
                home=target_home,
                templates=templates,
                status_message=str(exc),
                status_kind="error",
            )
        record_admin_action(
            home=target_home,
            event_type="admin_ui.bootstrap.init_admin",
            status="succeeded",
            actor=actor,
            details={
                "tenant_id": payload.tenant_id,
                "username": payload.username,
                "role_name": payload.role_name,
            },
        )
        message = f"Bootstrap admin '{payload.username}' saved for tenant {payload.tenant_id}."
        if setup.setup_required:
            response = _render_main_content(
                request=request,
                home=target_home,
                templates=templates,
                status_message=message,
                status_kind="success",
            )
            return _with_oob(
                response=response,
                request=request,
                home=target_home,
                templates=templates,
                status_message=message,
                status_kind="success",
                refresh_sidebar=True,
            )
        response = _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/admin_audit.html",
            context=_admin_audit_context(
                home=target_home, tenant_id=payload.tenant_id, actor_username=""
            ),
        )
        return _with_oob(
            response=response,
            request=request,
            home=target_home,
            templates=templates,
            status_message=message,
            status_kind="success",
            refresh_summary=True,
        )

    @app.post("/partials/actions/key-rotate")
    async def partial_key_rotate(
        request: Request,
        use: Literal["sig", "enc"] = Form(...),
        csrf_token: str = Form(...),
    ) -> Response:
        _require_csrf_value(csrf_token, request=request, home=target_home)
        actor = _require_admin(request, home=target_home)
        action_limit = _enforce_action_throttle(
            request,
            home=target_home,
            action=f"key-rotate:{use}",
            actor=actor.username,
        )
        if action_limit is not None:
            return _partial_throttled_response(
                request=request,
                home=target_home,
                templates=templates,
                response=action_limit,
            )
        try:
            rotate_runtime_keys(use=use, home=target_home)
        except Exception as exc:
            record_admin_action(
                home=target_home,
                event_type="admin_ui.keys.rotate",
                status="failed",
                actor=actor,
                details={"use": use},
            )
            response = _template_response(
                request=request,
                home=target_home,
                templates=templates,
                template_name="partials/panels/infrastructure.html",
                context=_dashboard_panel_context(home=target_home),
            )
            return _with_oob(
                response=response,
                request=request,
                home=target_home,
                templates=templates,
                status_message=str(exc),
                status_kind="error",
                refresh_summary=True,
            )
        record_admin_action(
            home=target_home,
            event_type="admin_ui.keys.rotate",
            status="succeeded",
            actor=actor,
            details={"use": use},
        )
        response = _template_response(
            request=request,
            home=target_home,
            templates=templates,
            template_name="partials/panels/infrastructure.html",
            context=_dashboard_panel_context(home=target_home),
        )
        return _with_oob(
            response=response,
            request=request,
            home=target_home,
            templates=templates,
            status_message=f"Rotated {use} runtime keys.",
            status_kind="success",
            refresh_summary=True,
        )

    @app.get("/api/session")
    def session_status(request: Request) -> Response:
        setup = operator_setup_status(home=target_home)
        csrf_token = _ensure_csrf_token(request, home=target_home)
        principal = _current_principal(request, home=target_home)
        return _json_response(
            {
                "authenticated": principal is not None,
                "csrf_token": csrf_token,
                "setup": {
                    "config_exists": setup.config_exists,
                    "bootstrap_admin_count": setup.bootstrap_admin_count,
                    "active_setup_token_count": setup.active_setup_token_count,
                    "setup_required": setup.setup_required,
                },
                "principal": None if principal is None else _principal_payload(principal),
            },
            request=request,
            home=target_home,
        )

    @app.post("/api/session/login")
    def login(payload: LoginRequest, request: Request) -> Response:
        _require_csrf(request, home=target_home)
        retry_after = _login_retry_after(
            request,
            home=target_home,
            tenant_id=payload.tenant_id,
            username=payload.username,
        )
        if retry_after > 0:
            record_admin_action(
                home=target_home,
                event_type="admin_ui.session.login",
                status="throttled",
                details={
                    "tenant_id": payload.tenant_id,
                    "username": payload.username,
                    "retry_after_seconds": retry_after,
                },
            )
            response = _json_response(
                {
                    "ok": False,
                    "detail": "rate_limited",
                    "message": f"Too many login attempts. Wait {retry_after} seconds and try again.",
                    "retry_after": retry_after,
                },
                request=request,
                home=target_home,
                status_code=429,
            )
            response.headers["Retry-After"] = str(retry_after)
            return response
        try:
            principal = authenticate_operator_admin(
                tenant_id=payload.tenant_id,
                username=payload.username,
                password=payload.password,
                home=target_home,
            )
        except PermissionError as exc:
            _record_login_failure(
                request, home=target_home, tenant_id=payload.tenant_id, username=payload.username
            )
            record_admin_action(
                home=target_home,
                event_type="admin_ui.session.login",
                status="denied",
                details={"tenant_id": payload.tenant_id, "username": payload.username},
            )
            raise HTTPException(status_code=403, detail="access_denied") from exc
        except Exception as exc:
            _record_login_failure(
                request, home=target_home, tenant_id=payload.tenant_id, username=payload.username
            )
            record_admin_action(
                home=target_home,
                event_type="admin_ui.session.login",
                status="failed",
                details={"tenant_id": payload.tenant_id, "username": payload.username},
            )
            raise HTTPException(status_code=401, detail="authentication_failed") from exc

        _reset_login_failures(
            request, home=target_home, tenant_id=payload.tenant_id, username=payload.username
        )
        _store_principal(request, principal, home=target_home)
        record_admin_action(
            home=target_home,
            event_type="admin_ui.session.login",
            status="succeeded",
            actor=principal,
            details={},
        )
        return _json_response(
            {
                "ok": True,
                "principal": _principal_payload(principal),
                "csrf_token": _ensure_csrf_token(request, home=target_home),
            },
            request=request,
            home=target_home,
        )

    @app.post("/api/session/logout")
    def logout(request: Request) -> Response:
        principal = _require_admin(request, home=target_home)
        _require_csrf(request, home=target_home)
        record_admin_action(
            home=target_home,
            event_type="admin_ui.session.logout",
            status="succeeded",
            actor=principal,
            details={},
        )
        _clear_principal(request, home=target_home)
        _ensure_csrf_token(request, home=target_home, rotate=True)
        return _json_response({"ok": True}, request=request, home=target_home)

    @app.get("/api/dashboard")
    def dashboard(request: Request) -> Response:
        _require_admin(request, home=target_home)
        return _json_response(
            _dashboard_payload(home=target_home), request=request, home=target_home
        )

    @app.get("/api/observability")
    def observability(request: Request) -> Response:
        _require_admin(request, home=target_home)
        return _json_response(_safe_observability(target_home), request=request, home=target_home)

    @app.get("/api/security")
    def security(request: Request) -> Response:
        _require_admin(request, home=target_home)
        return _json_response(_safe_security(target_home), request=request, home=target_home)

    @app.get("/api/oidc-audit")
    def oidc_audit(request: Request, tenant_id: str, provider_id: str | None = None) -> Response:
        _require_admin(request, home=target_home)
        try:
            records = list_oidc_audit_records(
                home=target_home, tenant_id=tenant_id, provider_id=provider_id
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail="audit_query_failed") from exc
        return _json_response(
            {"tenant_id": tenant_id, "provider_id": provider_id, "records": list(records)},
            request=request,
            home=target_home,
        )

    @app.get("/api/admin-audit")
    def admin_audit(
        request: Request, tenant_id: str | None = None, actor_username: str | None = None
    ) -> Response:
        _require_admin(request, home=target_home)
        try:
            records = list_admin_action_audit_records(
                home=target_home,
                tenant_id=tenant_id,
                actor_username=actor_username,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail="audit_query_failed") from exc
        return _json_response(
            {"tenant_id": tenant_id, "actor_username": actor_username, "records": list(records)},
            request=request,
            home=target_home,
        )

    @app.get("/api/plugin-audit")
    def plugin_audit(
        request: Request,
        tenant_id: str | None = None,
        plugin_name: str | None = None,
        execution_type: str | None = None,
        status: str | None = None,
    ) -> Response:
        _require_admin(request, home=target_home)
        try:
            records = list_plugin_audit_records(
                home=target_home,
                tenant_id=tenant_id,
                plugin_name=plugin_name,
                execution_type=execution_type,
                status=status,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail="plugin_audit_query_failed") from exc
        return _json_response(
            {
                "tenant_id": tenant_id,
                "plugin_name": plugin_name,
                "execution_type": execution_type,
                "status": status,
                "records": list(records),
            },
            request=request,
            home=target_home,
        )

    @app.post("/api/actions/config-init")
    def config_init(payload: ConfigInitRequest, request: Request) -> Response:
        setup = operator_setup_status(home=target_home)
        actor = _require_admin(request, home=target_home) if not setup.setup_required else None
        _require_csrf(request, home=target_home)
        action_limit = _enforce_action_throttle(
            request,
            home=target_home,
            action="config-init",
            actor=actor.username if actor is not None else "bootstrap",
        )
        if action_limit is not None:
            return _json_throttled_response(
                request=request, home=target_home, response=action_limit
            )
        if setup.setup_required:
            _require_setup_token(payload.bootstrap_token, home=target_home)
        try:
            path = initialize_config_home(
                home=target_home,
                project_name=payload.project_name,
                environment=payload.environment,
                persistence_backend=payload.persistence_backend,
                persistence_base_dir=str(target_home / "data"),
                issuer=payload.issuer,
                encrypt_values=payload.encrypt_values,
                force=payload.force,
            )
        except Exception as exc:
            record_admin_action(
                home=target_home,
                event_type="admin_ui.config.initialize",
                status="failed",
                actor=actor,
                details={
                    "environment": payload.environment,
                    "backend": payload.persistence_backend,
                },
            )
            logging.error("Config init error: %s", exc, exc_info=False)
            raise HTTPException(status_code=400, detail="config_initialization_failed") from exc
        record_admin_action(
            home=target_home,
            event_type="admin_ui.config.initialize",
            status="succeeded",
            actor=actor,
            details={"environment": payload.environment, "backend": payload.persistence_backend},
        )
        return _json_response(
            {"ok": True, "path": str(path), "message": f"Config saved to {path}"},
            request=request,
            home=target_home,
        )

    @app.post("/api/actions/init-admin")
    def init_admin(payload: AdminInitRequest, request: Request) -> Response:
        setup = operator_setup_status(home=target_home)
        actor = _require_admin(request, home=target_home) if not setup.setup_required else None
        _require_csrf(request, home=target_home)
        action_limit = _enforce_action_throttle(
            request,
            home=target_home,
            action="init-admin",
            actor=actor.username if actor is not None else "bootstrap",
        )
        if action_limit is not None:
            return _json_throttled_response(
                request=request, home=target_home, response=action_limit
            )
        if setup.setup_required:
            _require_setup_token(payload.bootstrap_token, home=target_home)
        try:
            path = write_initial_admin_setup(
                home=target_home,
                tenant_id=payload.tenant_id,
                username=payload.username,
                password=payload.password,
                email=payload.email,
                subject_id=payload.subject_id,
                role_name=payload.role_name,
                client_id=payload.client_id,
            )
        except Exception as exc:
            record_admin_action(
                home=target_home,
                event_type="admin_ui.bootstrap.init_admin",
                status="failed",
                actor=actor,
                details={"tenant_id": payload.tenant_id, "username": payload.username},
            )
            logging.error("Admin init error: %s", exc, exc_info=False)
            raise HTTPException(status_code=400, detail="admin_initialization_failed") from exc
        record_admin_action(
            home=target_home,
            event_type="admin_ui.bootstrap.init_admin",
            status="succeeded",
            actor=actor,
            details={
                "tenant_id": payload.tenant_id,
                "username": payload.username,
                "role_name": payload.role_name,
            },
        )
        return _json_response(
            {"ok": True, "path": str(path), "message": f"Bootstrap admin saved to {path}"},
            request=request,
            home=target_home,
        )

    @app.post("/api/actions/key-rotate")
    def key_rotate(payload: KeyRotateRequest, request: Request) -> Response:
        actor = _require_admin(request, home=target_home)
        _require_csrf(request, home=target_home)
        action_limit = _enforce_action_throttle(
            request,
            home=target_home,
            action=f"key-rotate:{payload.use}",
            actor=actor.username,
        )
        if action_limit is not None:
            return _json_throttled_response(
                request=request, home=target_home, response=action_limit
            )
        try:
            path, keys = rotate_runtime_keys(use=payload.use, home=target_home)
        except Exception as exc:
            record_admin_action(
                home=target_home,
                event_type="admin_ui.keys.rotate",
                status="failed",
                actor=actor,
                details={"use": payload.use},
            )
            raise HTTPException(status_code=400, detail="key_rotation_failed") from exc
        record_admin_action(
            home=target_home,
            event_type="admin_ui.keys.rotate",
            status="succeeded",
            actor=actor,
            details={"use": payload.use},
        )
        return _json_response(
            {
                "ok": True,
                "path": str(path),
                "keys": keys,
                "message": f"Rotated {payload.use} keys",
            },
            request=request,
            home=target_home,
        )

    return app


def _dashboard_payload(*, home: Path) -> dict[str, Any]:
    admin_actions = list_admin_action_audit_records(home=home)
    return {
        "home": str(home),
        "config": _safe_config(home),
        "inventory": _safe_inventory(home),
        "health": _safe_health(home),
        "persistence": _safe_persistence(home),
        "observability": _safe_observability(home),
        "security": _safe_security(home),
        "bootstrap": _bootstrap_payload(home),
        "jwks": {"keys": _safe_jwks(home)},
        "recent_admin_actions": list(admin_actions[-10:][::-1]),
        "admin_audit_summary": {"count": len(admin_actions)},
    }


def _dashboard_panel_context(
    *,
    home: Path,
    throttle_scope: str = "",
    plugin_status: str = "",
) -> dict[str, Any]:
    payload = _dashboard_payload(home=home)
    payload["security"] = _filtered_security_payload(
        cast(dict[str, Any], payload["security"]),
        throttle_scope=throttle_scope,
        plugin_status=plugin_status,
    )
    return {
        "dashboard": payload,
        "config": payload["config"],
        "inventory": payload["inventory"],
        "health": payload["health"],
        "persistence": payload["persistence"],
        "observability": payload["observability"],
        "security": payload["security"],
        "bootstrap": payload["bootstrap"],
        "jwks": payload["jwks"],
        "recent_admin_actions": payload["recent_admin_actions"],
        "admin_audit_summary": payload["admin_audit_summary"],
        "current_security_throttle_scope": throttle_scope,
        "current_plugin_audit_status": plugin_status,
    }


def _dashboard_view_context(*, request: Request, home: Path) -> dict[str, Any]:
    principal = _require_admin(request, home=home)
    context = _dashboard_panel_context(home=home)
    context.update(
        {
            "principal": _principal_payload(principal),
            "csrf_token": _ensure_csrf_token(request, home=home),
            "default_tenant_id": principal.tenant_id,
            "default_actor_username": principal.username,
            "audit_tenant_id": principal.tenant_id,
            "audit_provider_id": "",
            "oidc_records": [],
            "admin_audit_tenant": principal.tenant_id,
            "admin_audit_actor": "",
            "admin_records": list_admin_action_audit_records(
                home=home, tenant_id=principal.tenant_id
            ),
        },
    )
    return context


def _admin_audit_context(*, home: Path, tenant_id: str, actor_username: str) -> dict[str, Any]:
    records = list_admin_action_audit_records(
        home=home,
        tenant_id=tenant_id or None,
        actor_username=actor_username or None,
    )
    return {
        "admin_audit_tenant": tenant_id,
        "admin_audit_actor": actor_username,
        "admin_records": list(records),
    }


def _safe_config(home: Path) -> dict[str, Any]:
    from astraauth.core.config import AuthConfig

    try:
        config = AuthConfig.load(home=home)
    except Exception as exc:
        return {"configured": False, "error": str(exc)}
    return {"configured": True, **config.model_dump(mode="json")}


def _safe_inventory(home: Path) -> dict[str, Any]:
    try:
        report = runtime_inventory_report(home=home)
    except Exception as exc:
        return {"configured": False, "error": str(exc)}
    return {
        "configured": True,
        "environment": report.environment,
        "issuer": report.issuer,
        "oidc_providers": list(report.oidc_providers),
        "registered_plugins": list(report.registered_plugins),
        "tenant_plugins": {tenant: list(names) for tenant, names in report.tenant_plugins.items()},
        "bootstrap_admin_count": report.bootstrap_admin_count,
    }


def _safe_health(home: Path) -> dict[str, Any]:
    try:
        report = runtime_health_report(home=home)
    except Exception as exc:
        return {"configured": False, "error": str(exc)}
    return {
        "configured": True,
        "ok": report.ok,
        "environment": report.environment,
        "issuer": report.issuer,
        "persistence_backends": report.persistence_backends,
        "oidc_provider_count": report.oidc_provider_count,
        "plugin_count": report.plugin_count,
        "details": list(report.details),
    }


def _safe_persistence(home: Path) -> dict[str, Any]:
    try:
        report = persistence_report(home=home)
    except Exception as exc:
        return {"configured": False, "error": str(exc)}
    return {
        "configured": True,
        "auto_create_schema": report.auto_create_schema,
        "stores": [
            {
                "store_name": store.store_name,
                "backend": store.backend,
                "mode": store.mode,
                "dsn": store.dsn,
            }
            for store in report.stores
        ],
    }


def _safe_observability(home: Path) -> dict[str, Any]:
    try:
        report = runtime_observability_report(home=home)
    except Exception as exc:
        return {"configured": False, "error": str(exc)}
    return {
        "configured": True,
        "service_name": report.service_name,
        "correlation_header_name": report.correlation_header_name,
        "structured_logging_enabled": report.structured_logging_enabled,
        "metrics_enabled": report.metrics_enabled,
        "log_path": str(report.log_path),
        "metrics_path": str(report.metrics_path),
        "counters": [{"name": counter.name, "value": counter.value} for counter in report.counters],
    }


def _safe_security(home: Path) -> dict[str, Any]:
    try:
        report = runtime_security_report(home=home)
    except Exception as exc:
        return {"configured": False, "error": str(exc)}
    admin_ui_store = SharedThrottleStore(str(home / "data" / "admin-ui-throttle.db"))
    admin_ui_throttle = admin_ui_store.snapshot()
    return {
        "configured": True,
        "runtime_throttle": _throttle_snapshot_payload(report.runtime_throttle),
        "admin_ui_throttle": _throttle_snapshot_payload(admin_ui_throttle),
        "plugin_audit_log_path": str(report.plugin_audit_log_path),
        "plugin_audit_record_count": report.plugin_audit_record_count,
        "recent_plugin_audit_records": [
            {
                "timestamp": record.timestamp.isoformat(),
                "tenant_id": record.tenant_id,
                "plugin_name": record.plugin_name,
                "target": record.target,
                "execution_type": record.execution_type,
                "status": record.status,
                "fail_closed": record.fail_closed,
                "duration_ms": record.duration_ms,
                "error_classification": record.error_classification,
                "message": record.message,
            }
            for record in report.recent_plugin_audit_records
        ],
    }


def _filtered_security_payload(
    payload: dict[str, Any],
    *,
    throttle_scope: str,
    plugin_status: str,
) -> dict[str, Any]:
    filtered = dict(payload)
    runtime_throttle = dict(cast(dict[str, Any], payload.get("runtime_throttle", {})))
    runtime_buckets = list(cast(list[dict[str, Any]], runtime_throttle.get("buckets", [])))
    if throttle_scope:
        runtime_buckets = [
            bucket for bucket in runtime_buckets if bucket.get("scope") == throttle_scope
        ]
    runtime_throttle["buckets"] = runtime_buckets
    runtime_throttle["available_scopes"] = sorted(
        {
            str(bucket.get("scope", ""))
            for bucket in cast(
                list[dict[str, Any]], payload.get("runtime_throttle", {}).get("buckets", [])
            )
            if bucket.get("scope")
        }
    )
    filtered["runtime_throttle"] = runtime_throttle

    plugin_records = list(
        cast(list[dict[str, Any]], payload.get("recent_plugin_audit_records", []))
    )
    if plugin_status:
        plugin_records = [
            record for record in plugin_records if record.get("status") == plugin_status
        ]
    filtered["recent_plugin_audit_records"] = plugin_records
    filtered["available_plugin_statuses"] = sorted(
        {
            str(record.get("status", ""))
            for record in cast(list[dict[str, Any]], payload.get("recent_plugin_audit_records", []))
            if record.get("status")
        }
    )
    return filtered


def _throttle_snapshot_payload(snapshot: Any) -> dict[str, Any]:
    return {
        "storage_kind": snapshot.storage_kind,
        "bucket_count": snapshot.bucket_count,
        "blocked_bucket_count": snapshot.blocked_bucket_count,
        "dsn": snapshot.dsn,
        "table_name": snapshot.table_name,
        "buckets": [
            {
                "scope": bucket.scope,
                "fingerprint": bucket.fingerprint,
                "event_count": bucket.event_count,
                "blocked": bucket.blocked,
                "retry_after_seconds": bucket.retry_after_seconds,
            }
            for bucket in snapshot.buckets
        ],
    }


def _bootstrap_payload(home: Path) -> dict[str, Any]:
    manifest = load_bootstrap_manifest(home=home)
    return {
        "admins": [
            {
                "tenant_id": admin.tenant_id,
                "username": admin.username,
                "role_name": admin.role_name,
                "client_id": admin.client_id,
                "email": admin.email,
            }
            for admin in manifest.admins
        ]
    }


def _safe_jwks(home: Path) -> list[dict[str, Any]]:
    try:
        return export_public_jwks(home=home)
    except Exception:
        return []


def _session_fernet(home: Path) -> Fernet:
    secrets_dir = home / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    key_path = secrets_dir / "settings.key"
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
    return Fernet(key_path.read_bytes())


def _session_state(request: Request, *, home: Path) -> dict[str, Any]:
    cached = getattr(request.state, "admin_ui_session", None)
    if isinstance(cached, dict):
        return cached
    token = request.cookies.get(_SESSION_COOKIE)
    payload: dict[str, Any] = {}
    if token:
        try:
            decrypted = _session_fernet(home).decrypt(token.encode("utf-8")).decode("utf-8")
            raw = json.loads(decrypted)
            if isinstance(raw, dict):
                payload = raw
        except (InvalidToken, json.JSONDecodeError, ValueError):
            payload = {}
    request.state.admin_ui_session = payload
    return payload


def _json_response(
    payload: dict[str, Any],
    *,
    request: Request,
    home: Path,
    status_code: int = 200,
) -> Response:
    response = JSONResponse(payload, status_code=status_code)
    return _attach_session_cookie(response, request=request, home=home)


def _template_response(
    *,
    request: Request,
    home: Path,
    templates: Any,
    template_name: str,
    context: dict[str, Any],
) -> Response:
    response = templates.TemplateResponse(
        request,
        template_name,
        {
            **context,
            "csrf_token": context.get("csrf_token") or _ensure_csrf_token(request, home=home),
        },
    )
    return _attach_session_cookie(response, request=request, home=home)


def _render_sidebar(
    *,
    request: Request,
    home: Path,
    templates: Any,
) -> Response:
    setup = operator_setup_status(home=home)
    principal = _current_principal(request, home=home)
    if principal is None:
        return Response("", media_type="text/html")
    return _template_response(
        request=request,
        home=home,
        templates=templates,
        template_name="partials/sidebar.html",
        context={
            "home": str(home),
            "setup": {
                "config_exists": setup.config_exists,
                "bootstrap_admin_count": setup.bootstrap_admin_count,
                "active_setup_token_count": setup.active_setup_token_count,
                "setup_required": setup.setup_required,
            },
            "principal": None if principal is None else _principal_payload(principal),
        },
    )


def _render_main_content(
    *,
    request: Request,
    home: Path,
    templates: Any,
    status_message: str | None = None,
    status_kind: str = "info",
) -> Response:
    setup = operator_setup_status(home=home)
    principal = _current_principal(request, home=home)
    base_context = {
        "home": str(home),
        "csrf_token": _ensure_csrf_token(request, home=home),
        "status_message": status_message,
        "status_kind": status_kind,
    }
    if setup.setup_required:
        return _template_response(
            request=request,
            home=home,
            templates=templates,
            template_name="partials/setup.html",
            context=base_context,
        )
    if principal is None:
        return _template_response(
            request=request,
            home=home,
            templates=templates,
            template_name="partials/login.html",
            context=base_context,
        )
    return _template_response(
        request=request,
        home=home,
        templates=templates,
        template_name="partials/dashboard_shell.html",
        context=_dashboard_view_context(request=request, home=home),
    )


def _with_oob(
    *,
    response: Response,
    request: Request,
    home: Path,
    templates: Any,
    status_message: str,
    status_kind: str,
    refresh_sidebar: bool = False,
    refresh_summary: bool = False,
    refresh_workspace_panel: bool = False,
    workspace_panel_html: str = "",
) -> Response:
    setup = operator_setup_status(home=home)
    principal = _current_principal(request, home=home)
    panel_context = _dashboard_panel_context(home=home)
    oob_html = (
        templates.get_template("partials/oob_updates.html")
        .render(
            request=request,
            refresh_sidebar=refresh_sidebar,
            refresh_summary=refresh_summary,
            refresh_workspace_panel=refresh_workspace_panel,
            workspace_panel_html=workspace_panel_html,
            sidebar_html=""
            if principal is None
            else templates.get_template("partials/sidebar.html").render(
                request=request,
                home=str(home),
                setup={
                    "config_exists": setup.config_exists,
                    "bootstrap_admin_count": setup.bootstrap_admin_count,
                    "active_setup_token_count": setup.active_setup_token_count,
                    "setup_required": setup.setup_required,
                },
                principal=_principal_payload(principal),
                csrf_token=_ensure_csrf_token(request, home=home),
            ),
            status_html=templates.get_template("partials/status_banner.html").render(
                request=request,
                status_message=status_message,
                status_kind=status_kind,
            ),
            summary_html=templates.get_template("partials/panels/summary_cards.html").render(
                request=request,
                **panel_context,
            ),
        )
        .encode("utf-8")
    )
    response.body = response.body + oob_html
    response.headers["content-length"] = str(len(response.body))
    return _attach_session_cookie(response, request=request, home=home)


def _attach_session_cookie(response: Response, *, request: Request, home: Path) -> Response:
    session = _session_state(request, home=home)
    if not session:
        response.delete_cookie(_SESSION_COOKIE)
        return response
    token = _session_fernet(home).encrypt(json.dumps(session).encode("utf-8")).decode("utf-8")
    response.set_cookie(
        _SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return response


def _apply_security_headers(response: Response, *, request: Request) -> Response:
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        ),
    )
    if not request.url.path.startswith("/static"):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")
        response.headers.setdefault("Expires", "0")
    return response


def _ensure_csrf_token(request: Request, *, home: Path, rotate: bool = False) -> str:
    session = _session_state(request, home=home)
    admin_state = session.setdefault(_SESSION_KEY, {})
    token = admin_state.get("csrf_token")
    if rotate or not isinstance(token, str):
        token = token_urlsafe(24)
        admin_state["csrf_token"] = token
    session[_SESSION_KEY] = admin_state
    request.state.admin_ui_session = session
    return token


def _store_principal(request: Request, principal: OperatorAdminPrincipal, *, home: Path) -> None:
    session = _session_state(request, home=home)
    session[_SESSION_KEY] = {
        "csrf_token": _ensure_csrf_token(request, home=home, rotate=True),
        "principal": {
            "subject_id": principal.subject_id,
            "tenant_id": principal.tenant_id,
            "username": principal.username,
            "roles": list(principal.roles),
        },
    }
    request.state.admin_ui_session = session


def _clear_principal(request: Request, *, home: Path) -> None:
    session = _session_state(request, home=home)
    admin_state = session.setdefault(_SESSION_KEY, {})
    admin_state.pop("principal", None)
    session[_SESSION_KEY] = admin_state
    request.state.admin_ui_session = session


def _current_principal(request: Request, *, home: Path) -> OperatorAdminPrincipal | None:
    session = _session_state(request, home=home)
    admin_state = session.get(_SESSION_KEY)
    if not isinstance(admin_state, dict):
        return None
    principal = admin_state.get("principal")
    if not isinstance(principal, dict):
        return None
    try:
        subject_id = str(principal["subject_id"])
        tenant_id = str(principal["tenant_id"])
        username = str(principal["username"])
        raw_roles = principal.get("roles", [])
        if not isinstance(raw_roles, list):
            return None
        roles = tuple(str(role) for role in raw_roles)
    except KeyError:
        return None
    return OperatorAdminPrincipal(
        subject_id=subject_id,
        tenant_id=tenant_id,
        username=username,
        roles=roles,
    )


def _principal_payload(principal: OperatorAdminPrincipal) -> dict[str, Any]:
    return {
        "subject_id": principal.subject_id,
        "tenant_id": principal.tenant_id,
        "username": principal.username,
        "roles": list(principal.roles),
    }


def _require_admin(request: Request, *, home: Path) -> OperatorAdminPrincipal:
    principal = _current_principal(request, home=home)
    if principal is None:
        raise HTTPException(status_code=401, detail="admin_auth_required")
    return principal


def _require_csrf(request: Request, *, home: Path) -> None:
    expected = _ensure_csrf_token(request, home=home)
    provided = request.headers.get("x-csrf-token")
    if provided != expected:
        raise HTTPException(status_code=403, detail="csrf_token_invalid")


def _require_csrf_value(value: str, *, request: Request, home: Path) -> None:
    expected = _ensure_csrf_token(request, home=home)
    if value != expected:
        raise HTTPException(status_code=403, detail="csrf_token_invalid")


def _require_setup_token(token: str | None, *, home: Path) -> None:
    if not token:
        raise HTTPException(status_code=403, detail="bootstrap_setup_token_required")
    try:
        verify_bootstrap_setup_token(token=token, home=home)
    except Exception as exc:
        raise HTTPException(status_code=403, detail="bootstrap_setup_token_invalid") from exc


def _client_identity(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",", 1)[0].strip()
        if first:
            return first
    client = request.client
    if client is not None and client.host:
        return client.host
    return "unknown"


def _app_state(request: Request, *, home: Path) -> AdminUIState:
    state = getattr(request.app.state, "admin_ui", None)
    if isinstance(state, AdminUIState):
        return state
    restored = AdminUIState(home=home)
    request.app.state.admin_ui = restored
    return restored


def _login_throttle_key(request: Request, *, tenant_id: str, username: str) -> str:
    return f"{_client_identity(request)}|{tenant_id.strip().lower()}|{username.strip().lower()}"


def _login_retry_after(request: Request, *, home: Path, tenant_id: str, username: str) -> int:
    state = _app_state(request, home=home)
    return state.throttle_store.retry_after(
        bucket=f"login|{_login_throttle_key(request, tenant_id=tenant_id, username=username)}",
        window_seconds=_LOGIN_WINDOW_SECONDS,
    )


def _record_login_failure(request: Request, *, home: Path, tenant_id: str, username: str) -> int:
    state = _app_state(request, home=home)
    return state.throttle_store.record(
        bucket=f"login|{_login_throttle_key(request, tenant_id=tenant_id, username=username)}",
        max_events=_LOGIN_MAX_FAILURES,
        window_seconds=_LOGIN_WINDOW_SECONDS,
        block_seconds=_LOGIN_BLOCK_SECONDS,
    )


def _reset_login_failures(request: Request, *, home: Path, tenant_id: str, username: str) -> None:
    state = _app_state(request, home=home)
    state.throttle_store.reset(
        bucket=f"login|{_login_throttle_key(request, tenant_id=tenant_id, username=username)}"
    )


def _action_throttle_key(request: Request, *, action: str, actor: str) -> str:
    return f"{_client_identity(request)}|{actor.strip().lower()}|{action}"


def _enforce_action_throttle(
    request: Request,
    *,
    home: Path,
    action: str,
    actor: str,
) -> dict[str, Any] | None:
    state = _app_state(request, home=home)
    retry_after = state.throttle_store.record(
        bucket=f"action|{_action_throttle_key(request, action=action, actor=actor)}",
        max_events=_ACTION_MAX_EVENTS,
        window_seconds=_ACTION_WINDOW_SECONDS,
        block_seconds=_ACTION_BLOCK_SECONDS,
    )
    if retry_after <= 0:
        return None
    record_admin_action(
        home=home,
        event_type=f"admin_ui.{action}",
        status="throttled",
        details={"actor": actor, "retry_after_seconds": retry_after},
    )
    return {
        "detail": "rate_limited",
        "message": f"Too many {action} requests. Wait {retry_after} seconds and try again.",
        "retry_after": retry_after,
    }


def _json_throttled_response(request: Request, *, home: Path, response: dict[str, Any]) -> Response:
    payload = {"ok": False, **response}
    throttled = _json_response(payload, request=request, home=home, status_code=429)
    throttled.headers["Retry-After"] = str(response["retry_after"])
    return throttled


def _partial_throttled_response(
    *,
    request: Request,
    home: Path,
    templates: Any,
    response: dict[str, Any],
) -> Response:
    throttled = _render_main_content(
        request=request,
        home=home,
        templates=templates,
        status_message=str(response["message"]),
        status_kind="error",
    )
    throttled.headers["Retry-After"] = str(response["retry_after"])
    return _with_oob(
        response=throttled,
        request=request,
        home=home,
        templates=templates,
        status_message=str(response["message"]),
        status_kind="error",
    )


def _to_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
