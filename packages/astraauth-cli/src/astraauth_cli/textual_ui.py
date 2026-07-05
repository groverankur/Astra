from __future__ import annotations

from pathlib import Path
from typing import Any

from astraauth.core.config import DEFAULT_ASTRAAUTH_HOME
from astraauth.service import (
    export_public_jwks,
    initialize_config_home,
    list_oidc_audit_records,
    load_bootstrap_manifest,
    persistence_report,
    rotate_runtime_keys,
    runtime_health_report,
    runtime_inventory_report,
    runtime_security_report,
    write_initial_admin_setup,
)


def _load_textual() -> dict[str, Any] | None:
    try:
        from textual.app import App
        from textual.containers import Horizontal, VerticalScroll
        from textual.widgets import (
            Button,
            Footer,
            Header,
            Input,
            Pretty,
            Static,
            TabbedContent,
            TabPane,
        )
    except ImportError:
        return None
    return {
        "App": App,
        "Horizontal": Horizontal,
        "VerticalScroll": VerticalScroll,
        "Button": Button,
        "Footer": Footer,
        "Header": Header,
        "Input": Input,
        "Pretty": Pretty,
        "Static": Static,
        "TabbedContent": TabbedContent,
        "TabPane": TabPane,
    }


def run_textual_wizard_ui(*, home: Path | None = None) -> bool:
    return _run_textual_ui(mode="wizard", home=home)


def run_textual_admin_ui(*, home: Path | None = None) -> bool:
    return _run_textual_ui(mode="admin", home=home)


def _run_textual_ui(*, mode: str, home: Path | None = None) -> bool:  # noqa: C901
    textual = _load_textual()
    if textual is None:
        return False

    app_cls = textual["App"]
    horizontal_cls = textual["Horizontal"]
    vertical_scroll_cls = textual["VerticalScroll"]
    button_cls = textual["Button"]
    footer_cls = textual["Footer"]
    header_cls = textual["Header"]
    input_cls = textual["Input"]
    pretty_cls = textual["Pretty"]
    static_cls = textual["Static"]
    tabbed_content_cls = textual["TabbedContent"]
    tab_pane_cls = textual["TabPane"]

    target_home = home or DEFAULT_ASTRAAUTH_HOME

    class AstraConsoleApp(app_cls[None]):
        CSS = """
        Screen {
            layout: vertical;
        }
        #status {
            height: 3;
            padding: 1 2;
            background: $surface;
            color: $text;
        }
        .pane {
            padding: 1 2;
        }
        .section {
            margin-bottom: 1;
            border: round $accent;
            padding: 1;
        }
        Input {
            margin-bottom: 1;
        }
        Button {
            margin-right: 1;
            margin-bottom: 1;
        }
        Pretty {
            height: 12;
            border: round $panel;
        }
        #bootstrap-pretty, #jwks-pretty, #audit-pretty, #security-pretty {
            height: 16;
        }
        """
        BINDINGS = [("q", "quit", "Quit"), ("r", "refresh", "Refresh")]

        def __init__(self, *, mode_name: str, home_path: Path) -> None:
            super().__init__()
            self._mode_name = mode_name
            self._home_path = home_path

        def compose(self) -> Any:
            yield header_cls(show_clock=True)
            yield static_cls("Loading Astra console...", id="status")
            with tabbed_content_cls(
                initial="wizard" if self._mode_name == "wizard" else "dashboard"
            ):
                with tab_pane_cls("Dashboard", id="dashboard"):
                    with vertical_scroll_cls(classes="pane"):
                        with horizontal_cls(classes="section"):
                            yield button_cls("Refresh", id="refresh-dashboard", variant="primary")
                            yield button_cls("Quit", id="quit-dashboard", variant="error")
                        yield static_cls("Runtime inventory", classes="section")
                        yield pretty_cls({}, id="inventory-pretty")
                        yield static_cls("Health", classes="section")
                        yield pretty_cls({}, id="health-pretty")
                        yield static_cls("Persistence", classes="section")
                        yield pretty_cls({}, id="persistence-pretty")
                        yield static_cls("Security", classes="section")
                        yield pretty_cls({}, id="security-pretty")
                with tab_pane_cls("Wizard", id="wizard"):
                    with vertical_scroll_cls(classes="pane"):
                        yield static_cls("Initialize runtime config", classes="section")
                        yield input_cls(value="Astra", placeholder="Project name", id="cfg-project")
                        yield input_cls(
                            value="dev", placeholder="Environment", id="cfg-environment"
                        )
                        yield input_cls(
                            value="sqlite", placeholder="Persistence backend", id="cfg-backend"
                        )
                        yield input_cls(
                            value="https://auth.local", placeholder="Issuer", id="cfg-issuer"
                        )
                        yield button_cls(
                            "Initialize or reset config", id="cfg-init", variant="primary"
                        )
                        yield static_cls("Create bootstrap admin", classes="section")
                        yield input_cls(
                            value="tenant-1", placeholder="Tenant ID", id="admin-tenant"
                        )
                        yield input_cls(
                            value="admin", placeholder="Admin username", id="admin-username"
                        )
                        yield input_cls(
                            value="change-me",
                            placeholder="Admin password",
                            password=True,
                            id="admin-password",
                        )
                        yield input_cls(
                            value="admin@example.com", placeholder="Admin email", id="admin-email"
                        )
                        yield button_cls("Save bootstrap admin", id="admin-save", variant="success")
                        yield static_cls("Rotate runtime keys", classes="section")
                        with horizontal_cls():
                            yield button_cls("Rotate signing keys", id="rotate-sig")
                            yield button_cls("Rotate encryption keys", id="rotate-enc")
                with tab_pane_cls("Bootstrap", id="bootstrap"):
                    with vertical_scroll_cls(classes="pane"):
                        yield button_cls("Reload bootstrap", id="bootstrap-refresh")
                        yield pretty_cls({}, id="bootstrap-pretty")
                with tab_pane_cls("Keys", id="keys"):
                    with vertical_scroll_cls(classes="pane"):
                        yield button_cls("Reload JWKS", id="jwks-refresh")
                        yield pretty_cls({}, id="jwks-pretty")
                with tab_pane_cls("OIDC Audit", id="audit"):
                    with vertical_scroll_cls(classes="pane"):
                        yield input_cls(
                            value="tenant-1", placeholder="Tenant ID", id="audit-tenant"
                        )
                        yield input_cls(
                            value="", placeholder="Provider ID (optional)", id="audit-provider"
                        )
                        yield button_cls("Load audit records", id="audit-load")
                        yield pretty_cls({}, id="audit-pretty")
            yield footer_cls()

        def on_mount(self) -> None:
            self._refresh_all()
            self._set_status(f"Astra {self._mode_name} console ready for {self._home_path}")

        def action_refresh(self) -> None:
            self._refresh_all()
            self._set_status("Refreshed runtime data")

        def on_button_pressed(self, event: Any) -> None:
            button_id = getattr(event.button, "id", "")
            try:
                if button_id in {"refresh-dashboard", "bootstrap-refresh", "jwks-refresh"}:
                    self._refresh_all()
                    self._set_status("Runtime data refreshed")
                    return
                if button_id == "quit-dashboard":
                    self.exit()
                    return
                if button_id == "cfg-init":
                    self._initialize_config()
                    return
                if button_id == "admin-save":
                    self._save_bootstrap_admin()
                    return
                if button_id == "rotate-sig":
                    self._rotate_keys("sig")
                    return
                if button_id == "rotate-enc":
                    self._rotate_keys("enc")
                    return
                if button_id == "audit-load":
                    self._load_audit()
                    return
            except Exception as exc:
                self._set_status(f"Error: {exc}", error=True)

        def _initialize_config(self) -> None:
            project_name = self._input_value("cfg-project") or "Astra"
            environment = self._input_value("cfg-environment") or "dev"
            backend = self._input_value("cfg-backend") or "sqlite"
            issuer = self._input_value("cfg-issuer") or "https://auth.local"
            path = initialize_config_home(
                home=self._home_path,
                project_name=project_name,
                environment=environment,
                persistence_backend=backend,
                persistence_base_dir=str(self._home_path / "data"),
                issuer=issuer,
                encrypt_values=True,
                force=True,
            )
            self._refresh_all()
            self._set_status(f"Config saved to {path}")

        def _save_bootstrap_admin(self) -> None:
            path = write_initial_admin_setup(
                home=self._home_path,
                tenant_id=self._input_value("admin-tenant") or "tenant-1",
                username=self._input_value("admin-username") or "admin",
                password=self._input_value("admin-password") or "change-me",
                email=self._input_value("admin-email") or None,
            )
            self._refresh_bootstrap()
            self._set_status(f"Bootstrap admin saved to {path}")

        def _rotate_keys(self, use: str) -> None:
            path, keys = rotate_runtime_keys(use=use, home=self._home_path)
            self._pretty("jwks-pretty").update({"path": str(path), "keys": keys})
            self._set_status(f"Rotated {use} keys")

        def _load_audit(self) -> None:
            tenant_id = self._input_value("audit-tenant") or "tenant-1"
            provider_id = self._input_value("audit-provider") or None
            records = list_oidc_audit_records(
                home=self._home_path,
                tenant_id=tenant_id,
                provider_id=provider_id,
            )
            self._pretty("audit-pretty").update({"tenant_id": tenant_id, "records": records})
            self._set_status(f"Loaded {len(records)} audit records")

        def _refresh_all(self) -> None:
            self._refresh_dashboard()
            self._refresh_bootstrap()
            self._refresh_jwks()

        def _refresh_dashboard(self) -> None:
            self._pretty("inventory-pretty").update(_safe_inventory(self._home_path))
            self._pretty("health-pretty").update(_safe_health(self._home_path))
            self._pretty("persistence-pretty").update(_safe_persistence(self._home_path))
            self._pretty("security-pretty").update(_safe_security(self._home_path))

        def _refresh_bootstrap(self) -> None:
            manifest = load_bootstrap_manifest(home=self._home_path)
            self._pretty("bootstrap-pretty").update(
                {
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
            )

        def _refresh_jwks(self) -> None:
            try:
                self._pretty("jwks-pretty").update(
                    {"keys": export_public_jwks(home=self._home_path)}
                )
            except Exception as exc:
                self._pretty("jwks-pretty").update({"error": str(exc)})

        def _input_value(self, widget_id: str) -> str:
            widget = self.query_one(f"#{widget_id}")
            return str(getattr(widget, "value", "")).strip()

        def _pretty(self, widget_id: str) -> Any:
            return self.query_one(f"#{widget_id}")

        def _set_status(self, message: str, *, error: bool = False) -> None:
            prefix = "[error]" if error else "[ok]"
            (self.query_one("#status")).update(f"{prefix} {message}")

    AstraConsoleApp(mode_name=mode, home_path=target_home).run()
    return True


def _safe_inventory(home: Path) -> dict[str, object]:
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


def _safe_health(home: Path) -> dict[str, object]:
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
        "plugin_count": report.plugin_count,
        "oidc_provider_count": report.oidc_provider_count,
        "details": list(report.details),
    }


def _safe_persistence(home: Path) -> dict[str, object]:
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


def _safe_security(home: Path) -> dict[str, object]:
    try:
        report = runtime_security_report(home=home)
    except Exception as exc:
        return {"configured": False, "error": str(exc)}
    return {
        "configured": True,
        "runtime_throttle": {
            "storage_kind": report.runtime_throttle.storage_kind,
            "bucket_count": report.runtime_throttle.bucket_count,
            "blocked_bucket_count": report.runtime_throttle.blocked_bucket_count,
        },
        "plugin_audit_log_path": str(report.plugin_audit_log_path),
        "plugin_audit_record_count": report.plugin_audit_record_count,
        "recent_plugin_audit_records": [
            {
                "timestamp": record.timestamp.isoformat(),
                "plugin_name": record.plugin_name,
                "execution_type": record.execution_type,
                "status": record.status,
                "duration_ms": record.duration_ms,
            }
            for record in report.recent_plugin_audit_records[:8]
        ],
    }
