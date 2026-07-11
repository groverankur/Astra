"""Astra UI components designed using the htmy rendering core.

These are Basecoat-compatible pure Python UI elements, matching the structural style of
the Jinja macros.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from htmy import Component, ComponentType, Context, html

# =====================================================================
# Core UI Reusable Components
# =====================================================================


class Field:
    def __init__(
        self,
        name: str,
        label: str,
        value: str = "",
        placeholder: str = "",
        input_type: str = "text",
    ):
        self.name = name
        self.label = label
        self.value = value
        self.placeholder = placeholder
        self.input_type = input_type

    def htmy(self, context: Context) -> Component:
        return html.div(
            html.label(self.label, for_=self.name),
            html.input_(
                id=self.name,
                class_="input",
                name=self.name,
                type=self.input_type,
                value=self.value,
                placeholder=self.placeholder,
            ),
            class_="field",
        )


class SelectField:
    def __init__(self, name: str, label: str, options: list[str], selected: str = ""):
        self.name = name
        self.label = label
        self.options = options
        self.selected = selected

    def htmy(self, context: Context) -> Component:
        option_elements = []
        for opt in self.options:
            if opt == self.selected:
                option_elements.append(html.option(opt, value=opt, selected=True))
            else:
                option_elements.append(html.option(opt, value=opt))

        return html.div(
            html.label(self.label, for_=self.name),
            html.select(*option_elements, id=self.name, class_="input", name=self.name),
            class_="field",
        )


class Button:
    def __init__(
        self,
        label: str,
        variant: str = "primary",
        button_type: str = "button",
        hx_post: str | None = None,
        hx_get: str | None = None,
        hx_target: str | None = None,
        hx_swap: str | None = None,
        csrf_token: str | None = None,
    ):
        self.label = label
        self.variant = variant
        self.button_type = button_type
        self.hx_post = hx_post
        self.hx_get = hx_get
        self.hx_target = hx_target
        self.hx_swap = hx_swap
        self.csrf_token = csrf_token

    def htmy(self, context: Context) -> Component:
        attrs: dict[str, Any] = {"type": self.button_type}
        if self.hx_post:
            attrs["hx_post"] = self.hx_post
        if self.hx_get:
            attrs["hx_get"] = self.hx_get
        if self.hx_target:
            attrs["hx_target"] = self.hx_target
        if self.hx_swap:
            attrs["hx_swap"] = self.hx_swap

        button_el = html.button(self.label, class_=f"btn btn-{self.variant}", **attrs)
        if self.csrf_token:
            return html.form(
                html.input_(type="hidden", name="csrf_token", value=self.csrf_token),
                html.button(self.label, class_=f"btn btn-{self.variant}", type="submit"),
                hx_post=self.hx_post or "",
                hx_target=self.hx_target or "",
                hx_swap=self.hx_swap or "innerHTML",
            )
        return button_el


class MetricCard:
    def __init__(self, label: str, value: Any, description: str = "", status: str = ""):
        self.label = label
        self.value = value
        self.description = description
        self.status = status

    def htmy(self, context: Context) -> Component:
        children: list[Any] = [
            html.div(self.label, class_="label"),
            html.div(str(self.value), class_="metric-value"),
        ]
        if self.description:
            children.append(html.div(self.description, class_="metric-caption"))

        attrs: dict[str, Any] = {"class": "metric-card"}
        if self.status:
            attrs["data-status"] = self.status

        return html.div(*children, **attrs)


class InfoTile:
    def __init__(self, title: str, value: Any, description: str = ""):
        self.title = title
        self.value = value
        self.description = description

    def htmy(self, context: Context) -> Component:
        children: list[Any] = [
            html.div(self.title, class_="label"),
            html.div(str(self.value), class_="info-tile-value"),
        ]
        if self.description:
            children.append(html.div(self.description, class_="metric-caption"))
        return html.article(*children, class_="info-tile")


class Panel:
    def __init__(self, title: str, description: str = "", children: list[Any] | None = None):
        self.title = title
        self.description = description
        self.children = children or []

    def htmy(self, context: Context) -> Component:
        header_children: list[Any] = [html.h2(self.title)]
        if self.description:
            header_children.append(html.p(self.description))

        return html.section(
            html.div(*header_children, class_="panel-header"),
            *self.children,
            class_="panel",
        )


class AuditList:
    def __init__(self, records: list[Mapping[str, Any]]):
        self.records = records

    def htmy(self, context: Context) -> Component:
        if not self.records:
            return html.div(
                html.div("No records found for the current filter.", class_="empty-state"),
                class_="audit-table",
            )

        rows = []
        for r in self.records:
            meta_spans = [html.span(r.get("timestamp", ""))]
            if r.get("tenant_id"):
                meta_spans.append(html.span(r["tenant_id"]))
            if r.get("provider_id"):
                meta_spans.append(html.span(r["provider_id"]))
            if r.get("actor_username"):
                meta_spans.append(html.span(r["actor_username"]))

            card_children = [
                html.div(
                    html.strong(r.get("event_type", "UNKNOWN")),
                    html.span(
                        r.get("status", ""),
                        class_="audit-status",
                        data_status=r.get("status", ""),
                    ),
                    class_="audit-row-top",
                ),
                html.div(*meta_spans, class_="audit-row-meta"),
            ]

            if r.get("details"):
                details_json = json.dumps(r["details"], indent=2)
                card_children.append(html.pre(details_json, class_="audit-details"))

            rows.append(html.article(*card_children, class_="audit-row"))

        return html.div(*rows, class_="audit-table")


# =====================================================================
# Dashboard Panel Components
# =====================================================================


class SummaryCardsPanel:
    def __init__(self, context_data: dict[str, Any]):
        self.data = context_data

    def htmy(self, context: Context) -> Component:
        health = self.data.get("health", {})
        persistence = self.data.get("persistence", {})
        security = self.data.get("security", {})
        inventory = self.data.get("inventory", {})

        is_healthy = health.get("ok")
        health_val = "Healthy" if is_healthy else "Needs attention"
        health_status = "healthy" if is_healthy else "warning"

        stores_count = len(persistence.get("stores", [])) if persistence.get("configured") else 0
        throttle_blocks = (
            security.get("runtime_throttle", {}).get("blocked_bucket_count", 0)
            if security.get("configured")
            else 0
        )
        security_status = "warning" if throttle_blocks > 0 else ""

        return html.section(
            MetricCard(
                "Environment", inventory.get("environment") or "-", "Current runtime environment"
            ),
            MetricCard("Health", health_val, "Overall runtime status", status=health_status),
            MetricCard(
                "Persistence Stores", f"{stores_count} targets", "Configured storage targets"
            ),
            MetricCard(
                "Security Signals",
                f"{throttle_blocks} blocked",
                "Blocked runtime credential buckets",
                status=security_status,
            ),
            class_="metric-grid",
        )


class RuntimeOverviewPanel:
    def __init__(self, context_data: dict[str, Any]):
        self.data = context_data

    def htmy(self, context: Context) -> Component:
        health = self.data.get("health", {})
        inventory = self.data.get("inventory", {})
        bootstrap = self.data.get("bootstrap", {})
        config_info = self.data.get("config", {})

        health_val = "Healthy" if health.get("ok") else "Needs attention"
        admins_list = bootstrap.get("admins", [])
        admins_count = len(admins_list)

        # Build KV Lists
        providers_str = (
            ", ".join(inventory.get("oidc_providers", []))
            if inventory.get("oidc_providers")
            else "None configured"
        )
        plugins_str = (
            ", ".join(inventory.get("registered_plugins", []))
            if inventory.get("registered_plugins")
            else "None registered"
        )
        tenant_plugins_count = len(inventory.get("tenant_plugins", {}))
        config_val = "Configured" if config_info.get("configured") else "Missing or invalid"

        # Build Operational Posture Grid
        posture_grid = html.div(
            InfoTile("Health", health_val, "Runtime status based on current checks"),
            InfoTile(
                "Issuer",
                inventory.get("issuer") or "-",
                "Current issuer value exposed by the runtime",
            ),
            InfoTile(
                "Environment",
                inventory.get("environment") or "-",
                "Environment profile loaded from config",
            ),
            InfoTile(
                "Bootstrap Admins", admins_count, "Operator identities recorded in bootstrap state"
            ),
            class_="info-tile-grid",
        )

        # Build operational cards
        posture_card = html.div(
            html.h3("Operational Posture"),
            posture_grid,
            class_="overview-card",
        )

        inventory_card = html.div(
            html.h3("Runtime Inventory"),
            html.dl(
                html.div(html.dt("OIDC Providers"), html.dd(providers_str)),
                html.div(html.dt("Registered Plugins"), html.dd(plugins_str)),
                html.div(
                    html.dt("Tenant Plugin Map"), html.dd(f"{tenant_plugins_count} tenant entries")
                ),
                html.div(html.dt("Config State"), html.dd(config_val)),
                class_="kv-list",
            ),
            class_="overview-card",
        )

        # Health checks details list
        details_list = []
        for item in health.get("details", []):
            details_list.append(html.li(item))
        if not details_list:
            details_list.append(html.li("No runtime details available."))

        health_card = html.div(
            html.h3("Health Details"),
            html.ul(*details_list, class_="status-list"),
            class_="overview-card",
        )

        # Bootstrap admins list
        admin_items = []
        for admin in admins_list:
            admin_desc = f"{admin.get('username', '')} on {admin.get('tenant_id', '')}"
            if admin.get("email"):
                admin_desc += f" · {admin['email']}"
            admin_items.append(html.li(admin_desc))

        admins_el = (
            html.ul(*admin_items, class_="status-list")
            if admin_items
            else html.div("No bootstrap admins are recorded yet.", class_="empty-state")
        )

        bootstrap_card = html.div(
            html.h3("Bootstrap Admins"),
            admins_el,
            class_="overview-card",
        )

        # JSON Configuration print
        raw_config_json = json.dumps(config_info, indent=2)

        return Panel(
            "Runtime Overview",
            "Health, config, and plugin inventory for this deployment.",
            [
                html.div(posture_card, inventory_card, class_="overview-grid"),
                html.div(health_card, bootstrap_card, class_="overview-grid"),
                html.details(
                    html.summary("View raw config snapshot"),
                    html.pre(raw_config_json, class_="pretty-output"),
                    class_="detail-panel",
                ),
            ],
        )


class InfrastructurePanel:
    def __init__(self, context_data: dict[str, Any]):
        self.data = context_data

    def _build_stores_and_counters(self, persistence: dict, observability: dict) -> ComponentType:
        store_items = []
        for s in persistence.get("stores", []):
            store_items.append(
                html.li(f"{s.get('store_name', '')} · {s.get('backend', '')} · {s.get('mode', '')}")
            )
        stores_el = (
            html.ul(*store_items, class_="status-list")
            if store_items
            else html.div("No persistence stores are available.", class_="empty-state")
        )

        counter_items = []
        for c in observability.get("counters", []):
            counter_items.append(html.li(f"{c.get('name', '')} · {c.get('value', '')}"))
        counters_el = (
            html.ul(*counter_items, class_="status-list")
            if counter_items
            else html.div("No counters have been recorded yet.", class_="empty-state")
        )

        return html.div(
            html.div(html.h3("Persistence Stores"), stores_el, class_="overview-card"),
            html.div(html.h3("Observability Counters"), counters_el, class_="overview-card"),
            class_="overview-grid",
        )

    def _build_abuse_controls(self, security: dict) -> ComponentType:
        runtime_ctrls = []
        if security.get("configured"):
            rt = security.get("runtime_throttle", {})
            runtime_ctrls.append(html.li(f"Throttle storage · {rt.get('storage_kind', '')}"))
            runtime_ctrls.append(html.li(f"Tracked buckets · {rt.get('bucket_count', '')}"))
            runtime_ctrls.append(html.li(f"Blocked buckets · {rt.get('blocked_bucket_count', '')}"))
            if rt.get("table_name"):
                runtime_ctrls.append(html.li(f"Store table · {rt['table_name']}"))
        rt_controls_el = (
            html.ul(*runtime_ctrls, class_="status-list")
            if runtime_ctrls
            else html.div("Runtime throttle diagnostics are not available.", class_="empty-state")
        )

        admin_ctrls = []
        if security.get("configured"):
            at = security.get("admin_ui_throttle", {})
            admin_ctrls.append(html.li(f"Throttle storage · {at.get('storage_kind', '')}"))
            admin_ctrls.append(html.li(f"Tracked buckets · {at.get('bucket_count', '')}"))
            admin_ctrls.append(html.li(f"Blocked buckets · {at.get('blocked_bucket_count', '')}"))
        at_controls_el = (
            html.ul(*admin_ctrls, class_="status-list")
            if admin_ctrls
            else html.div("Admin UI throttle diagnostics are not available.", class_="empty-state")
        )

        return html.div(
            html.div(html.h3("Runtime Abuse Controls"), rt_controls_el, class_="overview-card"),
            html.div(html.h3("Admin UI Abuse Controls"), at_controls_el, class_="overview-card"),
            class_="overview-grid",
        )

    def _build_blocked_buckets_and_audits(self, security: dict) -> ComponentType:
        blocked_bucket_items = []
        if security.get("configured"):
            for b in security.get("runtime_throttle", {}).get("buckets", []):
                if b.get("blocked"):
                    blocked_bucket_items.append(
                        html.li(
                            f"{b.get('scope', '')} · fingerprint {b.get('fingerprint', '')} · retry {b.get('retry_after_seconds', '')}s"
                        )
                    )
        blocked_buckets_el = (
            html.ul(*blocked_bucket_items, class_="status-list")
            if blocked_bucket_items
            else html.div("No runtime buckets are currently blocked.", class_="empty-state")
        )

        plugin_audit_items = []
        if security.get("configured"):
            for r in security.get("recent_plugin_audit_records", [])[:8]:
                plugin_audit_items.append(
                    html.li(
                        f"{r.get('plugin_name', '')} · {r.get('execution_type', '')} · {r.get('status', '')} · {r.get('duration_ms', '')}ms"
                    )
                )
        plugin_audits_el = (
            html.ul(*plugin_audit_items, class_="status-list")
            if plugin_audit_items
            else html.div("No plugin audit entries have been recorded yet.", class_="empty-state")
        )

        return html.div(
            html.div(
                html.h3("Blocked Runtime Buckets"), blocked_buckets_el, class_="overview-card"
            ),
            html.div(
                html.h3("Recent Plugin Runtime Audit"), plugin_audits_el, class_="overview-card"
            ),
            class_="overview-grid",
        )

    def htmy(self, context: Context) -> Component:
        persistence = self.data.get("persistence", {})
        jwks = self.data.get("jwks", {})
        observability = self.data.get("observability", {})
        security = self.data.get("security", {})
        recent_admin_actions = self.data.get("recent_admin_actions", [])
        bootstrap = self.data.get("bootstrap", {})

        stores_count = len(persistence.get("stores", [])) if persistence.get("configured") else 0
        jwks_count = len(jwks.get("keys", [])) if isinstance(jwks.get("keys"), list) else 0
        counters_count = (
            len(observability.get("counters", [])) if observability.get("configured") else 0
        )
        correlation_header = (
            observability.get("correlation_header_name") or "-"
            if observability.get("configured")
            else "-"
        )
        runtime_blocks = (
            security.get("runtime_throttle", {}).get("blocked_bucket_count", 0)
            if security.get("configured")
            else 0
        )
        admin_blocks = (
            security.get("admin_ui_throttle", {}).get("blocked_bucket_count", 0)
            if security.get("configured")
            else 0
        )
        plugin_audits = (
            security.get("plugin_audit_record_count", 0) if security.get("configured") else 0
        )

        # Operational Grid Tiles
        grid_tiles = html.div(
            InfoTile("Stores", stores_count, "Configured persistence targets"),
            InfoTile("JWKS Keys", jwks_count, "Currently exported public keys"),
            InfoTile("Metrics", counters_count, "Named observability counters"),
            InfoTile(
                "Correlation Header",
                correlation_header,
                "Header propagated through runtime responses",
            ),
            InfoTile(
                "Runtime Throttle Blocks",
                runtime_blocks,
                "Credential or verification buckets currently blocked",
            ),
            InfoTile(
                "Admin UI Throttle Blocks",
                admin_blocks,
                "Operator login or action buckets currently blocked",
            ),
            InfoTile(
                "Plugin Audit Records", plugin_audits, "Recent hook and endpoint audit entries"
            ),
            class_="info-tile-grid",
        )

        # Filters Form
        custom_scopes = security.get("runtime_throttle", {}).get("available_scopes", [])
        fallback_scopes = [
            "oauth.login",
            "oauth.token",
            "webauthn.register",
            "webauthn.login",
            "otp.verify",
        ]
        throttle_scopes = [""] + sorted(set(custom_scopes + fallback_scopes))

        custom_statuses = security.get("available_plugin_statuses", [])
        fallback_statuses = ["success", "failure", "skipped", "error"]
        plugin_statuses = [""] + sorted(set(custom_statuses + fallback_statuses))

        filters_form = html.form(
            html.div(
                SelectField(
                    "throttle_scope",
                    "Blocked throttle scope",
                    throttle_scopes,
                    self.data.get("current_security_throttle_scope", ""),
                ),
                SelectField(
                    "plugin_status",
                    "Plugin audit status",
                    plugin_statuses,
                    self.data.get("current_plugin_audit_status", ""),
                ),
                class_="overview-grid",
            ),
            html.div(
                html.button("Apply Filters", class_="btn btn-primary", type="submit"),
                class_="button-grid",
            ),
            class_="form-stack",
            **{
                "data-workspace-view": "/partials/dashboard/infrastructure",
                "hx-get": "/partials/dashboard/infrastructure",
                "hx-target": "#workspace-tab-panel",
                "hx-swap": "innerHTML",
            },
        )

        # Advanced diagnostic details
        advanced_details = html.details(
            html.summary("Advanced diagnostics"),
            html.div(
                html.details(
                    html.summary("Persistence details"),
                    html.pre(
                        json.dumps(persistence, indent=2), class_="pretty-output pretty-green"
                    ),
                    class_="detail-panel",
                ),
                html.details(
                    html.summary("JWKS payload"),
                    html.pre(json.dumps(jwks, indent=2), class_="pretty-output pretty-magenta"),
                    class_="detail-panel",
                ),
                html.details(
                    html.summary("Observability payload"),
                    html.pre(
                        json.dumps(observability, indent=2), class_="pretty-output pretty-blue"
                    ),
                    class_="detail-panel",
                ),
                html.details(
                    html.summary("Security payload"),
                    html.pre(json.dumps(security, indent=2), class_="pretty-output pretty-magenta"),
                    class_="detail-panel",
                ),
                class_="split-grid three-up-grid stack-compact",
            ),
            class_="detail-panel",
        )

        # -------------------------------------------------------------
        # OneLogin inspired Tab Canvas Panels
        # -------------------------------------------------------------

        # TAB 1: General & Stores Content
        tab_general = html.div(
            self._build_stores_and_counters(persistence, observability),
            advanced_details,
            id="panel-infra-general",
            class_="tab-content-panel active",
        )

        # TAB 2: Abuse Controls Content
        tab_abuse = html.div(
            filters_form,
            self._build_abuse_controls(security),
            self._build_blocked_buckets_and_audits(security),
            id="panel-infra-abuse",
            class_="tab-content-panel",
        )

        # TAB 3: Key Management Forms (previously inside right action rail)
        tab_keys = html.div(
            html.div(
                html.h3("Rotate Keys & Token Verifiers"),
                html.p(
                    "Rotate active cryptographic keys for verifier updates and encryption target renewals.",
                    class_="workspace-copy",
                ),
                html.div(
                    html.form(
                        html.input_(
                            type="hidden", name="csrf_token", value=self.data.get("csrf_token", "")
                        ),
                        html.input_(type="hidden", name="use", value="sig"),
                        html.button(
                            "Rotate Signing Keys", class_="btn btn-primary btn-block", type="submit"
                        ),
                        **{
                            "data-workspace-view": "/partials/dashboard/infrastructure",
                            "hx-post": "/partials/actions/key-rotate",
                            "hx-target": "#workspace-tab-panel",
                            "hx-swap": "innerHTML",
                        },
                    ),
                    html.form(
                        html.input_(
                            type="hidden", name="csrf_token", value=self.data.get("csrf_token", "")
                        ),
                        html.input_(type="hidden", name="use", value="enc"),
                        html.button(
                            "Rotate Encryption Keys",
                            class_="btn btn-danger btn-block",
                            type="submit",
                        ),
                        **{
                            "data-workspace-view": "/partials/dashboard/infrastructure",
                            "hx-post": "/partials/actions/key-rotate",
                            "hx-target": "#workspace-tab-panel",
                            "hx-swap": "innerHTML",
                        },
                    ),
                    style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px;",
                ),
                class_="overview-card",
            ),
            id="panel-infra-keys",
            class_="tab-content-panel",
        )

        # TAB 4: Bootstrap Admin Credentials (previously inside right action rail)
        tab_bootstrap = html.div(
            html.div(
                html.h3("Rotate Bootstrap Administrator Credentials"),
                html.p(
                    "Replace the emergency local bootstrap credentials seeded during initial setups.",
                    class_="workspace-copy",
                ),
                html.form(
                    html.input_(
                        type="hidden", name="csrf_token", value=self.data.get("csrf_token", "")
                    ),
                    html.input_(type="hidden", name="role_name", value="admin"),
                    html.input_(type="hidden", name="client_id", value="bootstrap-admin-client"),
                    Field("tenant_id", "Tenant ID", self.data.get("default_tenant_id", "tenant-1")),
                    html.div(
                        Field(
                            "username",
                            "Admin Username",
                            self.data.get("default_actor_username", "admin"),
                        ),
                        style="margin-top: 8px;",
                    ),
                    html.div(
                        Field(
                            "password", "Admin Password", "", "New password", input_type="password"
                        ),
                        style="margin-top: 8px;",
                    ),
                    html.div(
                        Field(
                            "email",
                            "Admin Email",
                            bootstrap.get("admins", [{}])[0].get("email", "")
                            if bootstrap.get("admins")
                            else "",
                        ),
                        style="margin-top: 8px;",
                    ),
                    html.div(
                        html.button(
                            "Update Bootstrap Credentials", class_="btn btn-primary", type="submit"
                        ),
                        style="margin-top: 12px;",
                    ),
                    class_="form-stack",
                    **{
                        "data-workspace-view": "/partials/dashboard/admin-audit",
                        "hx-post": "/partials/actions/init-admin",
                        "hx-target": "#workspace-tab-panel",
                        "hx-swap": "innerHTML",
                    },
                ),
                class_="overview-card",
            ),
            id="panel-infra-bootstrap",
            class_="tab-content-panel",
        )

        tab_headers_bar = html.div(
            html.button(
                "🛠️ General & Stores",
                id="btn-infra-general",
                class_="tab-header-btn infra-tab-btn active",
            ),
            html.button(
                "🚫 Abuse Controls", id="btn-infra-abuse", class_="tab-header-btn infra-tab-btn"
            ),
            html.button(
                "🔑 Key Management", id="btn-infra-keys", class_="tab-header-btn infra-tab-btn"
            ),
            html.button(
                "👤 Bootstrap Admin",
                id="btn-infra-bootstrap",
                class_="tab-header-btn infra-tab-btn",
            ),
            class_="tab-headers",
        )

        return Panel(
            "Infrastructure, Keys, and Observability",
            "Persistence configurations, encryption endpoints, and telemetry signals.",
            [
                grid_tiles,
                html.div(
                    tab_headers_bar,
                    tab_general,
                    tab_abuse,
                    tab_keys,
                    tab_bootstrap,
                    class_="tab-container",
                ),
                html.div(
                    html.div("Recent Admin Actions", class_="subheading"),
                    AuditList(recent_admin_actions),
                    class_="recent-list",
                ),
            ],
        )


class RebacPanel:
    def __init__(self, context_data: dict[str, Any]):
        self.data = context_data

    def htmy(self, context: Context) -> Component:
        dsl_val = self.data.get("dsl") or ""
        tuples = self.data.get("tuples") or []

        # Zanzibar schema parser & Live visualizer extraction
        from astraauth_policy import SchemaParser

        parsed_schema = None
        try:
            parsed_schema = SchemaParser.parse(dsl_val)
        except Exception:
            pass

        snippets_toolbar = html.div(
            html.button(
                "📄 Document Collaboration Schema",
                class_="btn-snippet",
                data_snippet="document",
                type="button",
            ),
            html.button(
                "🏢 Organization Hierarchy Schema",
                class_="btn-snippet",
                data_snippet="org",
                type="button",
            ),
            class_="snippets-bar",
        )

        # Zanzibar schema compiler card
        schema_card = html.div(
            html.h3("Zanzibar-style Schema Compiler"),
            html.p(
                "Define your entity hierarchy, relations, and permissions rules using KeyNetra-style DSL.",
                class_="sidebar-copy",
                style="margin-bottom: 8px;",
            ),
            snippets_toolbar,
            html.form(
                html.div(
                    html.label("Schema DSL Code Editor", for_="dsl"),
                    html.textarea(
                        dsl_val,
                        id="dsl",
                        class_="input",
                        name="dsl",
                        rows="12",
                        style="font-family: monospace; width: 100%; padding: 8px; border-radius: 4px; border: 1px solid var(--border); background: var(--bg-card); color: var(--text); margin-top: 8px;",
                    ),
                    class_="field",
                ),
                html.div(
                    html.button("Compile & Save Schema", class_="btn btn-primary", type="submit"),
                    style="margin-top: 12px;",
                ),
                hx_post="/partials/dashboard/rebac/schema/compile",
                hx_target="#schema-feedback-region",
                hx_swap="innerHTML",
            ),
            html.div(id="schema-feedback-region", style="margin-top: 12px;"),
            class_="overview-card",
        )

        # Evaluator Console Card
        check_card = html.div(
            html.h3("Permission Check Evaluator"),
            html.p(
                "Evaluate permissions or relations dynamically against the active schema rules and relationship facts.",
                class_="sidebar-copy",
                style="margin-bottom: 12px;",
            ),
            html.form(
                html.div(
                    Field("subject_type", "Subject Type", placeholder="e.g. user"),
                    Field("subject_id", "Subject ID", placeholder="e.g. alice"),
                    style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;",
                ),
                html.div(
                    Field(
                        "relation_or_permission", "Relation or Permission", placeholder="e.g. view"
                    ),
                    style="margin-top: 8px;",
                ),
                html.div(
                    Field("object_type", "Object Type", placeholder="e.g. document"),
                    Field("object_id", "Object ID", placeholder="e.g. 1"),
                    style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px;",
                ),
                html.div(
                    html.button("Evaluate Check", class_="btn btn-primary", type="submit"),
                    style="margin-top: 12px;",
                ),
                hx_post="/partials/dashboard/rebac/check",
                hx_target="#check-results-region",
                hx_swap="innerHTML",
            ),
            html.div(id="check-results-region", style="margin-top: 12px;"),
            class_="overview-card",
        )

        # Live Entity Visualizer Nodes
        viz_nodes_list = []
        if parsed_schema and parsed_schema.objects:
            for obj_name, obj in parsed_schema.objects.items():
                relations_badges = []
                for rel_name in obj.relations.keys():
                    relations_badges.append(html.span(rel_name, class_="viz-item-badge"))

                permissions_badges = []
                for perm_name in obj.permissions.keys():
                    permissions_badges.append(html.span(perm_name, class_="viz-item-badge"))

                node_card = html.div(
                    html.div(f"entity: {obj_name}", class_="viz-node-title"),
                    html.div(
                        html.div("Relations", class_="viz-section-title"),
                        html.div(*relations_badges, class_="viz-item-list")
                        if relations_badges
                        else html.div("None", style="font-size:0.75rem;color:var(--muted);"),
                        class_="viz-node-section",
                    ),
                    html.div(
                        html.div("Permissions", class_="viz-section-title"),
                        html.div(*permissions_badges, class_="viz-item-list")
                        if permissions_badges
                        else html.div("None", style="font-size:0.75rem;color:var(--muted);"),
                        class_="viz-node-section",
                    ),
                    class_="viz-node-card",
                )
                viz_nodes_list.append(node_card)

        viz_section_el = (
            html.div(
                html.h4("Active Zanzibar Schema Graph Nodes:"),
                html.div(*viz_nodes_list, class_="rebac-viz-grid"),
                style="margin-top: 12px; padding: 12px; border-radius: var(--radius); border: 1px solid var(--border); background: var(--bg-panel);",
            )
            if viz_nodes_list
            else html.div()
        )

        # Tuples form and table
        add_tuple_form = html.form(
            html.div(
                Field("obj_type", "Object Type", placeholder="document"),
                Field("obj_id", "Object ID", placeholder="1"),
                style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px;",
            ),
            html.div(
                Field("rel", "Relation", placeholder="editor"),
                style="margin-top: 6px;",
            ),
            html.div(
                Field("sub_type", "Subject Type", placeholder="user"),
                Field("sub_id", "Subject ID", placeholder="alice"),
                style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 6px;",
            ),
            html.div(
                Field("sub_rel", "Subject Relation (Optional)", placeholder="member"),
                style="margin-top: 6px;",
            ),
            html.div(
                html.button(
                    "Add Relation Tuple", class_="btn btn-secondary btn-block", type="submit"
                ),
                style="margin-top: 12px;",
            ),
            hx_post="/partials/dashboard/rebac/tuples/add",
            hx_target="#tuples-table-region",
            hx_swap="innerHTML",
            class_="sidebar-form",
            style="padding: 12px; border: 1px solid var(--border); border-radius: 4px; background: var(--bg-panel);",
        )

        tuples_card = html.div(
            html.h3("Relational Tuples Playground"),
            html.p(
                "Write facts asserting relations between subjects and objects. Example: (user:bob, owner, folder:sub)",
                class_="sidebar-copy",
                style="margin-bottom: 12px;",
            ),
            html.div(
                add_tuple_form,
                html.div(RebacTuplesList(tuples), id="tuples-table-region"),
                style="display: grid; grid-template-columns: 1.5fr 2fr; gap: 16px;",
            ),
            class_="overview-card",
            style="grid-column: span 2;",
        )

        return Panel(
            "ReBAC Access Policy Playground",
            "Author schemas, write relation tuples, and audit access checks in real-time.",
            [
                html.div(schema_card, check_card, class_="overview-grid"),
                viz_section_el,
                html.div(tuples_card, class_="overview-grid", style="margin-top: 16px;"),
            ],
        )


class RebacTuplesList:
    def __init__(self, tuples: list[Any]):
        self.tuples = tuples

    def htmy(self, context: Context) -> Component:
        if not self.tuples:
            return html.div("No relation tuples configured for this tenant.", class_="empty-state")

        rows = []
        for t in self.tuples:
            sub_rel_str = f"#{t.subject_relation}" if t.subject_relation else ""
            rows.append(
                html.article(
                    html.div(
                        html.code(f"{t.object_type}:{t.object_id}"),
                        html.span(f" #{t.relation}", style="color: var(--accent);"),
                        html.span(" @ "),
                        html.code(f"{t.subject_type}:{t.subject_id}{sub_rel_str}"),
                    ),
                    html.button(
                        "Delete",
                        class_="btn btn-secondary",
                        style="padding: 2px 8px; font-size: 0.8em;",
                        hx_post=f"/partials/dashboard/rebac/tuples/delete?id={t.id}",
                        hx_target="#tuples-table-region",
                        hx_swap="innerHTML",
                        type="button",
                    ),
                    class_="audit-row",
                    style="padding: 8px; font-size: 0.9em; display: flex; justify-content: space-between; align-items: center;",
                )
            )

        return html.div(*rows, class_="audit-table", style="max-height: 350px; overflow-y: auto;")


class TenantsPanel:
    def __init__(self, context_data: dict[str, Any]):
        self.data = context_data

    def htmy(self, context: Context) -> Component:
        tenants = self.data.get("tenants") or []

        tenants_card = html.div(
            html.h3("Active Tenant Workspaces"),
            html.p(
                "Active tenants and database connection isolation boundaries defined in this runtime.",
                class_="sidebar-copy",
                style="margin-bottom: 12px;",
            ),
            html.div(TenantsList(tenants), id="tenants-table-region"),
            class_="overview-card",
            style="grid-column: span 1;",
        )

        create_form = html.form(
            Field("tenant_id", "Tenant ID", placeholder="e.g. tenant-abc"),
            html.div(
                Field("name", "Tenant Name", placeholder="e.g. Enterprise Corp"),
                style="margin-top: 8px;",
            ),
            html.div(
                Field(
                    "database_url",
                    "Database Connection URL",
                    placeholder="e.g. sqlite:///data/tenant-abc.db",
                ),
                style="margin-top: 8px;",
            ),
            html.div(
                Field("max_users", "Max Users Limit", placeholder="5000", value="5000"),
                Field(
                    "max_relation_tuples", "Max Relation Tuples", placeholder="20000", value="20000"
                ),
                style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px;",
            ),
            html.div(
                html.button("Register Tenant", class_="btn btn-primary", type="submit"),
                style="margin-top: 12px;",
            ),
            **{
                "hx-post": "/partials/dashboard/tenants/add",
                "hx-target": "#tenants-table-region",
                "hx-swap": "innerHTML",
                "hx-on::after-request": "this.reset()",
            },
        )

        create_card = html.div(
            html.h3("Register New Tenant Workspace"),
            html.p(
                "Provide tenant metadata, isolation limits, and database connection strings.",
                class_="sidebar-copy",
                style="margin-bottom: 12px;",
            ),
            create_form,
            class_="overview-card",
            style="grid-column: span 1;",
        )

        return Panel(
            "Multi-Tenancy Workspace Isolation",
            "Inspect, manage, and register isolated tenant boundaries in the Astra platform.",
            [html.div(tenants_card, create_card, class_="overview-grid")],
        )


class TenantsList:
    def __init__(self, tenants: list[Any]):
        self.tenants = tenants

    def htmy(self, context: Context) -> Component:
        if not self.tenants:
            return html.div("No tenant workspaces configured.", class_="empty-state")

        rows = []
        for t in self.tenants:
            name = t.get("name", "")
            tenant_id = t.get("tenant_id", "")
            database_url = t.get("database_url", "")
            max_users = t.get("max_users", "")
            max_relation_tuples = t.get("max_relation_tuples", "")

            rows.append(
                html.article(
                    html.div(
                        html.strong(name, style="color: var(--text);"),
                        f" ({tenant_id})",
                        html.br(),
                        html.span(
                            f"DB: {database_url}",
                            style="font-size: 0.85em; color: var(--accent); word-break: break-all;",
                        ),
                        html.br(),
                        html.span(
                            f"Limits — Users: {max_users} · Relation Tuples: {max_relation_tuples}",
                            style="font-size: 0.85em; color: var(--text-muted);",
                        ),
                    ),
                    html.button(
                        "Delete",
                        class_="btn btn-secondary",
                        style="padding: 4px 10px; font-size: 0.85em;",
                        hx_post=f"/partials/dashboard/tenants/delete?tenant_id={tenant_id}",
                        hx_target="#tenants-table-region",
                        hx_swap="innerHTML",
                        type="button",
                    ),
                    class_="audit-row",
                    style="padding: 10px; font-size: 0.95em; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border);",
                )
            )

        return html.div(*rows, class_="audit-table", style="max-height: 350px; overflow-y: auto;")


class OidcAuditPanel:
    def __init__(self, context_data: dict[str, Any]):
        self.data = context_data

    def htmy(self, context: Context) -> Component:
        tenant_id = self.data.get("audit_tenant_id") or ""
        provider_id = self.data.get("audit_provider_id") or ""
        records = self.data.get("oidc_records") or []

        form_el = html.form(
            Field("tenant_id", "Tenant ID", tenant_id, "Tenant ID"),
            Field("provider_id", "Provider ID", provider_id, "Optional provider ID"),
            html.button("Load OIDC Audit", class_="btn btn-primary", type="submit"),
            class_="inline-form",
            **{
                "data-workspace-view": "/partials/dashboard/oidc-audit",
                "hx-get": "/partials/dashboard/oidc-audit",
                "hx-target": "#workspace-tab-panel",
                "hx-swap": "innerHTML",
            },
        )

        return Panel(
            "OIDC Audit",
            "Inspect federation activity by tenant and provider.",
            [
                form_el,
                AuditList(records),
            ],
        )


class AdminAuditPanel:
    def __init__(self, context_data: dict[str, Any]):
        self.data = context_data

    def htmy(self, context: Context) -> Component:
        tenant_id = self.data.get("admin_audit_tenant") or ""
        actor_username = self.data.get("admin_audit_actor") or ""
        records = self.data.get("admin_records") or []

        form_el = html.form(
            Field("tenant_id", "Tenant Filter", tenant_id, "Optional tenant"),
            Field("actor_username", "Actor Username", actor_username, "Optional username"),
            html.button("Load Admin Audit", class_="btn btn-primary", type="submit"),
            class_="inline-form",
            **{
                "data-workspace-view": "/partials/dashboard/admin-audit",
                "hx-get": "/partials/dashboard/admin-audit",
                "hx-target": "#workspace-tab-panel",
                "hx-swap": "innerHTML",
            },
        )

        return Panel(
            "Admin Audit",
            "Review operator actions and current audit history.",
            [
                form_el,
                AuditList(records),
            ],
        )
