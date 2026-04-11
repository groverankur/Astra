from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from astraauth_service import runtime_inventory_report

from astraauth_cli.display import render_action_table, render_admin_summary
from astraauth_cli.interactive import (
    InteractiveExitError,
    admin_init_answers,
    key_rotate_answers,
    select_action,
)


def run_admin_ui(
    *,
    home: Path,
    init_admin: Callable[..., None],
    rotate_keys: Callable[..., None],
    show_health: Callable[..., None],
) -> None:
    inventory = runtime_inventory_report(home=home)
    render_admin_summary(home=inventory.home, environment=inventory.environment, issuer=inventory.issuer)
    choices = [
        ("health", "Show runtime health"),
        ("init-admin", "Create bootstrap admin"),
        ("key-rotate", "Rotate runtime keys"),
        ("exit", "Exit admin UI"),
    ]
    while True:
        render_action_table([(value, label) for value, label in choices])
        try:
            action = select_action(message="Choose an admin action", choices=choices)
        except InteractiveExitError:
            return
        if action == "exit":
            return
        if action == "health":
            show_health(home=home, as_json=False)
            continue
        if action == "init-admin":
            try:
                admin_answers = admin_init_answers(home=home)
            except InteractiveExitError:
                return
            init_admin(
                home=home,
                tenant_id=admin_answers["tenant_id"],
                username=admin_answers["username"],
                password=admin_answers["password"],
                email=admin_answers["email"],
            )
            continue
        if action == "key-rotate":
            try:
                rotate_answers = key_rotate_answers(home=home)
            except InteractiveExitError:
                return
            rotate_keys(home=home, use=rotate_answers["use"], as_json=False)
