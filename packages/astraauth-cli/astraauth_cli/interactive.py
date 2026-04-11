# mypy: disable-error-code="import-not-found"
from __future__ import annotations

from pathlib import Path
from typing import Any, TypedDict, cast

import typer
from astraauth_core.config import DEFAULT_ASTRAAUTH_HOME, DatabaseBackend, EnvironmentName

QuestionaryModule = Any


class InteractiveExitError(Exception):
    """Raised when the user exits an interactive CLI flow."""


class AdminInitAnswers(TypedDict):
    tenant_id: str
    username: str
    password: str
    email: str | None


class KeyRotateAnswers(TypedDict):
    use: str


def _load_questionary() -> QuestionaryModule | None:
    try:
        import questionary
    except ImportError:
        return None
    return questionary


def select_action(*, message: str, choices: list[tuple[str, str]]) -> str:
    resolved_choices = list(choices)
    if not any(value == "exit" for value, _label in resolved_choices):
        resolved_choices.append(("exit", "Exit"))
    questionary = _load_questionary()
    if questionary is not None:
        result = questionary.select(
            message,
            choices=[
                questionary.Choice(title=label, value=value) for value, label in resolved_choices
            ],
        ).ask()
        if isinstance(result, str):
            return result
        raise InteractiveExitError()
    typer.echo(message)
    for value, label in resolved_choices:
        typer.echo(f"- {value}: {label}")
    result = cast(str, typer.prompt("Select action", default=resolved_choices[0][0]))
    if result == "exit":
        raise InteractiveExitError()
    return result


def prompt_text(message: str, *, default: str | None = None, password: bool = False) -> str:
    questionary = _load_questionary()
    if questionary is not None:
        if password:
            result = questionary.password(message).ask()
        else:
            result = questionary.text(message, default=default or "").ask()
        if isinstance(result, str) and result:
            if result.strip().lower() == "exit":
                raise InteractiveExitError()
            return result
        raise InteractiveExitError()
    result = cast(str, typer.prompt(message, default=default or "", hide_input=password))
    if result.strip().lower() == "exit":
        raise InteractiveExitError()
    return result


def prompt_confirm(message: str, *, default: bool = True) -> bool:
    questionary = _load_questionary()
    if questionary is not None:
        result = questionary.confirm(message, default=default).ask()
        if isinstance(result, bool):
            return result
        raise InteractiveExitError()
    return bool(typer.confirm(message, default=default))


def prompt_environment(*, default: EnvironmentName = "dev") -> EnvironmentName:
    value = prompt_text("Environment", default=default)
    return cast(EnvironmentName, value)


def prompt_backend(*, default: DatabaseBackend = "sqlite") -> DatabaseBackend:
    value = prompt_text("Persistence backend", default=default)
    return cast(DatabaseBackend, value)


def admin_init_answers(*, home: Path) -> AdminInitAnswers:
    _ = home
    return {
        "tenant_id": prompt_text("Tenant ID", default="tenant-1"),
        "username": prompt_text("Admin username", default="admin"),
        "password": prompt_text("Admin password", password=True),
        "email": prompt_text("Admin email", default="admin@example.com"),
    }


def key_rotate_answers(*, home: Path) -> KeyRotateAnswers:
    _ = home
    use = select_action(
        message="Which key set do you want to rotate?",
        choices=[("sig", "Signing keys"), ("enc", "Encryption keys")],
    )
    return {"use": use}


def resolve_home(home: Path | None) -> Path:
    return home or DEFAULT_ASTRAAUTH_HOME
