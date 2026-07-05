from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


class RequestContext(Protocol):
    def header(self, name: str) -> str | None: ...
    def cookie(self, name: str) -> str | None: ...
    def query(self, name: str) -> str | None: ...
    def form(self, name: str) -> str | None: ...
    def method(self) -> str: ...
    def path(self) -> str: ...
    def ip(self) -> str | None: ...
    def json_body(self) -> dict[str, Any] | None: ...


@dataclass(frozen=True)
class NormalizedRequestContext:
    http_method: str
    request_path: str
    query_params: Mapping[str, str]
    headers: Mapping[str, str]
    form_data: Mapping[str, str] = field(default_factory=dict)
    cookies: Mapping[str, str] = field(default_factory=dict)
    client_ip: str | None = None
    body_json: dict[str, Any] | None = None

    def header(self, name: str) -> str | None:
        direct = self.headers.get(name) or self.headers.get(name.lower())
        if direct is not None:
            return direct
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None

    def cookie(self, name: str) -> str | None:
        return self.cookies.get(name)

    def query(self, name: str) -> str | None:
        return self.query_params.get(name)

    def form(self, name: str) -> str | None:
        return self.form_data.get(name)

    def method(self) -> str:
        return self.http_method

    def path(self) -> str:
        return self.request_path

    def ip(self) -> str | None:
        return self.client_ip

    def json_body(self) -> dict[str, Any] | None:
        return self.body_json


@dataclass(frozen=True)
class AuthContext:
    subject: str | None
    session_id: str | None
    decision: str | None


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: dict[str, Any] | str | None = None
    headers: dict[str, str] | None = None
