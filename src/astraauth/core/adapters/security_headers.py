from __future__ import annotations

from astraauth.core.adapters.http_types import HttpResponse


def apply_runtime_security_headers(
    response: HttpResponse,
    *,
    allow_caching: bool = False,
) -> HttpResponse:
    headers = dict(response.headers or {})
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("Referrer-Policy", "no-referrer")
    headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    headers.setdefault(
        "Content-Security-Policy",
        ("default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    )
    if not allow_caching:
        headers.setdefault("Cache-Control", "no-store")
        headers.setdefault("Pragma", "no-cache")
        headers.setdefault("Expires", "0")
    return HttpResponse(status=response.status, body=response.body, headers=headers)
