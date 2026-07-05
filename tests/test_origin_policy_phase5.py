from astraauth.adapters.origin import (
    AdapterOriginPolicy,
    apply_origin_headers,
    preflight_response,
    reject_disallowed_origin,
)
from astraauth.core.adapters.http_types import HttpResponse, NormalizedRequestContext


def _request(
    *,
    method: str = "POST",
    path: str = "/token",
    origin: str = "https://evil.example.com",
) -> NormalizedRequestContext:
    return NormalizedRequestContext(
        http_method=method,
        request_path=path,
        query_params={},
        headers={"origin": origin, "access-control-request-method": method},
    )


def test_origin_policy_rejects_state_changing_requests_outside_allowlist() -> None:
    policy = AdapterOriginPolicy(allowed_origins=frozenset({"https://app.example.com"}))

    rejected = reject_disallowed_origin(_request(), policy=policy)
    allowed = reject_disallowed_origin(_request(origin="https://app.example.com"), policy=policy)

    assert rejected is not None
    assert rejected.status == 403
    assert allowed is None


def test_origin_policy_uses_callback_allowlist_for_oidc_callback() -> None:
    policy = AdapterOriginPolicy(
        allowed_origins=frozenset({"https://app.example.com"}),
        allowed_callback_origins=frozenset({"https://callback.example.com"}),
    )
    req = _request(path="/oidc/callback", origin="https://callback.example.com")

    response = apply_origin_headers(req, HttpResponse(status=200), policy=policy)

    assert response.headers is not None
    assert response.headers["Access-Control-Allow-Origin"] == "https://callback.example.com"


def test_origin_policy_preflight_returns_cors_headers_for_allowed_origin() -> None:
    policy = AdapterOriginPolicy(allowed_origins=frozenset({"https://app.example.com"}))

    response = preflight_response(_request(origin="https://app.example.com"), policy=policy)

    assert response.status == 204
    assert response.headers is not None
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
