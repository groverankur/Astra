from __future__ import annotations

from datetime import UTC, datetime, timedelta

from astraauth.core.oauth.models import TokenRequestContext
from astraauth.core.version import TOKEN_SCHEMA_VERSION


def build_id_token_claims(
    *,
    ctx: TokenRequestContext,
    issuer: str,
    ttl_seconds: int,
) -> dict[str, object]:
    """
    Build OIDC ID Token claims with strict rules.
    """
    now = datetime.now(tz=UTC)
    exp = now + timedelta(seconds=ttl_seconds)

    claims: dict[str, object] = {
        "iss": issuer,
        "sub": ctx.subject.subject_id,
        "aud": ctx.client.client_id,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "ver": TOKEN_SCHEMA_VERSION,
    }

    # OIDC: include nonce if present in the auth request
    if ctx.nonce:
        claims["nonce"] = ctx.nonce

    # OIDC: include auth_time if available
    if ctx.auth_time:
        claims["auth_time"] = int(ctx.auth_time.replace(tzinfo=UTC).timestamp())

    return claims
