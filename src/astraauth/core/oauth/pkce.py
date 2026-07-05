import base64
import hashlib
import secrets
from typing import Literal

CodeChallengeMethod = Literal["S256"]


def generate_code_verifier(length: int = 64) -> str:
    """
    Generate a high-entropy code_verifier per RFC 7636.
    Uses URL-safe characters without padding.
    """
    if not (43 <= length <= 128):
        raise ValueError("code_verifier length must be between 43 and 128")

    # token_urlsafe returns ~1.3 chars per byte; trim to exact length
    verifier = secrets.token_urlsafe(length)
    return verifier[:length]


def _base64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def compute_code_challenge(verifier: str, method: CodeChallengeMethod = "S256") -> str:
    """
    Compute code_challenge from code_verifier using S256 (OAuth 2.1 only).
    """
    if method != "S256":
        raise ValueError("Only S256 is supported in OAuth 2.1")

    if not verifier:
        raise ValueError("code_verifier must not be empty")

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _base64url_nopad(digest)


def verify_pkce(
    *,
    code_verifier: str,
    code_challenge: str,
    code_challenge_method: CodeChallengeMethod = "S256",
) -> bool:
    """
    Verify that code_verifier matches the stored code_challenge.
    Constant-time comparison is used to avoid timing leaks.
    """
    if code_challenge_method != "S256":
        return False

    try:
        expected = compute_code_challenge(code_verifier, "S256")
    except Exception:
        return False

    # Constant-time compare
    return secrets.compare_digest(expected, code_challenge)
