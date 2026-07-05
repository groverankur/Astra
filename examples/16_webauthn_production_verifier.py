from __future__ import annotations

from astraauth.service import build_inmemory_service
from astraauth.webauthn import build_default_webauthn_verifier


def main() -> None:
    verifier = build_default_webauthn_verifier()
    service = build_inmemory_service(
        default_plugins_enabled=False,
        webauthn_verifier=verifier,
    )

    print(f"webauthn_verifier={type(verifier).__name__}")
    print(f"service={type(service).__name__}")
    print(
        "Finish WebAuthn ceremonies with credential_response/authentication_response, expected_origin, and rp_id."
    )
    print("Use LocalDevelopmentWebAuthnVerifier only for explicit local development tests.")


if __name__ == "__main__":
    main()
