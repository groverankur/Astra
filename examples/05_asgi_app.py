from __future__ import annotations

from astraauth_adapters import create_asgi_app
from astraauth_service import build_inmemory_service


def main() -> None:
    service = build_inmemory_service(default_plugins_enabled=False)
    app = create_asgi_app(adapter=service.adapter, issuer='https://auth.local')

    print('Created ASGI app:', type(app).__name__)
    print('Routes are provided for /token, /introspect, /mfa/*, /oidc/*, and OIDC discovery endpoints.')


if __name__ == '__main__':
    main()
