from __future__ import annotations

from astraauth_adapters import mount_oauth_flask
from astraauth_service import build_inmemory_service


def main() -> None:
    try:
        from flask import Flask
    except ImportError:
        print('Install the Flask extra first: uv sync --extra flask')
        return

    service = build_inmemory_service(default_plugins_enabled=False)
    app = Flask(__name__)
    mount_oauth_flask(app, service.adapter, issuer='https://auth.local')

    print('Created Flask app:', app.name)
    print('Mounted AstraAuth routes into Flask. Try /.well-known/openid-configuration in a test client.')


if __name__ == '__main__':
    main()
