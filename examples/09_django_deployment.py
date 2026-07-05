from __future__ import annotations

import pprint
import shutil
from pathlib import Path

from astraauth.adapters import AdapterOriginPolicy
from astraauth.core.config import AuthConfig
from astraauth.service import (
    build_service_from_home,
    initialize_config_home,
    write_initial_admin_setup,
)


def build_urlpatterns(home: Path) -> tuple[object, ...]:
    from django.conf import settings

    from astraauth.adapters import build_django_urlpatterns as build_astra_urlpatterns

    demo_admin_password = "change-me-now-local-demo-only"
    initialize_config_home(
        home=home,
        project_name="AstraAuth",
        environment="prod",
        persistence_backend="sqlite",
        persistence_base_dir=str(home / "data"),
        issuer="https://auth.example.com",
        force=True,
    )
    write_initial_admin_setup(
        home=home,
        tenant_id="tenant-1",
        username="admin",
        password=demo_admin_password,
        email="admin@example.com",
    )

    if not settings.configured:
        settings.configure(
            DEBUG=False,
            SECRET_KEY="replace-this-in-real-deployments",
            ROOT_URLCONF=__name__,
            ALLOWED_HOSTS=["*"],
            MIDDLEWARE=[],
            INSTALLED_APPS=[],
        )
        import django

        django.setup()

    config = AuthConfig.load(home=home)
    service = build_service_from_home(home=home)
    origin_policy = AdapterOriginPolicy(
        allowed_origins=frozenset({"https://app.example.com"}),
        allowed_callback_origins=frozenset({"https://app.example.com"}),
    )
    return tuple(
        build_astra_urlpatterns(
            adapter=service.adapter,
            issuer=config.issuer,
            origin_policy=origin_policy,
        )
    )


# Set global urlpatterns for Django ROOT_URLCONF lookup
home_dir = Path(".example-django-home")
shutil.rmtree(home_dir, ignore_errors=True)
try:
    urlpatterns = build_urlpatterns(home_dir)
except ImportError:
    urlpatterns = []


def main() -> None:
    if not urlpatterns:
        print("Install the Django extra first: uv sync --all-groups")
        return

    print("Django deployment urlpatterns created successfully.")

    # E2E test client execution
    from django.test import Client

    client = Client()

    print("\n[E2E] Requesting Django mounted OpenID Configuration...")
    resp = client.get("/.well-known/openid-configuration")
    print("Status Code:", resp.status_code)
    assert resp.status_code == 200

    config_data = resp.json()
    pprint.pprint(config_data)
    assert "token_endpoint" in config_data

    # Clean up
    shutil.rmtree(home_dir, ignore_errors=True)
    print("\n[E2E] Django adapter verification successful!")


if __name__ == "__main__":
    main()
