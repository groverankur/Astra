# mypy: disable-error-code="import-not-found"
from __future__ import annotations

from pathlib import Path

from astraauth_core.config import AuthConfig
from astraauth_service import (
    build_service_from_home,
    initialize_config_home,
    write_initial_admin_setup,
)


def main() -> None:
    try:
        from django.conf import settings
    except ImportError:
        print("Install the Django extra first: uv sync --extra django")
        return

    from astraauth_adapters import build_django_urlpatterns

    home = Path(".astraauth")
    if not (home / "config.json").exists():
        initialize_config_home(
            home=home,
            project_name="AstraAuth",
            environment="prod",
            persistence_backend="sqlite",
            persistence_base_dir=str(home / "data"),
            issuer="https://auth.example.com",
            force=False,
        )
        write_initial_admin_setup(
            home=home,
            tenant_id="tenant-1",
            username="admin",
            password="change-me-now",
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
    urlpatterns = build_django_urlpatterns(adapter=service.adapter, issuer=config.issuer)

    print("Django deployment urlpatterns created")
    print(f"config_home={home}")
    print(f"issuer={config.issuer}")
    print(f"urlpattern_count={len(urlpatterns)}")
    print("Include these urlpatterns in your project URLConf after installing Django.")


if __name__ == "__main__":
    main()
