# mypy: disable-error-code="import-not-found"
from __future__ import annotations

import pytest
from astraauth_service import build_inmemory_service


def test_build_django_urlpatterns_exposes_runtime_routes() -> None:
    django = pytest.importorskip("django")
    _ = django

    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DEBUG=True,
            SECRET_KEY="test-secret",
            ROOT_URLCONF=__name__,
            ALLOWED_HOSTS=["testserver", "localhost"],
            MIDDLEWARE=[],
            INSTALLED_APPS=[],
        )
        import django as django_module

        django_module.setup()

    from astraauth_adapters.django.wiring import build_urlpatterns
    from django.test import Client, override_settings

    service = build_inmemory_service(default_plugins_enabled=False)
    urlpatterns = build_urlpatterns(adapter=service.adapter, issuer="https://auth.example.com")

    with override_settings(ROOT_URLCONF=type("URLConf", (), {"urlpatterns": urlpatterns})):
        client = Client()
        jwks = client.get("/.well-known/jwks.json")
        config = client.get("/.well-known/openid-configuration")

    assert jwks.status_code == 200
    assert "keys" in jwks.json()
    assert config.status_code == 200
    assert config.json()["issuer"] == "https://auth.example.com"
