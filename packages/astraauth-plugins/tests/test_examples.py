import pytest
from astraauth_plugins import GeoPlugin, RiskPlugin


def test_geo_plugin_blocks_configured_country() -> None:
    plugin = GeoPlugin(blocked_countries=("CN",))
    with pytest.raises(ValueError):
        plugin.hooks()["auth.pre_authenticate"]({"country": "cn"})


def test_risk_plugin_enforces_threshold() -> None:
    plugin = RiskPlugin(max_risk_score=50)
    with pytest.raises(ValueError):
        plugin.hooks()["auth.pre_authorize"]({"risk_score": 90})
