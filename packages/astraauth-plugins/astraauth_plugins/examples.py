"""Compatibility exports for older example-plugin imports.

Use :mod:`astraauth_plugins.builtin_plugins` for release-facing imports.
"""

from astraauth_plugins.builtin_plugins import GeoPlugin as GeoPlugin
from astraauth_plugins.builtin_plugins import GeoSignalPlugin as GeoSignalPlugin
from astraauth_plugins.builtin_plugins import RiskPlugin as RiskPlugin
from astraauth_plugins.builtin_plugins import RiskSignalPlugin as RiskSignalPlugin

__all__ = ["GeoSignalPlugin", "RiskSignalPlugin", "GeoPlugin", "RiskPlugin"]
