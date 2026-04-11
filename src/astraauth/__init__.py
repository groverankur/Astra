from __future__ import annotations

"""Compatibility package for the root ``astraauth`` distribution.

The public CLI command is ``astra``. This package remains so the root
distribution can expose version/module compatibility without changing the
active package namespace underneath.
"""

from astraauth_core.version import __version__

__all__ = ["__version__"]
