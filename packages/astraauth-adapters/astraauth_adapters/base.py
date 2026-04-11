from __future__ import annotations

from typing import Protocol

from astraauth_core.adapters.base import OAuthAdapter


class FrameworkOAuthMount(Protocol):
    def mount_oauth(self, adapter: OAuthAdapter) -> None: ...
