from __future__ import annotations

import json
from typing import Any, Protocol

from astraauth_core.events.base import EventBus, EventHandler, EventPayload


class RedisPublisher(Protocol):
    def publish(self, channel: str, message: str) -> Any: ...


class RedisPubSubEventBus(EventBus):
    """
    Publish-only Redis event bus.

    Subscription is expected to be handled by an external worker/process that
    consumes Redis pub/sub and dispatches handlers.
    """

    def __init__(self, client: RedisPublisher, *, channel_prefix: str = "astraauth:events:") -> None:
        self._client = client
        self._prefix = channel_prefix

    def publish(self, topic: str, payload: EventPayload) -> None:
        channel = f"{self._prefix}{topic}"
        self._client.publish(channel, json.dumps(payload))

    def subscribe(self, topic: str, handler: EventHandler) -> None:
        _ = topic
        _ = handler
        raise NotImplementedError("RedisPubSubEventBus subscription is handled externally")
