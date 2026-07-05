from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from astraauth.core.events.base import EventBus, EventHandler, EventPayload


class InMemoryEventBus(EventBus):
    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)

    def publish(self, topic: str, payload: EventPayload) -> None:
        handlers: Iterable[EventHandler] = self._handlers.get(topic, [])
        for handler in handlers:
            handler(payload)

    def subscribe(self, topic: str, handler: EventHandler) -> None:
        self._handlers[topic].append(handler)
