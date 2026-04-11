from __future__ import annotations

import json

from astraauth_core.events.base import EventBus, EventHandler, EventPayload


class ZeroMQPubSubEventBus(EventBus):
    """
    Publish-only ZeroMQ event bus.

    Subscription is expected to be handled by dedicated subscriber processes
    using ZeroMQ SUB sockets.
    """

    def __init__(
        self,
        *,
        endpoint: str = "tcp://127.0.0.1:5556",
        bind: bool = True,
    ) -> None:
        try:
            import zmq
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError(
                "ZeroMQ support requires optional dependency 'pyzmq'. "
                "Install astraauth-core[zeromq]."
            ) from exc

        self._endpoint = endpoint
        self._context = zmq.Context.instance()
        self._socket = self._context.socket(zmq.PUB)

        if bind:
            self._socket.bind(endpoint)
        else:
            self._socket.connect(endpoint)

    def publish(self, topic: str, payload: EventPayload) -> None:
        body = json.dumps(payload)
        self._socket.send_multipart([topic.encode("utf-8"), body.encode("utf-8")])

    def subscribe(self, topic: str, handler: EventHandler) -> None:
        _ = topic
        _ = handler
        raise NotImplementedError("ZeroMQPubSubEventBus subscription is handled externally")
