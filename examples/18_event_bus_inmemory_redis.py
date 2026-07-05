from __future__ import annotations

import pprint
import time

from astraauth.core.events.inmemory import InMemoryEventBus


def main() -> None:
    print("=== InMemoryEventBus Example ===")

    # 1. Initialize the in-memory event bus
    inmemory_bus = InMemoryEventBus()

    # 2. Declare a local handler callback
    def handle_auth_event(payload: dict) -> None:
        print("\n[InMemory Handler Callback] Received Event:")
        pprint.pprint(payload)

    # 3. Register the handler on a topic
    inmemory_bus.subscribe("auth.success", handle_auth_event)

    # 4. Publish an event (this invokes the callback synchronously)
    print("Publishing 'auth.success' event...")
    inmemory_bus.publish(
        topic="auth.success",
        payload={
            "event_id": "evt-201",
            "timestamp": time.time(),
            "username": "bob",
            "status": "authorized",
        },
    )

    print("\n=== RedisPubSubEventBus Integration ===")
    print("AstraAuth also provides `RedisPubSubEventBus` (requiring `redis` extra).")
    print("Setup syntax:")
    print("  from astraauth.core.events.redis_pubsub import RedisPubSubEventBus")
    print("  publisher = RedisPubSubEventBus(host='localhost', port=6379, db=0)")
    print("  publisher.publish('auth.events', {'status': 'active'})")
    print("\nLike ZeroMQ, subscription is expected to be handled by dedicated subscriber workers.")


if __name__ == "__main__":
    main()
