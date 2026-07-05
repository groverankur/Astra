from __future__ import annotations

import json
import pprint
import threading
import time

from astraauth.core.events.zeromq_pubsub import ZeroMQPubSubEventBus


def main() -> None:
    try:
        import zmq
    except ImportError:
        print("Install PyZMQ first: pip install pyzmq or uv sync --all-groups")
        return

    endpoint = "tcp://127.0.0.1:5556"
    print(f"Setting up ZeroMQ Event Bus on {endpoint}...")

    # 1. Start an asynchronous subscriber in a background thread
    received_events: list[tuple[str, dict]] = []
    subscriber_running = threading.Event()
    subscriber_running.set()

    def run_subscriber() -> None:
        context = zmq.Context.instance()
        socket = context.socket(zmq.SUB)

        # Connect subscriber to the publisher endpoint
        socket.connect(endpoint)

        # Subscribe to all topics (empty prefix matches everything)
        socket.setsockopt(zmq.SUBSCRIBE, b"")

        # Use a poller to receive messages with a timeout, allowing graceful exit
        poller = zmq.Poller()
        poller.register(socket, zmq.POLLIN)

        print("[Subscriber] Connected and waiting for pub/sub signals...")
        while subscriber_running.is_set():
            socks = dict(poller.poll(timeout=200))
            if socket in socks:
                try:
                    topic_bin, payload_bin = socket.recv_multipart()
                    topic = topic_bin.decode("utf-8")
                    payload = json.loads(payload_bin.decode("utf-8"))

                    print(f"\n[Subscriber Received] Topic: '{topic}'")
                    print("Payload:")
                    pprint.pprint(payload)
                    received_events.append((topic, payload))
                except Exception as e:
                    print("Subscriber Receive Error:", e)

    sub_thread = threading.Thread(target=run_subscriber, daemon=True)
    sub_thread.start()

    # Allow subscriber socket to establish connection
    time.sleep(0.5)

    # 2. Create the ZeroMQ publisher
    # This wraps PyZMQ and binds to the specified port
    publisher = ZeroMQPubSubEventBus(endpoint=endpoint, bind=True)
    print("[Publisher] Bound and publishing events.")

    # 3. Publish typical AstraAuth audit/event payloads
    print("\n[Publisher] Publishing 'auth.login_success' event...")
    publisher.publish(
        topic="auth.login_success",
        payload={
            "event_id": "evt-101",
            "timestamp": time.time(),
            "tenant_id": "tenant-1",
            "subject_id": "user-456",
            "username": "alice",
            "client_id": "client-app",
        },
    )

    time.sleep(0.2)

    print("\n[Publisher] Publishing 'mfa.challenge_triggered' event...")
    publisher.publish(
        topic="mfa.challenge_triggered",
        payload={
            "event_id": "evt-102",
            "timestamp": time.time(),
            "tenant_id": "tenant-1",
            "subject_id": "user-456",
            "factor_type": "totp",
            "challenge_id": "chal-789",
        },
    )

    # Wait for background thread to consume the messages
    time.sleep(0.5)

    # 4. Clean shutdown
    subscriber_running.clear()
    sub_thread.join(timeout=1.0)
    print("\n[E2E] ZeroMQ Event Bus verification complete!")
    print(f"Total events verified: {len(received_events)}")


if __name__ == "__main__":
    main()
