from __future__ import annotations

import asyncio

from astraauth_policy import CheckEngine, RelationTuple, RelationTupleStore, SchemaParser
from astraauth_tenancy import get_current_tenant, reset_current_tenant, set_current_tenant


async def run_example() -> None:
    print("=== Astra ReBAC & Tenancy Example ===")

    # 1. Bind and retrieve active tenancy contexts
    token = set_current_tenant("tenant-100")
    print(f"Current tenant bound in request context: {get_current_tenant()}")

    # 2. Compile a Zanzibar-style schema DSL
    dsl = """
    definition user {}

    definition document {
        relation reader: user
        relation owner: user
        permission view = reader + owner
    }
    """
    schema = SchemaParser.parse(dsl)
    print("Successfully compiled Zanzibar schema definitions.")

    # 3. Persist relation tuples
    store = RelationTupleStore()
    await store.add_tuple(
        RelationTuple(
            id="t-1",
            tenant_id="tenant-100",
            object_type="document",
            object_id="doc-123",
            relation="reader",
            subject_type="user",
            subject_id="alice",
        )
    )
    print("Added relationship fact: (user:alice is reader of document:doc-123)")

    # 4. Initialize solver engine and evaluate checks
    engine = CheckEngine(store, schema)

    print("\nEvaluating checks against graph...")
    is_allowed = await engine.check(
        tenant_id="tenant-100",
        subject_type="user",
        subject_id="alice",
        relation_or_permission="view",
        object_type="document",
        object_id="doc-123",
    )
    print(
        f"Is user:alice allowed to view document:doc-123? {'ALLOWED' if is_allowed else 'DENIED'}"
    )
    assert is_allowed is True

    is_denied = await engine.check(
        tenant_id="tenant-100",
        subject_type="user",
        subject_id="bob",
        relation_or_permission="view",
        object_type="document",
        object_id="doc-123",
    )
    print(f"Is user:bob allowed to view document:doc-123? {'ALLOWED' if is_denied else 'DENIED'}")
    assert is_denied is False

    # 5. Clean context
    reset_current_tenant(token)
    print("\nExample executed successfully!")


if __name__ == "__main__":
    asyncio.run(run_example())
