from __future__ import annotations

import pytest
from astraauth_policy import (
    CheckEngine,
    RelationTuple,
    RelationTupleStore,
    SchemaParser,
)


@pytest.mark.asyncio
async def test_schema_parsing_and_evaluation() -> None:
    # 1. Define Zanzibar-style Schema DSL
    dsl = """
    definition user {}

    definition document {
        relation viewer: user
        relation editor: user
        relation parent: folder

        permission view = viewer + editor + parent->view
        permission edit = editor
    }

    definition folder {
        relation owner: user
        relation viewer: user

        permission view = owner + viewer
    }
    """

    schema = SchemaParser.parse(dsl)
    assert "document" in schema.objects
    assert "folder" in schema.objects

    # Check relations and permissions structure
    doc = schema.objects["document"]
    assert "viewer" in doc.relations
    assert "parent" in doc.relations
    assert "view" in doc.permissions

    # 2. Setup relation tuple store and solver engine
    store = RelationTupleStore()
    engine = CheckEngine(store, schema)

    # 3. Create mock relationship facts
    # user:alice is editor of document:1
    # folder:sub is parent of document:1
    # user:bob is owner of folder:sub
    await store.add_tuple(
        RelationTuple(
            id="t1",
            tenant_id="tenant-1",
            object_type="document",
            object_id="1",
            relation="editor",
            subject_type="user",
            subject_id="alice",
        )
    )
    await store.add_tuple(
        RelationTuple(
            id="t2",
            tenant_id="tenant-1",
            object_type="document",
            object_id="1",
            relation="parent",
            subject_type="folder",
            subject_id="sub",
        )
    )
    await store.add_tuple(
        RelationTuple(
            id="t3",
            tenant_id="tenant-1",
            object_type="folder",
            object_id="sub",
            relation="owner",
            subject_type="user",
            subject_id="bob",
        )
    )

    # 4. Perform check evaluations
    # user:alice is editor => should have edit and view permissions
    assert (
        await engine.check(
            tenant_id="tenant-1",
            subject_type="user",
            subject_id="alice",
            relation_or_permission="edit",
            object_type="document",
            object_id="1",
        )
        is True
    )

    assert (
        await engine.check(
            tenant_id="tenant-1",
            subject_type="user",
            subject_id="alice",
            relation_or_permission="view",
            object_type="document",
            object_id="1",
        )
        is True
    )

    # user:bob is owner of parent folder => should inherit view on document:1
    assert (
        await engine.check(
            tenant_id="tenant-1",
            subject_type="user",
            subject_id="bob",
            relation_or_permission="view",
            object_type="document",
            object_id="1",
        )
        is True
    )

    # user:charlie is an outsider => should be denied
    assert (
        await engine.check(
            tenant_id="tenant-1",
            subject_type="user",
            subject_id="charlie",
            relation_or_permission="view",
            object_type="document",
            object_id="1",
        )
        is False
    )


@pytest.mark.asyncio
async def test_circular_dependency_loop_detection() -> None:
    # Set up circular loop: doc:1 parent is folder:sub, folder:sub parent is doc:1
    dsl = """
    definition document {
        relation parent: document
        permission view = parent->view
    }
    """
    schema = SchemaParser.parse(dsl)
    store = RelationTupleStore()
    engine = CheckEngine(store, schema)

    await store.add_tuple(
        RelationTuple(
            id="loop-1",
            tenant_id="tenant-1",
            object_type="document",
            object_id="1",
            relation="parent",
            subject_type="document",
            subject_id="1",
        )
    )

    # Evaluation should not enter infinite recursion, and should return False
    assert (
        await engine.check(
            tenant_id="tenant-1",
            subject_type="user",
            subject_id="alice",
            relation_or_permission="view",
            object_type="document",
            object_id="1",
        )
        is False
    )
