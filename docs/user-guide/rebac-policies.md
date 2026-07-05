# ReBAC Access Policies (Astra Niyam)

Astra offers relationship-based access control (ReBAC) inspired by Google's Zanzibar database model and KeyNetra's schema architecture. It evaluates permissions transitively by resolving relationships across nodes.

## Zanzibar-style Schema DSL

ReBAC schemas are defined using a structured DSL:

```
definition user {}

definition document {
    relation reader: user
    relation editor: user
    relation parent: folder

    permission view = reader + editor + parent->view
    permission edit = editor
}

definition folder {
    relation owner: user
    relation viewer: user

    permission view = owner + viewer
}
```

### Supported Operators
- `+` (Union): The permission is granted if any of the relations/sub-expressions are satisfied.
- `&` (Intersection): The permission is granted if all of the relations/sub-expressions are satisfied.
- `-` (Exclusion): The permission is granted if the left relation is satisfied and the right is not.
- `->` (Tuple-to-Userset): Dynamically walks relationships. For example, `parent->view` means the caller has permission if they have `view` permission on the parent object.

## Evaluation Check Engine

To evaluate checks, initialize the `CheckEngine` with the relation tuples store and the compiled schema:

```python
from astraauth_policy import SchemaParser, RelationTupleStore, RelationTuple, CheckEngine

# 1. Parse Schema
schema = SchemaParser.parse(schema_dsl)

# 2. Add Relation Facts
store = RelationTupleStore()
await store.add_tuple(
    RelationTuple(
        id="t-1",
        tenant_id="tenant-1",
        object_type="document",
        object_id="doc-123",
        relation="reader",
        subject_type="user",
        subject_id="alice",
    )
)

# 3. Solve Queries
engine = CheckEngine(store, schema)
allowed = await engine.check(
    tenant_id="tenant-1",
    subject_type="user",
    subject_id="alice",
    relation_or_permission="view",
    object_type="document",
    object_id="doc-123",
)
```

## Loop Protection and Depth Limits
The evaluation solver has built-in circular graph loop detection and depth limit boundaries (defaulting to 10 nested evaluations) to prevent infinite loops.
