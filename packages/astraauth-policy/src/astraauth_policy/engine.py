from __future__ import annotations

from astraauth_policy.parser import SchemaDefinition
from astraauth_policy.store import RelationTupleStore


class CheckEngine:
    def __init__(self, store: RelationTupleStore, schema: SchemaDefinition):
        self.store = store
        self.schema = schema

    async def check(
        self,
        *,
        tenant_id: str,
        subject_type: str,
        subject_id: str,
        relation_or_permission: str,
        object_type: str,
        object_id: str,
        depth_limit: int = 10,
        _visited: set[str] | None = None,
    ) -> bool:
        if _visited is None:
            _visited = set()

        check_key = (
            f"{subject_type}:{subject_id}#{relation_or_permission}@{object_type}:{object_id}"
        )
        if check_key in _visited:
            return False  # Circular loop detected

        if len(_visited) >= depth_limit:
            return False  # Depth limit reached

        _visited.add(check_key)

        # Look up object type in schema
        obj_def = self.schema.objects.get(object_type)
        if not obj_def:
            return False

        # Case A: It is a permission
        if relation_or_permission in obj_def.permissions:
            perm_def = obj_def.permissions[relation_or_permission]
            return await self._eval_expression(
                tenant_id=tenant_id,
                subject_type=subject_type,
                subject_id=subject_id,
                expression=perm_def.expression,
                object_type=object_type,
                object_id=object_id,
                depth_limit=depth_limit,
                _visited=_visited,
            )

        # Case B: It is a relation
        # 1. Direct tuple match
        direct_exists = await self.store.has_tuple(
            tenant_id=tenant_id,
            object_type=object_type,
            object_id=object_id,
            relation=relation_or_permission,
            subject_type=subject_type,
            subject_id=subject_id,
        )
        if direct_exists:
            return True

        # 2. Indirect match via subject sets (usersets)
        userset_tuples = await self.store.find_usersets(
            tenant_id=tenant_id,
            object_type=object_type,
            object_id=object_id,
            relation=relation_or_permission,
        )
        for t in userset_tuples:
            if t.subject_relation:
                has_relation = await self.check(
                    tenant_id=tenant_id,
                    subject_type=subject_type,
                    subject_id=subject_id,
                    relation_or_permission=t.subject_relation,
                    object_type=t.subject_type,
                    object_id=t.subject_id,
                    depth_limit=depth_limit,
                    _visited=_visited.copy(),
                )
                if has_relation:
                    return True

        return False

    async def _eval_expression(
        self,
        *,
        tenant_id: str,
        subject_type: str,
        subject_id: str,
        expression: str,
        object_type: str,
        object_id: str,
        depth_limit: int,
        _visited: set[str],
    ) -> bool:
        # Resolve operators (+ for union, & for intersection, - for exclusion)
        if " + " in expression:
            parts = [p.strip() for p in expression.split("+")]
            for part in parts:
                if await self._eval_sub_expr(
                    tenant_id,
                    subject_type,
                    subject_id,
                    part,
                    object_type,
                    object_id,
                    depth_limit,
                    _visited,
                ):
                    return True
            return False

        if " & " in expression:
            parts = [p.strip() for p in expression.split("&")]
            for part in parts:
                if not await self._eval_sub_expr(
                    tenant_id,
                    subject_type,
                    subject_id,
                    part,
                    object_type,
                    object_id,
                    depth_limit,
                    _visited,
                ):
                    return False
            return True

        if " - " in expression:
            left, right = [p.strip() for p in expression.split("-", 1)]
            val_left = await self._eval_sub_expr(
                tenant_id,
                subject_type,
                subject_id,
                left,
                object_type,
                object_id,
                depth_limit,
                _visited,
            )
            val_right = await self._eval_sub_expr(
                tenant_id,
                subject_type,
                subject_id,
                right,
                object_type,
                object_id,
                depth_limit,
                _visited,
            )
            return val_left and not val_right

        return await self._eval_sub_expr(
            tenant_id,
            subject_type,
            subject_id,
            expression,
            object_type,
            object_id,
            depth_limit,
            _visited,
        )

    async def _eval_sub_expr(
        self,
        tenant_id: str,
        subject_type: str,
        subject_id: str,
        expr: str,
        object_type: str,
        object_id: str,
        depth_limit: int,
        _visited: set[str],
    ) -> bool:
        # Check if it is a tuple-to-userset expression, e.g. "parent->view"
        if "->" in expr:
            relation, sub_relation = [p.strip() for p in expr.split("->", 1)]
            parents = await self.store.find_parents(
                tenant_id=tenant_id,
                object_type=object_type,
                object_id=object_id,
                relation=relation,
            )
            for p in parents:
                if await self.check(
                    tenant_id=tenant_id,
                    subject_type=subject_type,
                    subject_id=subject_id,
                    relation_or_permission=sub_relation,
                    object_type=p.subject_type,
                    object_id=p.subject_id,
                    depth_limit=depth_limit,
                    _visited=_visited.copy(),
                ) or (
                    p.subject_relation
                    and await self.check(
                        tenant_id=tenant_id,
                        subject_type=subject_type,
                        subject_id=subject_id,
                        relation_or_permission=sub_relation,
                        object_type=p.subject_type,
                        object_id=p.subject_id,
                        depth_limit=depth_limit,
                        _visited=_visited.copy(),
                    )
                ):
                    return True
            return False

        return await self.check(
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
            relation_or_permission=expr,
            object_type=object_type,
            object_id=object_id,
            depth_limit=depth_limit,
            _visited=_visited.copy(),
        )
