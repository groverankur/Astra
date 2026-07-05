from __future__ import annotations

from pydantic import BaseModel


class RelationTuple(BaseModel):
    id: str
    tenant_id: str
    object_type: str
    object_id: str
    relation: str
    subject_type: str
    subject_id: str
    subject_relation: str | None = None


class RelationTupleStore:
    def __init__(self) -> None:
        self.tuples: list[RelationTuple] = []

    async def add_tuple(self, rtuple: RelationTuple) -> None:
        self.tuples.append(rtuple)

    async def delete_tuple(
        self,
        tenant_id: str,
        object_type: str,
        object_id: str,
        relation: str,
        subject_type: str,
        subject_id: str,
    ) -> None:
        self.tuples = [
            t
            for t in self.tuples
            if not (
                t.tenant_id == tenant_id
                and t.object_type == object_type
                and t.object_id == object_id
                and t.relation == relation
                and t.subject_type == subject_type
                and t.subject_id == subject_id
            )
        ]

    async def has_tuple(
        self,
        tenant_id: str,
        object_type: str,
        object_id: str,
        relation: str,
        subject_type: str,
        subject_id: str,
    ) -> bool:
        for t in self.tuples:
            if (
                t.tenant_id == tenant_id
                and t.object_type == object_type
                and t.object_id == object_id
                and t.relation == relation
                and t.subject_type == subject_type
                and t.subject_id == subject_id
                and t.subject_relation is None
            ):
                return True
        return False

    async def find_usersets(
        self,
        tenant_id: str,
        object_type: str,
        object_id: str,
        relation: str,
    ) -> list[RelationTuple]:
        return [
            t
            for t in self.tuples
            if (
                t.tenant_id == tenant_id
                and t.object_type == object_type
                and t.object_id == object_id
                and t.relation == relation
                and t.subject_relation is not None
            )
        ]

    async def find_parents(
        self,
        tenant_id: str,
        object_type: str,
        object_id: str,
        relation: str,
    ) -> list[RelationTuple]:
        return [
            t
            for t in self.tuples
            if (
                t.tenant_id == tenant_id
                and t.object_type == object_type
                and t.object_id == object_id
                and t.relation == relation
            )
        ]
