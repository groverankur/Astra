from __future__ import annotations

import re

from pydantic import BaseModel, Field


class RelationDefinition(BaseModel):
    name: str
    allowed_types: list[str]


class PermissionDefinition(BaseModel):
    name: str
    expression: str


class ObjectDefinition(BaseModel):
    name: str
    relations: dict[str, RelationDefinition] = Field(default_factory=dict)
    permissions: dict[str, PermissionDefinition] = Field(default_factory=dict)


class SchemaDefinition(BaseModel):
    objects: dict[str, ObjectDefinition] = Field(default_factory=dict)


class SchemaParser:
    @staticmethod
    def parse(dsl: str) -> SchemaDefinition:
        # Normalize whitespace and strip comments
        lines = []
        for line in dsl.splitlines():
            line = re.sub(r"#.*$", "", line).strip()
            if line:
                lines.append(line)

        normalized = "\n".join(lines)

        # Match definitions: definition <name> { <content> }
        matches = re.finditer(r"\bdefinition\s+(\w+)\s*\{([^}]*)\}", normalized)

        objects = {}
        for match in matches:
            obj_name = match.group(1)
            content = match.group(2).strip()

            relations = {}
            permissions = {}

            # Split items by semicolon or spaces
            items = [item.strip() for item in re.split(r"[;\n]", content) if item.strip()]
            for item in items:
                # Parse relation: relation <name>: <allowed_types>
                rel_match = re.match(r"^relation\s+(\w+)\s*:\s*(.+)$", item)
                if rel_match:
                    rel_name = rel_match.group(1)
                    allowed_str = rel_match.group(2)
                    allowed_types = [
                        t.strip() for t in re.split(r"[|,\s]+", allowed_str) if t.strip()
                    ]
                    relations[rel_name] = RelationDefinition(
                        name=rel_name, allowed_types=allowed_types
                    )
                    continue

                # Parse permission: permission <name> = <expression>
                perm_match = re.match(r"^permission\s+(\w+)\s*=\s*(.+)$", item)
                if perm_match:
                    perm_name = perm_match.group(1)
                    expression = perm_match.group(2).strip()
                    permissions[perm_name] = PermissionDefinition(
                        name=perm_name, expression=expression
                    )
                    continue

                raise ValueError(f"Invalid syntax in definition '{obj_name}': {item}")

            objects[obj_name] = ObjectDefinition(
                name=obj_name, relations=relations, permissions=permissions
            )

        schema = SchemaDefinition(objects=objects)
        SchemaParser.validate(schema)
        return schema

    @staticmethod
    def validate(schema: SchemaDefinition) -> None:
        for obj_name, obj in schema.objects.items():
            # Verify relations reference valid object types
            for rel_name, rel in obj.relations.items():
                for allowed in rel.allowed_types:
                    if allowed not in schema.objects and allowed != "user":
                        # Support user as default subject type
                        pass
                    elif allowed not in schema.objects:
                        raise ValueError(
                            f"Relation '{obj_name}.{rel_name}' references undefined type '{allowed}'"
                        )
