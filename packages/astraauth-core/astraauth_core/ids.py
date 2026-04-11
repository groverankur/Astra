from __future__ import annotations

import sys
from typing import cast
from uuid import UUID

if sys.version_info >= (3, 14):
    from uuid import uuid7 as _uuid7
else:
    from uuid_utils import uuid7 as _uuid7


def new_uuid7() -> UUID:
    return cast(UUID, _uuid7())


def new_uuid7_str() -> str:
    return str(new_uuid7())
