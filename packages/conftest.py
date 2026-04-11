from __future__ import annotations

import shutil
import sys
from collections.abc import Generator
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parent
for package_dir in ROOT.iterdir():
    if package_dir.is_dir() and (package_dir / package_dir.name.replace("-", "_")).exists():
        sys.path.insert(0, str(package_dir))


@pytest.fixture
def workspace_tmp_path() -> Generator[Path]:
    path = Path(".tmp") / "test-artifacts" / str(uuid4())
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
