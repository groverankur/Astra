from __future__ import annotations

import shutil
import sys
from collections.abc import Generator
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[1] / "packages"
if ROOT.exists():
    for package_dir in ROOT.iterdir():
        if package_dir.is_dir():
            src_dir = package_dir / "src"
            mod_name = package_dir.name.replace("-", "_")
            if (src_dir / mod_name).exists():
                sys.path.insert(0, str(src_dir))
            elif (package_dir / mod_name).exists():
                sys.path.insert(0, str(package_dir))


@pytest.fixture
def workspace_tmp_path() -> Generator[Path]:
    path = Path(".tmp") / "test-artifacts" / str(uuid4())
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
