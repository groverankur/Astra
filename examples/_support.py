from __future__ import annotations

import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def workspace_example_home(name: str) -> Iterator[Path]:
    root = Path.cwd() / '.example-workspaces'
    home = root / name
    shutil.rmtree(home, ignore_errors=True)
    home.mkdir(parents=True, exist_ok=True)
    try:
        yield home
    finally:
        shutil.rmtree(home, ignore_errors=True)
