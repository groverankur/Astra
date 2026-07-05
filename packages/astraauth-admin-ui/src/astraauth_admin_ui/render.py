from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

PACKAGE_ROOT = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_ROOT / "templates"
STATIC_DIR = PACKAGE_ROOT / "static"


def create_templates() -> Jinja2Templates:
    return Jinja2Templates(directory=str(TEMPLATES_DIR))
