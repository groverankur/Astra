#!/usr/bin/env python3
"""Generate the code reference pages and navigation."""

import logging
from pathlib import Path

log = logging.getLogger(__name__)

src = Path(__file__).parent.parent / "packages"
docs = Path(__file__).parent


def get_packages() -> list[str]:
    """Get all packages in the astraauth namespace."""
    packages = []
    if src.exists():
        for item in src.iterdir():
            if (
                item.is_dir()
                and item.name.startswith("astraauth-")
                and (item / "pyproject.toml").exists()
            ):
                # Extract package name (remove astraauth- prefix)
                package_name = item.name.replace("astraauth-", "")
                packages.append(package_name)
    return packages


def generate_api_pages() -> None:
    """Generate API reference pages."""
    packages = get_packages()

    for package in packages:
        package_path = docs / "api" / f"{package}.md"
        package_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert package name to module name (admin-ui -> admin_ui)
        module_name = package.replace("-", "_")

        content = f"""# {package.replace("-", " ").title()} API Reference

::: astraauth_{module_name}
    options:
      show_root_heading: true
      show_root_toc_entry: false
      inherited_members: true
"""

        package_path.write_text(content)
        log.info(f"Generated API page for {package}")


def update_nav() -> None:
    """Update the navigation in the Zensical config."""
    # This would update the nav section, but for now we'll keep it static
    pass


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    generate_api_pages()
    update_nav()
