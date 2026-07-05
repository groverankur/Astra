#!/usr/bin/env python3
"""Serve the Zensical documentation site locally."""

import subprocess
import sys
from pathlib import Path


def serve_docs() -> None:
    """Serve the documentation site locally."""
    project_root = Path(__file__).parent

    try:
        # Use uv to run the native Zensical dev server.
        cmd = ["uv", "run", "zensical", "serve"]
        print("Starting Zensical development server...")
        print("Documentation will be available at: http://localhost:8000")
        print("Press Ctrl+C to stop the server")

        subprocess.run(cmd, cwd=project_root, check=True)

    except subprocess.CalledProcessError as e:
        print(f"Error starting Zensical server: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping Zensical server...")
        sys.exit(0)


if __name__ == "__main__":
    serve_docs()
