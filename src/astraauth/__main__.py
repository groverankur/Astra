from __future__ import annotations

"""Compatibility ``python -m astraauth`` entrypoint."""

from astraauth_cli.__main__ import main as cli_main


def main() -> int | None:
    return cli_main()

if __name__ == "__main__":
    raise SystemExit(main())
