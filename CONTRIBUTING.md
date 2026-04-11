# Contributing to Astra

Thanks for contributing. Astra is a package-first Python platform, so changes should keep package boundaries, public docs, tests, and release readiness in sync.

## Before You Start

- Use Python `3.12+`
- Prefer `uv` for environment and workspace commands
- Read:
  - [`README.md`](README.md)
  - [`docs/index.md`](docs/index.md)
  - [`docs/about/package-summary.md`](docs/about/package-summary.md)
  - [`docs/about/status.md`](docs/about/status.md)

## Local Setup

```bash
uv sync --all-groups
uv run ruff check .
uv run python -m mypy packages
uv run pytest -q packages
uv run mkdocs build --strict
```

## Contribution Expectations

- Keep technical package names and imports under the existing `astraauth-*` / `astraauth_*` namespace unless a migration is explicitly planned.
- Keep public branding and docs aligned with the Astra naming map.
- Add or update tests for behavioral changes.
- Update docs when runtime behavior, package metadata, CLI commands, or operator workflows change.
- Do not create reserved future packages as empty scaffolds unless the feature scope is being actively implemented.

## Coding Standards

- Ruff, mypy, and pytest should pass on the changed surface at minimum.
- Prefer the existing repository patterns:
  - driver-first repositories for persistence
  - framework-agnostic logic in `astraauth-core`
  - runtime composition in `astraauth-service`
  - operator surfaces in `astraauth-cli` and `astraauth-admin-ui`
- Preserve backward-compatible Python imports and public runtime commands when possible.

## Release-Oriented Changes

If your change affects packaging or public behavior, also review:

- [`CHANGELOG.md`](CHANGELOG.md)
- [`docs/PUBLISHING.md`](docs/PUBLISHING.md)
- [`docs/VERSIONING.md`](docs/VERSIONING.md)
- [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md)

## Security-Sensitive Changes

For security-sensitive issues, do not open a public issue first. Follow [`SECURITY.md`](SECURITY.md).
