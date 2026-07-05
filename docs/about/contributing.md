# Contributing

For contribution workflow and quality expectations, see the repository root
`CONTRIBUTING.md` file in the GitHub repository.

Highlights:

- use Python `3.12+`
- prefer `uv`
- keep package boundaries and public docs in sync
- run `ruff`, `ty check`, `pytest`, and `zensical build --strict` for release-facing changes
- repo-level `ty` config treats migration-heavy diagnostics as warnings until the repo finishes the checker transition
- update [zensical.toml](../../zensical.toml) when docs navigation or theme settings change
