# Installation

Astra ships today as a family of `astraauth-*` Python packages with a compatibility root package named `astraauth`.

Current baseline version: `0.5.1`

## Python Requirement

- Python `3.12+`

## Install The Full Workspace Package

```bash
pip install astraauth==0.5.1
```

That gives you the current integrated platform surface and the `astra` CLI.

## Install Only What You Need

```bash
pip install astraauth-core==0.5.1
pip install astraauth-service==0.5.1
pip install astraauth-cli==0.5.1
```

## Useful Extras

```bash
pip install "astraauth-core[otp,postgres,mysql,sql-async,redis,zeromq]==0.5.1"
pip install "astraauth-webauthn[webauthn]==0.5.1"
pip install "astraauth-adapters[fastapi,flask,django,asgi]==0.5.1"
pip install "astraauth-cli[tui,interactive]==0.5.1"
```

## Verify The Install

```bash
astra version
```

You can also use module entry points directly:

```bash
python -m astraauth_cli version
```

## What Gets Installed

- `astraauth-core`: Astra Yantra
- `astraauth-service`: Astra Sutra
- `astraauth-adapters`: Astra Setu
- `astraauth-plugins`: Astra Tantra
- `astraauth-idp`: Astra Pramaan
- `astraauth-webauthn`: Astra Mudra
- `astraauth-cli`: Astra Dwaar

## Coming Next Release

- `astraauth-admin-ui`: Astra Netra

## Deferred Packages Not Installed

These are documented future modules only. They are not part of the current workspace and should not be installed yet:

- `astraauth-policy`
- `astraauth-tenancy`
- `astraauth-observability`
- `@astraauth/sdk-js`
- `@astraauth/sdk-react`

