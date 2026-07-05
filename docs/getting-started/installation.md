# Installation

Astra is distributed as a consolidated package under `astraauth` alongside three ancillary packages.

Current version: `1.0.0`

## Python Requirement

- Python `3.12+`

## Install the Main Package

To install the core library with all submodules (Yantra, Sutra, Setu, Pramaan, and Mudra):

```bash
pip install astraauth==1.0.0
```

### Extras & Optional Dependencies

You can customize your installation by choosing specific extras:

```bash
# Relational DB backends (PostgreSQL, MySQL, Redis, ZeroMQ)
pip install "astraauth[postgres,mysql,redis,zeromq]==1.0.0"

# OTP & WebAuthn support
pip install "astraauth[otp,webauthn]==1.0.0"

# Specific web framework adapters
pip install "astraauth[fastapi,flask,django,litestar,robyn]==1.0.0"

# Install everything (all database drivers, adapters, and cryptographic extras)
pip install "astraauth[otp,postgres,mysql,sql-async,redis,zeromq,webauthn,all-adapters]==1.0.0"
```

---

## Install Ancillary Packages

Depending on your requirements, you can install the optional tools separately:

### 1. Plugins Hub (`astraauth-plugins`)
Provides built-in plugins (like Geo/Risk filters) and re-exports core plugin hooks:
```bash
pip install astraauth-plugins==1.0.0
```

### 2. Operator CLI Tool (`astraauth-cli`)
Exposes the setup wizard and CLI:
```bash
pip install "astraauth-cli[interactive,tui]==1.0.0"
```

### 3. Browser Admin Panel (`astraauth-admin-ui`)
Browser administration console:
```bash
pip install astraauth-admin-ui==1.0.0
```

---

## Verify the Installation

Check the active version of the CLI utility:
```bash
astra version
```
Or verify the module entrypoint:
```bash
python -m astraauth_cli version
```

