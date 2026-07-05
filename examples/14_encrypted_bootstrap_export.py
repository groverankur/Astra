from __future__ import annotations

import json

from _support import workspace_example_home

from astraauth.service import (
    export_bootstrap_manifest,
    initialize_config_home,
    load_bootstrap_manifest,
    write_initial_admin_setup,
)


def main() -> None:
    with workspace_example_home("encrypted-bootstrap-export") as home:
        initialize_config_home(
            home=home,
            project_name="AstraAuth",
            environment="dev",
            persistence_backend="sqlite",
            persistence_base_dir=str(home / "data"),
            issuer="https://auth.local",
            force=False,
        )
        write_initial_admin_setup(
            home=home,
            tenant_id="tenant-1",
            username="admin",
            password="local-demo-password-change-before-sharing",
            email="admin@example.com",
        )

        output = home / "exports" / "bootstrap.encrypted.json"
        export_bootstrap_manifest(home=home, output_path=output)
        payload = json.loads(output.read_text(encoding="utf-8"))
        manifest = load_bootstrap_manifest(home=home)

        print(f"encrypted_export={output}")
        print(f"export_encryption={payload.get('encryption')}")
        print(f"setup_locked={manifest.setup_locked}")
        print(
            "Default bootstrap exports are encrypted; avoid --unsafe-plaintext outside throwaway demos."
        )


if __name__ == "__main__":
    main()
