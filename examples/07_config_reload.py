from __future__ import annotations

from _support import workspace_example_home
from astraauth_core.config import AuthConfig
from astraauth_service import load_auth_config, refresh_service_from_home


def main() -> None:
    with workspace_example_home('config-reload') as home:
        config = AuthConfig.for_project(
            project_name='AstraAuth',
            environment='dev',
            persistence_backend='sqlite',
            persistence_base_dir=str(home / 'data'),
            issuer='https://initial.local',
        )
        config.save_json(home=home, encrypt_values=False)
        print('initial issuer:', load_auth_config(home=home).issuer)

        AuthConfig.update_json_path('issuer', 'https://updated.local', home=home, encrypt_values=False)
        refreshed = refresh_service_from_home(current_config=config, home=home)
        print('reloaded issuer:', refreshed.token_manager._config.issuer)


if __name__ == '__main__':
    main()
