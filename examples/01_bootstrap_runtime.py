from __future__ import annotations

from _support import workspace_example_home
from astraauth_core.config import AuthConfig
from astraauth_service import build_service_from_home, runtime_health_report


def main() -> None:
    with workspace_example_home('bootstrap-runtime') as home:
        config = AuthConfig.for_project(
            project_name='AstraAuth',
            environment='dev',
            persistence_backend='sqlite',
            persistence_base_dir=str(home / 'data'),
            issuer='https://auth.local',
        )
        config.save_json(home=home)

        service = build_service_from_home(home=home)
        report = runtime_health_report(home=home)
        configuration = service.adapter.handle_openid_configuration(issuer=report.issuer).body
        assert isinstance(configuration, dict)

        print('home:', home)
        print('environment:', report.environment)
        print('issuer:', report.issuer)
        print('persistence:', report.persistence_backends)
        print('openid keys:', sorted(configuration.keys()))


if __name__ == '__main__':
    main()
