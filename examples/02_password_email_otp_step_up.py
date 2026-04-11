from __future__ import annotations

from pprint import pprint

from astraauth_core.adapters.http_types import NormalizedRequestContext
from astraauth_core.authorization.models import Role
from astraauth_core.oauth.models import OAuthClient, Subject
from astraauth_service import build_inmemory_service


def main() -> None:
    service = build_inmemory_service(default_plugins_enabled=False)

    subject = Subject(subject_id='user-1', tenants={'tenant-1'}, username='alice')
    service.add_subject_password(
        subject=subject,
        tenant_id='tenant-1',
        username='alice',
        password='secret',
    )
    service.add_role(Role(name='user', permissions={'openid'}))
    service.assign_roles(subject_id='user-1', tenant_id='tenant-1', roles={'user'})
    service.add_client(
        OAuthClient(
            client_id='client-1',
            redirect_uris={'https://app.local/callback'},
            allowed_scopes={'openid'},
            client_type='public',
            auth_method='none',
            require_pkce=False,
        )
    )

    factor_id = service.enroll_subject_email_otp(
        subject_id='user-1',
        tenant_id='tenant-1',
        email='alice@example.com',
    )
    service.activate_subject_email_otp(factor_id=factor_id)

    token_resp = service.adapter.handle_token(
        NormalizedRequestContext(
            http_method='POST',
            request_path='/token',
            query_params={},
            headers={},
            form_data={
                'grant_type': 'password',
                'client_id': 'client-1',
                'tenant_id': 'tenant-1',
                'username': 'alice',
                'password': 'secret',
                'scope': 'openid',
                'required_acr': '2',
                'preferred_factor_type': 'email_otp',
            },
        )
    )
    assert isinstance(token_resp.body, dict)
    challenge_resp = service.adapter.handle_mfa_challenge(
        NormalizedRequestContext(
            http_method='POST',
            request_path='/mfa/challenge',
            query_params={},
            headers={},
            form_data={
                'session_id': token_resp.body['session_id'],
                'factor_type': 'email_otp',
                'required_acr': '2',
                'purpose': 'step_up',
            },
        )
    )
    assert isinstance(challenge_resp.body, dict)
    otp_code = service.email_delivery.sent_messages[-1]['code']
    verify_resp = service.adapter.handle_mfa_verify(
        NormalizedRequestContext(
            http_method='POST',
            request_path='/mfa/verify',
            query_params={},
            headers={},
            form_data={
                'session_id': token_resp.body['session_id'],
                'challenge_id': challenge_resp.body['challenge_id'],
                'factor_type': 'email_otp',
                'code': otp_code,
            },
        )
    )

    print('initial token response:')
    pprint(token_resp.body)
    print('\nchallenge response:')
    pprint(challenge_resp.body)
    print('\nverified session:')
    pprint(verify_resp.body)


if __name__ == '__main__':
    main()
