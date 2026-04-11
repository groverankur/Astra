from __future__ import annotations

from typing import Any, Literal, Protocol

from astraauth_plugins.contracts import HookName

from astraauth_core.adapters.base import OAuthAdapter
from astraauth_core.adapters.http_types import HttpResponse, RequestContext
from astraauth_core.authorization.engine import AuthorizationEngine
from astraauth_core.authorization.exceptions import PermissionDeniedError, StepUpRequiredError
from astraauth_core.authorization.scope_policy import ScopePolicy
from astraauth_core.events.base import EventBus
from astraauth_core.mfa import (
    EmailOTPCodeStore,
    EmailOTPDelivery,
    EmailOTPFactorStore,
    EmailOTPVerificationError,
    MFAChallengeError,
    MFAChallengeStore,
    MFAFactorType,
    NumericEmailOTPGenerator,
    TOTPFactorStore,
    TOTPProvider,
    TOTPVerificationError,
    create_email_otp_challenge,
    create_mfa_challenge,
    upgrade_session_with_verified_challenge,
    verify_email_otp_challenge,
    verify_totp_challenge,
)
from astraauth_core.oauth.errors import OAuthError
from astraauth_core.oauth.services import (
    APIKeyAuthenticator,
    AuthorizationCodeStore,
    ClientRegistry,
    PasswordAuthenticator,
    SubjectDirectory,
    exchange_token,
    start_authorization,
)
from astraauth_core.sessions.introspection import introspect_access_token
from astraauth_core.sessions.models import Session
from astraauth_core.sessions.services import logout_by_refresh_token
from astraauth_core.sessions.store import SessionStore
from astraauth_core.token.token_manager import TokenKeyManager


class HookRunner(Protocol):
    def run_hook(
        self,
        *,
        hook: HookName,
        tenant_id: str,
        payload: dict[str, Any],
        fail_closed: bool = True,
    ) -> dict[str, Any]: ...


class WebAuthnHandler(Protocol):
    def begin_registration(self, *, session_id: str, user_name: str, rp_id: str, rp_name: str) -> dict[str, object]: ...
    def finish_registration(
        self,
        *,
        state_id: str,
        credential_id: str,
        public_key: str,
        transports: tuple[str, ...],
        sign_count: int,
    ) -> dict[str, object]: ...
    def begin_authentication(self, *, session_id: str, challenge_id: str) -> dict[str, object]: ...
    def finish_authentication(
        self,
        *,
        session_id: str,
        state_id: str,
        credential_id: str,
        sign_count: int,
    ) -> dict[str, object]: ...


class OIDCHandler(Protocol):
    def begin_login(
        self,
        *,
        provider_id: str,
        tenant_id: str,
        redirect_uri: str,
    ) -> dict[str, object]: ...
    def complete_callback(
        self,
        *,
        provider_id: str,
        tenant_id: str,
        client_id: str,
        redirect_uri: str,
        code: str,
        state: str,
        scope: str | None = None,
    ) -> dict[str, object]: ...


class ObservabilityRecorder(Protocol):
    correlation_header_name: str

    def next_correlation_id(self, *, supplied: str | None = None) -> str: ...
    def record_metric(self, *, name: str, value: int = 1) -> None: ...
    def record_event(
        self,
        *,
        event_type: str,
        status: str,
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
        level: str = "INFO",
    ) -> None: ...


class OAuthHTTPAdapter(OAuthAdapter):
    def __init__(
        self,
        *,
        clients: ClientRegistry,
        subjects: SubjectDirectory,
        codes: AuthorizationCodeStore,
        session_store: SessionStore,
        token_manager: TokenKeyManager,
        access_token_audience: str,
        code_ttl_seconds: int,
        session_ttl_seconds: int,
        authorization_engine: AuthorizationEngine,
        scope_policy: ScopePolicy,
        password_authenticator: PasswordAuthenticator | None = None,
        api_key_authenticator: APIKeyAuthenticator | None = None,
        hook_runner: HookRunner | None = None,
        mfa_challenge_store: MFAChallengeStore | None = None,
        totp_factor_store: TOTPFactorStore | None = None,
        totp_provider: TOTPProvider | None = None,
        email_otp_factor_store: EmailOTPFactorStore | None = None,
        email_otp_code_store: EmailOTPCodeStore | None = None,
        email_otp_delivery: EmailOTPDelivery | None = None,
        webauthn_handler: WebAuthnHandler | None = None,
        oidc_handler: OIDCHandler | None = None,
        event_bus: EventBus | None = None,
        observability: ObservabilityRecorder | None = None,
    ) -> None:
        self._clients = clients
        self._subjects = subjects
        self._codes = codes
        self._session_store = session_store
        self._token_manager = token_manager
        self._access_token_audience = access_token_audience
        self._code_ttl_seconds = code_ttl_seconds
        self._session_ttl_seconds = session_ttl_seconds
        self._authorization_engine = authorization_engine
        self._scope_policy = scope_policy
        self._password_authenticator = password_authenticator
        self._api_key_authenticator = api_key_authenticator
        self._hook_runner = hook_runner
        self._mfa_challenge_store = mfa_challenge_store
        self._totp_factor_store = totp_factor_store
        self._totp_provider = totp_provider
        self._email_otp_factor_store = email_otp_factor_store
        self._email_otp_code_store = email_otp_code_store
        self._email_otp_delivery = email_otp_delivery
        self._email_otp_generator = NumericEmailOTPGenerator()
        self._webauthn_handler = webauthn_handler
        self._oidc_handler = oidc_handler
        self._event_bus = event_bus
        self._observability = observability

    def _oauth_error_to_status(self, error_code: str) -> int:
        if error_code == "invalid_client":
            return 401
        if error_code in {"access_denied", "unauthorized_client"}:
            return 403
        return 400

    def _build_oauth_error_response(self, err: OAuthError) -> HttpResponse:
        return HttpResponse(
            status=self._oauth_error_to_status(err.error),
            body={"error": err.error, "error_description": str(err)},
        )

    def _correlation_id(self, req: RequestContext) -> str | None:
        if self._observability is None:
            return None
        return self._observability.next_correlation_id(
            supplied=req.header(self._observability.correlation_header_name)
        )

    def _finalize_response(
        self,
        *,
        req: RequestContext,
        response: HttpResponse,
        correlation_id: str | None,
        event_type: str | None = None,
        status: str | None = None,
        metric_name: str | None = None,
        details: dict[str, Any] | None = None,
        level: str = "INFO",
    ) -> HttpResponse:
        headers = dict(response.headers or {})
        if correlation_id is not None and self._observability is not None:
            headers[self._observability.correlation_header_name] = correlation_id
            if metric_name is not None:
                self._observability.record_metric(name=metric_name)
            if event_type is not None and status is not None:
                self._observability.record_event(
                    event_type=event_type,
                    status=status,
                    correlation_id=correlation_id,
                    details=details,
                    level=level,
                )
        return HttpResponse(status=response.status, body=response.body, headers=headers or None)

    def _run_hook(
        self,
        *,
        hook: HookName,
        tenant_id: str,
        payload: dict[str, Any],
        fail_closed: bool = True,
    ) -> dict[str, Any]:
        if self._hook_runner is None:
            return payload
        return self._hook_runner.run_hook(
            hook=hook,
            tenant_id=tenant_id,
            payload=payload,
            fail_closed=fail_closed,
        )

    def _get_session_for_mfa(self, session_id: str | None) -> tuple[HttpResponse | None, Session | None]:
        if session_id is None:
            return HttpResponse(status=400, body={"error": "invalid_request"}), None
        session = self._session_store.get(session_id)
        if session is None or session.revoked or session.is_expired():
            return HttpResponse(status=400, body={"error": "invalid_session"}), None
        return None, session

    def _get_session_from_refresh_token(self, refresh_token: str | None) -> Session | None:
        if refresh_token is None:
            return None
        claims = self._token_manager.decrypt_jwe(refresh_token)
        session_id = claims.get("sid")
        if not isinstance(session_id, str):
            return None
        return self._session_store.get(session_id)

    def _start_step_up_if_required(self, req: RequestContext, token_response: Any) -> HttpResponse | None:
        required_acr_raw = req.form("required_acr")
        if required_acr_raw is None or self._mfa_challenge_store is None:
            return None
        required_acr = int(required_acr_raw)
        session = self._get_session_from_refresh_token(getattr(token_response, "refresh_token", None))
        if session is None or session.acr >= required_acr:
            return None
        factor_type = MFAFactorType(req.form("preferred_factor_type") or MFAFactorType.WEBAUTHN.value)
        return self._start_step_up_response(
            session=session,
            factor_type=factor_type,
            required_acr=required_acr,
            purpose=req.form("purpose") or "step_up",
            ttl_seconds=int(req.form("ttl_seconds") or "300"),
        )

    def _start_step_up_response(
        self,
        *,
        session: Session,
        factor_type: MFAFactorType,
        required_acr: int,
        purpose: str,
        ttl_seconds: int,
    ) -> HttpResponse:
        if self._mfa_challenge_store is None:
            return HttpResponse(status=501, body={"error": "mfa_not_configured"})
        if factor_type == MFAFactorType.TOTP:
            challenge = create_mfa_challenge(
                session=session,
                factor_type=factor_type,
                challenge_store=self._mfa_challenge_store,
                required_acr=required_acr,
                purpose=purpose,
                ttl_seconds=ttl_seconds,
                event_bus=self._event_bus,
            )
            return HttpResponse(
                status=428,
                body={
                    "error": "step_up_required",
                    "session_id": session.session_id,
                    "challenge_id": challenge.challenge_id,
                    "factor_type": challenge.factor_type.value,
                    "required_acr": challenge.required_acr,
                },
            )
        if factor_type == MFAFactorType.EMAIL_OTP:
            if (
                self._email_otp_factor_store is None
                or self._email_otp_code_store is None
                or self._email_otp_delivery is None
            ):
                return HttpResponse(status=501, body={"error": "email_otp_not_configured"})
            result = create_email_otp_challenge(
                session=session,
                challenge_store=self._mfa_challenge_store,
                factor_store=self._email_otp_factor_store,
                code_store=self._email_otp_code_store,
                delivery=self._email_otp_delivery,
                code_generator=self._email_otp_generator,
                required_acr=required_acr,
                purpose=purpose,
                ttl_seconds=ttl_seconds,
                event_bus=self._event_bus,
            )
            return HttpResponse(
                status=428,
                body={
                    "error": "step_up_required",
                    "session_id": session.session_id,
                    "challenge_id": result.challenge.challenge_id,
                    "factor_type": result.challenge.factor_type.value,
                    "required_acr": result.challenge.required_acr,
                    "destination": result.destination,
                },
            )
        if factor_type == MFAFactorType.WEBAUTHN:
            if self._webauthn_handler is None:
                return HttpResponse(status=501, body={"error": "webauthn_not_configured"})
            challenge = create_mfa_challenge(
                session=session,
                factor_type=factor_type,
                challenge_store=self._mfa_challenge_store,
                required_acr=required_acr,
                purpose=purpose,
                ttl_seconds=ttl_seconds,
                event_bus=self._event_bus,
            )
            try:
                webauthn = self._webauthn_handler.begin_authentication(
                    session_id=session.session_id,
                    challenge_id=challenge.challenge_id,
                )
            except Exception as exc:
                return HttpResponse(
                    status=400,
                    body={"error": "webauthn_authentication_failed", "error_description": str(exc)},
                )
            return HttpResponse(
                status=428,
                body={
                    "error": "step_up_required",
                    "session_id": session.session_id,
                    "challenge_id": challenge.challenge_id,
                    "factor_type": challenge.factor_type.value,
                    "required_acr": challenge.required_acr,
                    "state_id": webauthn["state_id"],
                    "options": webauthn["options"],
                },
            )
        return HttpResponse(status=400, body={"error": "unsupported_factor_type"})

    def handle_authorize(self, req: RequestContext) -> HttpResponse:
        correlation_id = self._correlation_id(req)
        try:
            client_id = req.query("client_id")
            tenant_id = req.query("tenant_id") or "Default"
            redirect_uri = req.query("redirect_uri")
            scope = req.query("scope") or ""
            subject_id = req.query("subject_id")
            nonce = req.query("nonce")
            code_challenge = req.query("code_challenge")
            code_challenge_method = req.query("code_challenge_method")

            if (
                client_id is None
                or redirect_uri is None
                or subject_id is None
                or code_challenge is None
                or code_challenge_method is None
            ):
                return self._finalize_response(
                    req=req,
                    response=HttpResponse(status=400, body={"error": "invalid_request"}),
                    correlation_id=correlation_id,
                    event_type="oauth.authorize",
                    status="failed",
                    metric_name="auth.failures",
                    details={"reason": "invalid_request"},
                    level="WARNING",
                )

            if code_challenge_method != "S256":
                return self._finalize_response(
                    req=req,
                    response=HttpResponse(status=400, body={"error": "invalid_request"}),
                    correlation_id=correlation_id,
                    event_type="oauth.authorize",
                    status="failed",
                    metric_name="auth.failures",
                    details={"reason": "invalid_pkce_method"},
                    level="WARNING",
                )

            self._run_hook(
                hook="auth.pre_authenticate",
                tenant_id=tenant_id,
                payload={
                    "client_id": client_id,
                    "tenant_id": tenant_id,
                    "subject_id": subject_id,
                    "redirect_uri": redirect_uri,
                    "scope": scope,
                    "country": req.header("X-Country"),
                    "ip": req.ip(),
                    "path": req.path(),
                },
                fail_closed=True,
            )

            method: Literal["S256"] = "S256"
            from astraauth_core.oauth.models import PKCEParams
            pkce = PKCEParams(code_challenge=code_challenge, code_challenge_method=method)

            code = start_authorization(
                client_id=client_id,
                tenant_id=tenant_id,
                redirect_uri=redirect_uri,
                scopes=set(scope.split()) if scope else set(),
                subject_id=subject_id,
                pkce=pkce,
                nonce=nonce,
                clients=self._clients,
                subjects=self._subjects,
                codes=self._codes,
                code_ttl_seconds=self._code_ttl_seconds,
            )

            self._run_hook(
                hook="auth.post_authenticate",
                tenant_id=tenant_id,
                payload={
                    "client_id": client_id,
                    "tenant_id": tenant_id,
                    "subject_id": subject_id,
                    "authorization_code_issued": True,
                },
                fail_closed=False,
            )
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=302, body=None, headers={"Location": f"{redirect_uri}?code={code.code}"}),
                correlation_id=correlation_id,
                event_type="oauth.authorize",
                status="succeeded",
                details={"tenant_id": tenant_id, "client_id": client_id},
            )
        except RuntimeError:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=403, body={"error": "access_denied"}),
                correlation_id=correlation_id,
                event_type="oauth.authorize",
                status="failed",
                metric_name="auth.failures",
                details={"reason": "hook_denied"},
                level="WARNING",
            )
        except OAuthError as e:
            return self._finalize_response(
                req=req,
                response=self._build_oauth_error_response(e),
                correlation_id=correlation_id,
                event_type="oauth.authorize",
                status="failed",
                metric_name="auth.failures",
                details={"reason": e.error},
                level="WARNING",
            )
        except PermissionDeniedError:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=403, body={"error": "access_denied"}),
                correlation_id=correlation_id,
                event_type="oauth.authorize",
                status="failed",
                metric_name="auth.failures",
                details={"reason": "permission_denied"},
                level="WARNING",
            )
        except StepUpRequiredError:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=428, body={"error": "step_up_required"}),
                correlation_id=correlation_id,
                event_type="oauth.authorize",
                status="step_up_required",
                details={"reason": "step_up_required"},
                level="WARNING",
            )

    def handle_token(self, req: RequestContext) -> HttpResponse:
        correlation_id = self._correlation_id(req)
        try:
            grant_type = req.form("grant_type")
            client_id = req.form("client_id")
            tenant_id = req.form("tenant_id") or "Default"
            authorization_header = req.header("Authorization")
            form_client_secret = req.form("client_secret")
            client_assertion = req.form("client_assertion")
            client_assertion_type = req.form("client_assertion_type")
            token_endpoint = "https://auth.server/token"
            if grant_type is None or client_id is None:
                return self._finalize_response(
                    req=req,
                    response=HttpResponse(status=400, body={"error": "invalid_request"}),
                    correlation_id=correlation_id,
                    event_type="oauth.token",
                    status="failed",
                    metric_name="auth.failures",
                    details={"reason": "invalid_request"},
                    level="WARNING",
                )
            scope_raw = req.form("scope")
            requested_scopes = set(scope_raw.split()) if scope_raw else set()

            self._run_hook(
                hook="auth.pre_authorize",
                tenant_id=tenant_id,
                payload={
                    "grant_type": grant_type,
                    "client_id": client_id,
                    "tenant_id": tenant_id,
                    "requested_scopes": sorted(requested_scopes),
                    "risk_score": req.header("X-Risk-Score"),
                    "ip": req.ip(),
                    "path": req.path(),
                },
                fail_closed=True,
            )

            token_response = exchange_token(
                grant_type=grant_type,
                client_id=client_id,
                tenant_id=tenant_id,
                redirect_uri=req.form("redirect_uri"),
                code=req.form("code"),
                code_verifier=req.form("code_verifier"),
                refresh_token=req.form("refresh_token"),
                requested_scopes=requested_scopes,
                username=req.form("username"),
                password=req.form("password"),
                api_key=req.form("api_key"),
                clients=self._clients,
                subjects=self._subjects,
                codes=self._codes,
                session_store=self._session_store,
                token_manager=self._token_manager,
                access_token_audience=self._access_token_audience,
                session_ttl_seconds=self._session_ttl_seconds,
                authorization_engine=self._authorization_engine,
                authorization_header=authorization_header,
                scope_policy=self._scope_policy,
                form_client_secret=form_client_secret,
                client_assertion=client_assertion,
                client_assertion_type=client_assertion_type,
                token_endpoint=token_endpoint,
                password_authenticator=self._password_authenticator,
                api_key_authenticator=self._api_key_authenticator,
            )

            step_up_response = self._start_step_up_if_required(req, token_response)
            if step_up_response is not None:
                return self._finalize_response(
                    req=req,
                    response=step_up_response,
                    correlation_id=correlation_id,
                    event_type="oauth.token",
                    status="step_up_required",
                    details={"tenant_id": tenant_id, "client_id": client_id},
                    level="WARNING",
                )

            self._run_hook(
                hook="auth.post_authorize",
                tenant_id=tenant_id,
                payload={
                    "grant_type": grant_type,
                    "client_id": client_id,
                    "tenant_id": tenant_id,
                    "issued_access_token": token_response.access_token is not None,
                    "issued_refresh_token": token_response.refresh_token is not None,
                },
                fail_closed=False,
            )
            self._run_hook(
                hook="token.issued",
                tenant_id=tenant_id,
                payload={"client_id": client_id, "tenant_id": tenant_id, "token_type": "access_token"},
                fail_closed=False,
            )
            if token_response.refresh_token:
                self._run_hook(
                    hook="token.issued",
                    tenant_id=tenant_id,
                    payload={"client_id": client_id, "tenant_id": tenant_id, "token_type": "refresh_token"},
                    fail_closed=False,
                )
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=200, body=token_response.__dict__),
                correlation_id=correlation_id,
                event_type="oauth.token",
                status="succeeded",
                details={"tenant_id": tenant_id, "client_id": client_id, "grant_type": grant_type},
            )
        except RuntimeError:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=403, body={"error": "access_denied"}),
                correlation_id=correlation_id,
                event_type="oauth.token",
                status="failed",
                metric_name="auth.failures",
                details={"reason": "hook_denied"},
                level="WARNING",
            )
        except OAuthError as e:
            return self._finalize_response(
                req=req,
                response=self._build_oauth_error_response(e),
                correlation_id=correlation_id,
                event_type="oauth.token",
                status="failed",
                metric_name="auth.failures",
                details={"reason": e.error},
                level="WARNING",
            )
        except PermissionDeniedError:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=403, body={"error": "access_denied"}),
                correlation_id=correlation_id,
                event_type="oauth.token",
                status="failed",
                metric_name="auth.failures",
                details={"reason": "permission_denied"},
                level="WARNING",
            )
        except StepUpRequiredError:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=428, body={"error": "step_up_required"}),
                correlation_id=correlation_id,
                event_type="oauth.token",
                status="step_up_required",
                details={"reason": "step_up_required"},
                level="WARNING",
            )

    def handle_mfa_challenge(self, req: RequestContext) -> HttpResponse:
        factor_type_raw = req.form("factor_type") or MFAFactorType.TOTP.value
        required_acr_raw = req.form("required_acr") or "2"
        purpose = req.form("purpose") or "step_up"
        ttl_seconds_raw = req.form("ttl_seconds") or "300"
        error, session = self._get_session_for_mfa(req.form("session_id"))
        if error is not None or session is None:
            return error or HttpResponse(status=400, body={"error": "invalid_session"})
        try:
            return self._start_step_up_response(
                session=session,
                factor_type=MFAFactorType(factor_type_raw),
                required_acr=int(required_acr_raw),
                purpose=purpose,
                ttl_seconds=int(ttl_seconds_raw),
            )
        except (ValueError, MFAChallengeError) as exc:
            return HttpResponse(status=400, body={"error": "invalid_request", "error_description": str(exc)})

    def handle_mfa_verify(self, req: RequestContext) -> HttpResponse:
        if self._mfa_challenge_store is None:
            return HttpResponse(status=501, body={"error": "mfa_not_configured"})
        factor_type_raw = req.form("factor_type")
        challenge_id = req.form("challenge_id")
        code = req.form("code")
        error, session = self._get_session_for_mfa(req.form("session_id"))
        if error is not None or session is None:
            return error or HttpResponse(status=400, body={"error": "invalid_session"})
        if challenge_id is None or code is None or factor_type_raw is None:
            return HttpResponse(status=400, body={"error": "invalid_request"})
        try:
            factor_type = MFAFactorType(factor_type_raw)
            if factor_type == MFAFactorType.TOTP:
                if self._totp_factor_store is None or self._totp_provider is None:
                    return HttpResponse(status=501, body={"error": "totp_not_configured"})
                verify_totp_challenge(
                    challenge_id=challenge_id,
                    session=session,
                    code=code,
                    challenge_store=self._mfa_challenge_store,
                    factor_store=self._totp_factor_store,
                    provider=self._totp_provider,
                )
                upgraded = upgrade_session_with_verified_challenge(
                    challenge_id=challenge_id,
                    challenge_store=self._mfa_challenge_store,
                    session_store=self._session_store,
                    methods={"totp"},
                    event_bus=self._event_bus,
                )
                return HttpResponse(status=200, body={"sid": upgraded.session_id, "acr": upgraded.acr, "amr": list(upgraded.amr)})
            if factor_type == MFAFactorType.EMAIL_OTP:
                if self._email_otp_code_store is None:
                    return HttpResponse(status=501, body={"error": "email_otp_not_configured"})
                verify_email_otp_challenge(
                    challenge_id=challenge_id,
                    session=session,
                    code=code,
                    challenge_store=self._mfa_challenge_store,
                    code_store=self._email_otp_code_store,
                )
                upgraded = upgrade_session_with_verified_challenge(
                    challenge_id=challenge_id,
                    challenge_store=self._mfa_challenge_store,
                    session_store=self._session_store,
                    methods={"email_otp"},
                    event_bus=self._event_bus,
                )
                return HttpResponse(status=200, body={"sid": upgraded.session_id, "acr": upgraded.acr, "amr": list(upgraded.amr)})
            return HttpResponse(status=400, body={"error": "unsupported_factor_type"})
        except (TOTPVerificationError, EmailOTPVerificationError, MFAChallengeError) as exc:
            return HttpResponse(status=400, body={"error": "verification_failed", "error_description": str(exc)})

    def handle_webauthn_register_start(self, req: RequestContext) -> HttpResponse:
        if self._webauthn_handler is None:
            return HttpResponse(status=501, body={"error": "webauthn_not_configured"})
        session_id = req.form("session_id")
        user_name = req.form("user_name")
        rp_id = req.form("rp_id") or "localhost"
        rp_name = req.form("rp_name") or "AstraAuth"
        if session_id is None or user_name is None:
            return HttpResponse(status=400, body={"error": "invalid_request"})
        try:
            result = self._webauthn_handler.begin_registration(
                session_id=session_id,
                user_name=user_name,
                rp_id=rp_id,
                rp_name=rp_name,
            )
            return HttpResponse(status=200, body=result)
        except Exception as exc:
            return HttpResponse(status=400, body={"error": "webauthn_registration_failed", "error_description": str(exc)})

    def handle_webauthn_register_finish(self, req: RequestContext) -> HttpResponse:
        if self._webauthn_handler is None:
            return HttpResponse(status=501, body={"error": "webauthn_not_configured"})
        state_id = req.form("state_id")
        credential_id = req.form("credential_id")
        public_key = req.form("public_key")
        transports_raw = req.form("transports") or "internal"
        sign_count_raw = req.form("sign_count") or "0"
        if state_id is None or credential_id is None or public_key is None:
            return HttpResponse(status=400, body={"error": "invalid_request"})
        try:
            result = self._webauthn_handler.finish_registration(
                state_id=state_id,
                credential_id=credential_id,
                public_key=public_key,
                transports=tuple(filter(None, (part.strip() for part in transports_raw.split(",")))),
                sign_count=int(sign_count_raw),
            )
            return HttpResponse(status=200, body=result)
        except Exception as exc:
            return HttpResponse(status=400, body={"error": "webauthn_registration_failed", "error_description": str(exc)})

    def handle_webauthn_authenticate_start(self, req: RequestContext) -> HttpResponse:
        if self._webauthn_handler is None:
            return HttpResponse(status=501, body={"error": "webauthn_not_configured"})
        session_id = req.form("session_id")
        challenge_id = req.form("challenge_id")
        if session_id is None or challenge_id is None:
            return HttpResponse(status=400, body={"error": "invalid_request"})
        try:
            result = self._webauthn_handler.begin_authentication(
                session_id=session_id,
                challenge_id=challenge_id,
            )
            return HttpResponse(status=200, body=result)
        except Exception as exc:
            return HttpResponse(status=400, body={"error": "webauthn_authentication_failed", "error_description": str(exc)})

    def handle_webauthn_authenticate_finish(self, req: RequestContext) -> HttpResponse:
        if self._webauthn_handler is None:
            return HttpResponse(status=501, body={"error": "webauthn_not_configured"})
        session_id = req.form("session_id")
        state_id = req.form("state_id")
        credential_id = req.form("credential_id")
        sign_count_raw = req.form("sign_count") or "0"
        if session_id is None or state_id is None or credential_id is None:
            return HttpResponse(status=400, body={"error": "invalid_request"})
        try:
            result = self._webauthn_handler.finish_authentication(
                session_id=session_id,
                state_id=state_id,
                credential_id=credential_id,
                sign_count=int(sign_count_raw),
            )
            return HttpResponse(status=200, body=result)
        except Exception as exc:
            return HttpResponse(status=400, body={"error": "webauthn_authentication_failed", "error_description": str(exc)})

    def handle_oidc_login_start(self, req: RequestContext) -> HttpResponse:
        correlation_id = self._correlation_id(req)
        if self._oidc_handler is None:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=501, body={"error": "oidc_not_configured"}),
                correlation_id=correlation_id,
                event_type="oidc.login.start",
                status="failed",
                metric_name="federation.failures",
                details={"reason": "oidc_not_configured"},
                level="WARNING",
            )
        provider_id = req.form("provider_id") or req.query("provider_id")
        tenant_id = req.form("tenant_id") or req.query("tenant_id") or "Default"
        redirect_uri = req.form("redirect_uri") or req.query("redirect_uri")
        if provider_id is None or redirect_uri is None:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=400, body={"error": "invalid_request"}),
                correlation_id=correlation_id,
                event_type="oidc.login.start",
                status="failed",
                metric_name="federation.failures",
                details={"reason": "invalid_request"},
                level="WARNING",
            )
        try:
            result = self._oidc_handler.begin_login(
                provider_id=provider_id,
                tenant_id=tenant_id,
                redirect_uri=redirect_uri,
            )
            authorization_url = result.get("authorization_url")
            if isinstance(authorization_url, str):
                return self._finalize_response(
                    req=req,
                    response=HttpResponse(status=302, body=None, headers={"Location": authorization_url}),
                    correlation_id=correlation_id,
                    event_type="oidc.login.start",
                    status="succeeded",
                    details={"tenant_id": tenant_id, "provider_id": provider_id},
                )
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=200, body=result),
                correlation_id=correlation_id,
                event_type="oidc.login.start",
                status="succeeded",
                details={"tenant_id": tenant_id, "provider_id": provider_id},
            )
        except Exception as exc:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=400, body={"error": "oidc_login_failed", "error_description": str(exc)}),
                correlation_id=correlation_id,
                event_type="oidc.login.start",
                status="failed",
                metric_name="federation.failures",
                details={"reason": str(exc)},
                level="WARNING",
            )

    def handle_oidc_callback(self, req: RequestContext) -> HttpResponse:
        correlation_id = self._correlation_id(req)
        if self._oidc_handler is None:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=501, body={"error": "oidc_not_configured"}),
                correlation_id=correlation_id,
                event_type="oidc.callback",
                status="failed",
                metric_name="federation.failures",
                details={"reason": "oidc_not_configured"},
                level="WARNING",
            )
        provider_id = req.query("provider_id") or req.form("provider_id")
        tenant_id = req.query("tenant_id") or req.form("tenant_id") or "Default"
        client_id = req.query("client_id") or req.form("client_id")
        redirect_uri = req.query("redirect_uri") or req.form("redirect_uri")
        code = req.query("code") or req.form("code")
        state = req.query("state") or req.form("state")
        scope = req.query("scope") or req.form("scope")
        if None in {provider_id, client_id, redirect_uri, code, state}:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=400, body={"error": "invalid_request"}),
                correlation_id=correlation_id,
                event_type="oidc.callback",
                status="failed",
                metric_name="federation.failures",
                details={"reason": "invalid_request"},
                level="WARNING",
            )
        try:
            result = self._oidc_handler.complete_callback(
                provider_id=str(provider_id),
                tenant_id=tenant_id,
                client_id=str(client_id),
                redirect_uri=str(redirect_uri),
                code=str(code),
                state=str(state),
                scope=scope,
            )
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=200, body=result),
                correlation_id=correlation_id,
                event_type="oidc.callback",
                status="succeeded",
                details={"tenant_id": tenant_id, "provider_id": provider_id},
            )
        except Exception as exc:
            return self._finalize_response(
                req=req,
                response=HttpResponse(status=400, body={"error": "oidc_callback_failed", "error_description": str(exc)}),
                correlation_id=correlation_id,
                event_type="oidc.callback",
                status="failed",
                metric_name="federation.failures",
                details={"reason": str(exc)},
                level="WARNING",
            )

    def handle_logout(self, req: RequestContext) -> HttpResponse:
        try:
            refresh_token = req.form("refresh_token")
            if refresh_token is None:
                return HttpResponse(status=400, body={"error": "invalid_request"})
            logout_by_refresh_token(
                refresh_token=refresh_token,
                session_store=self._session_store,
                token_manager=self._token_manager,
            )
            return HttpResponse(status=200, body={"status": "logged_out"})
        except Exception:
            return HttpResponse(status=400, body={"error": "invalid_request"})

    def handle_introspect(self, req: RequestContext) -> HttpResponse:
        token = req.form("token")
        if token is None:
            return HttpResponse(status=400, body={"error": "invalid_request"})
        result = introspect_access_token(
            token,
            token_manager=self._token_manager,
            expected_audience=self._access_token_audience,
            session_store=self._session_store,
        )
        return HttpResponse(status=200, body=result)

    def handle_jwks(self, req: RequestContext) -> HttpResponse:
        _ = req
        return HttpResponse(status=200, body={"keys": self._token_manager.get_jwks()})

    def handle_openid_configuration(self, *, issuer: str) -> HttpResponse:
        base = issuer.rstrip("/")
        return HttpResponse(
            status=200,
            body={
                "issuer": base,
                "authorization_endpoint": f"{base}/authorize",
                "token_endpoint": f"{base}/token",
                "jwks_uri": f"{base}/.well-known/jwks.json",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": [self._token_manager._config.signing_alg],
                "token_endpoint_auth_methods_supported": [
                    "none",
                    "client_secret_basic",
                    "client_secret_post",
                    "private_key_jwt",
                ],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["openid"],
            },
        )

