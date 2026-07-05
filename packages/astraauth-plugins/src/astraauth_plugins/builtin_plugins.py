from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from astraauth.plugins.contracts import (
    ColumnExtension,
    EndpointExtension,
    HookName,
    TableExtension,
)


@dataclass(frozen=True)
class GeoSignalPlugin:
    """Built-in plugin for basic geo-aware auth checks and health reporting."""

    name: str = "geo"
    order: int = 10
    blocked_countries: tuple[str, ...] = ()

    def hooks(self) -> dict[HookName, Any]:
        return {
            "auth.pre_authenticate": self._pre_authenticate,
            "auth.pre_authorize": self._pre_authorize,
        }

    def register_endpoints(self) -> tuple[EndpointExtension, ...]:
        return (
            EndpointExtension(self.name, "/auth/ext/geo/health", ("GET",), self._health_handler),
        )

    def register_tables(self) -> tuple[TableExtension, ...]:
        return (TableExtension(self.name, "plugin_geo_events"),)

    def register_columns(self) -> tuple[ColumnExtension, ...]:
        return ()

    def _health_handler(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "ok", "plugin": self.name, "payload_path": payload.get("path")}

    def _pre_authenticate(self, payload: dict[str, Any]) -> dict[str, Any]:
        country = str(payload.get("country", "")).upper()
        if country and country in set(self.blocked_countries):
            raise ValueError(f"Country '{country}' is blocked")
        return {"geo_checked": True}

    def _pre_authorize(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"geo_authorize_checked": True}


@dataclass(frozen=True)
class RiskSignalPlugin:
    """Built-in plugin for simple risk-threshold decisions and MFA hints."""

    name: str = "risk"
    order: int = 20
    max_risk_score: int = 80

    def hooks(self) -> dict[HookName, Any]:
        return {
            "auth.pre_authorize": self._pre_authorize,
            "mfa.challenge": self._mfa_challenge,
        }

    def register_endpoints(self) -> tuple[EndpointExtension, ...]:
        return (
            EndpointExtension(self.name, "/auth/ext/risk/score", ("POST",), self._score_handler),
        )

    def register_tables(self) -> tuple[TableExtension, ...]:
        return (TableExtension(self.name, "plugin_risk_events"),)

    def register_columns(self) -> tuple[ColumnExtension, ...]:
        return (ColumnExtension(self.name, "plugin_risk_extension", "risk_score"),)

    def _pre_authorize(self, payload: dict[str, Any]) -> dict[str, Any]:
        risk_score = int(payload.get("risk_score", 0))
        if risk_score > self.max_risk_score:
            raise ValueError("Risk score exceeds threshold")
        return {"risk_checked": True}

    def _mfa_challenge(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"risk_mfa_hint": "challenge_if_untrusted_device"}

    def _score_handler(self, payload: dict[str, Any]) -> dict[str, Any]:
        risk_score = int(payload.get("risk_score", 0))
        verdict = "allow" if risk_score <= self.max_risk_score else "deny"
        return {"plugin": self.name, "risk_score": risk_score, "verdict": verdict}


# Backward-compatible aliases for the older public names.
GeoPlugin = GeoSignalPlugin
RiskPlugin = RiskSignalPlugin
