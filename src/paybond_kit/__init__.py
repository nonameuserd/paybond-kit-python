"""Paybond Kit — Harbor client, evidence signing, service-account sessions, and agent framework hooks."""

from __future__ import annotations

from paybond_kit.capability_binding import PaybondCapabilityBinding
from paybond_kit.credentials import (
    GatewayAuthError,
    GatewayHarborTokenProvider,
    ServiceAccountHarborSession,
)
from paybond_kit.harbor import (
    HarborClient,
    HarborHttpError,
    TenantBindingError,
    VerifyCapabilityResult,
)
from paybond_kit.paybond import Paybond, PaybondIntents
from paybond_kit.signal import (
    GatewaySignalClient,
    ServiceAccountSignalSession,
    SignalHttpError,
)
from paybond_kit.signing import sign_payee_evidence_binding

__all__ = [
    "GatewayAuthError",
    "GatewayHarborTokenProvider",
    "HarborClient",
    "HarborHttpError",
    "Paybond",
    "PaybondCapabilityBinding",
    "PaybondIntents",
    "GatewaySignalClient",
    "ServiceAccountHarborSession",
    "ServiceAccountSignalSession",
    "SignalHttpError",
    "TenantBindingError",
    "VerifyCapabilityResult",
    "sign_payee_evidence_binding",
]
