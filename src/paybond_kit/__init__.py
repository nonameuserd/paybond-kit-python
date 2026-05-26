"""Paybond Kit — Harbor client, evidence signing, service-account sessions, and agent framework hooks."""

from __future__ import annotations

from paybond_kit.capability_binding import PaybondCapabilityBinding
from paybond_kit.credentials import (
    GatewayAuthError,
    GatewayHarborTokenProvider,
    ServiceAccountHarborSession,
)
from paybond_kit.a2a import A2AHttpError, GatewayA2AClient
from paybond_kit.fraud import (
    FraudHttpError,
    GatewayFraudClient,
    ServiceAccountFraudSession,
    SignalFraudAssessment,
    SignalFraudAssessmentResponse,
    SignalFraudMetricsResponse,
    SignalFraudReviewEventInput,
    SignalFraudReviewEventResponse,
    SignalFraudReviewQueueItem,
    SignalFraudReviewQueueResponse,
    SignalFraudSignal,
)
from paybond_kit.harbor import (
    FundIntentResult,
    HarborClient,
    HarborHttpError,
    IntentFundingResult,
    SettlementRail,
    TenantBindingError,
    VerifyCapabilityResult,
)
from paybond_kit.paybond import Paybond, PaybondIntents
from paybond_kit.protocol import (
    AgentRecognitionProofV1,
    AgentMandateV1,
    GatewayProtocolClient,
    ImportAgentMandateV1Result,
    ProtocolAuthorizationReceiptV1,
    ProtocolHttpError,
    ProtocolSettlementReceiptV1,
    ProtocolTransportBindingV1,
    SignedAgentMandateV1,
    VerifyProtocolReceiptV1Result,
)
from paybond_kit.signal import (
    GatewaySignalClient,
    ServiceAccountSignalSession,
    SignalHttpError,
    SignalPortfolioSummary,
    SignalReceiptEnvelope,
    SignalSignedPortfolioArtifact,
    SignalSignedReceipt,
)
from paybond_kit.signing import sign_payee_evidence_binding

__all__ = [
    "A2AHttpError",
    "GatewayAuthError",
    "GatewayA2AClient",
    "GatewayFraudClient",
    "GatewayHarborTokenProvider",
    "GatewayProtocolClient",
    "FundIntentResult",
    "HarborClient",
    "HarborHttpError",
    "IntentFundingResult",
    "SettlementRail",
    "Paybond",
    "PaybondCapabilityBinding",
    "PaybondIntents",
    "GatewaySignalClient",
    "FraudHttpError",
    "ServiceAccountHarborSession",
    "ServiceAccountFraudSession",
    "ServiceAccountSignalSession",
    "SignalFraudAssessment",
    "SignalFraudAssessmentResponse",
    "SignalFraudMetricsResponse",
    "SignalFraudReviewEventInput",
    "SignalFraudReviewEventResponse",
    "SignalFraudReviewQueueItem",
    "SignalFraudReviewQueueResponse",
    "SignalFraudSignal",
    "SignalHttpError",
    "SignalPortfolioSummary",
    "SignalReceiptEnvelope",
    "SignalSignedPortfolioArtifact",
    "SignalSignedReceipt",
    "ProtocolHttpError",
    "AgentRecognitionProofV1",
    "AgentMandateV1",
    "SignedAgentMandateV1",
    "ProtocolTransportBindingV1",
    "ProtocolAuthorizationReceiptV1",
    "ProtocolSettlementReceiptV1",
    "ImportAgentMandateV1Result",
    "VerifyProtocolReceiptV1Result",
    "TenantBindingError",
    "VerifyCapabilityResult",
    "sign_payee_evidence_binding",
]
