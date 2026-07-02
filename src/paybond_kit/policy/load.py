"""Load and use paybond.policy.yaml documents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from paybond_kit.agent.registry import PaybondToolRegistry
from paybond_kit.policy.intent_spec import (
    PaybondPolicyIntentCreateInput,
    policy_to_intent_create_input,
)
from paybond_kit.policy.merge import (
    PolicyMergeOptions,
    PolicyMergeResult,
    merge_paybond_policies,
    to_effective_policy_document,
)
from paybond_kit.policy.parse_text import parse_policy_document_text
from paybond_kit.policy.registry import policy_to_tool_registry
from paybond_kit.policy.schema import (
    PaybondPolicyDocument,
    PaybondPolicyDocumentV1,
    PaybondPolicyDocumentV2,
    PaybondPolicyIntentSection,
    is_paybond_policy_overlay,
    parse_paybond_policy_document,
    parse_paybond_policy_document_v1,
)
from paybond_kit.policy.sandbox_bootstrap import (
    PaybondPolicySandboxBootstrapOptions,
    policy_sandbox_bootstrap,
)
from paybond_kit.policy.validate import PolicyValidator, PolicyValidatorOptions, PolicyValidatorResult
from paybond_kit.policy.load_effective import (
    PolicyEffectiveResolveClient,
    PolicyEffectiveResolveResult,
    resolve_policy_effective_remote,
)
from paybond_kit.policy.validate_remote import (
    PolicyRemoteValidateClient,
    PolicyRemoteValidateOptions,
    PolicyRemoteValidateResult,
    validate_policy_remote,
    validate_policy_payload_remote,
)
from paybond_kit.agent.types import PaybondRunBindingSandboxBootstrapInput

PaybondPolicyLoadSource = str | Path | dict[str, Any] | PaybondPolicyDocumentV1 | PaybondPolicyDocumentV2


class PaybondPolicy:
    """
    Portable policy-as-code document loaded from paybond.policy.yaml or an in-memory object.

    Drives tool registry construction and production intent create alignment.
    """

    def __init__(self, document: PaybondPolicyDocumentV1, *, source: str | None = None) -> None:
        self.document = document
        self.source = source

    @property
    def name(self) -> str:
        return self.document.name

    @property
    def default_deny(self) -> bool:
        return self.document.default_deny

    @property
    def intent(self) -> PaybondPolicyIntentSection | None:
        return self.document.intent

    @classmethod
    def load(cls, source: PaybondPolicyLoadSource) -> PaybondPolicy:
        """Load and validate a policy from a file path or pre-parsed document object."""
        if isinstance(source, (str, Path)):
            path = Path(source)
            document = cls._load_document(path)
            effective = cls._resolve_effective_document(document, source_path=path)
            return cls(effective, source=str(path))
        if isinstance(source, PaybondPolicyDocumentV1):
            return cls(source)
        document = parse_paybond_policy_document(source)
        effective = cls._resolve_effective_document(document)
        return cls(effective)

    @classmethod
    def merge_local(
        cls,
        *,
        base: PaybondPolicyLoadSource,
        overlay: PaybondPolicyLoadSource,
        options: PolicyMergeOptions | None = None,
    ) -> PolicyMergeResult:
        """Offline merge of org base + tenant overlay into an effective v1 policy."""
        base_doc = cls._load_document_source(base)
        overlay_doc = cls._load_document_source(overlay)
        if not isinstance(overlay_doc, PaybondPolicyDocumentV2) or not is_paybond_policy_overlay(overlay_doc):
            raise ValueError("overlay must be a v2 tenant policy with extends")
        return merge_paybond_policies(base_doc, overlay_doc, options=options)

    @classmethod
    async def load_effective(
        cls,
        *,
        overlay: PaybondPolicyLoadSource,
        gateway: PolicyEffectiveResolveClient,
    ) -> tuple[PaybondPolicy, PolicyEffectiveResolveResult]:
        """Resolve merged effective policy via Gateway org-policy inheritance."""
        overlay_payload = cls._load_overlay_payload(overlay)
        document = parse_paybond_policy_document(overlay_payload)
        if not isinstance(document, PaybondPolicyDocumentV2) or not is_paybond_policy_overlay(document):
            raise ValueError("overlay must be a v2 tenant policy with extends")
        resolved = await resolve_policy_effective_remote(overlay_payload, gateway)
        effective = parse_paybond_policy_document_v1(resolved.effective_policy)
        source = str(overlay) if isinstance(overlay, (str, Path)) else None
        return cls(effective, source=source), resolved

    @classmethod
    def _load_overlay_payload(cls, source: PaybondPolicyLoadSource) -> dict[str, Any]:
        if isinstance(source, (str, Path)):
            path = Path(source)
            text = path.read_text(encoding="utf-8")
            raw = parse_policy_document_text(text, str(path))
            if not isinstance(raw, dict):
                raise ValueError("overlay must be a JSON or YAML object")
            return raw
        if isinstance(source, dict):
            return source
        if isinstance(source, PaybondPolicyDocumentV2):
            raise ValueError("load_effective requires a file path or raw overlay dict")
        raise ValueError("overlay must be a v2 tenant policy with extends")

    @classmethod
    def _load_document_source(cls, source: PaybondPolicyLoadSource) -> PaybondPolicyDocument:
        if isinstance(source, (str, Path)):
            return cls._load_document(Path(source))
        if isinstance(source, PaybondPolicyDocumentV1):
            return source
        if isinstance(source, PaybondPolicyDocumentV2):
            return source
        return parse_paybond_policy_document(source)

    @classmethod
    def _load_document(cls, path: Path) -> PaybondPolicyDocument:
        text = path.read_text(encoding="utf-8")
        raw = parse_policy_document_text(text, str(path))
        return parse_paybond_policy_document(raw)

    @classmethod
    def _resolve_effective_document(
        cls,
        document: PaybondPolicyDocument,
        *,
        source_path: Path | None = None,
    ) -> PaybondPolicyDocumentV1:
        if isinstance(document, PaybondPolicyDocumentV2) and is_paybond_policy_overlay(document):
            base_path = document.extends.base_policy if document.extends else None
            if base_path and source_path is not None:
                resolved_base = (source_path.parent / base_path).resolve()
                base_doc = cls._load_document(resolved_base)
                return merge_paybond_policies(base_doc, document).effective
            return to_effective_policy_document(document)
        return to_effective_policy_document(document)

    @classmethod
    def from_document(cls, document: PaybondPolicyDocumentV1) -> PaybondPolicy:
        """Construct from an already-validated policy document."""
        return cls(document)

    def to_tool_registry(self) -> PaybondToolRegistry:
        """Build the tool registry consumed by agent middleware."""
        return policy_to_tool_registry(self.document)

    def to_intent_create_input(
        self,
        *,
        principal_did: str,
        principal_signing_seed: bytes,
        payee_did: str,
        payee_signing_seed: bytes,
        deadline_rfc3339: str,
        settlement_rail: str,
        recognition_proof: dict[str, object],
        materialized_predicate: dict[str, object],
        policy_template_id: str,
        policy_version_seq: int,
        policy_content_digest_hex: str,
        intent_id: str | None = None,
        predicate_ref: str = "",
        amount_cents: int | None = None,
        currency: str | None = None,
        budget: dict[str, object] | None = None,
        allowed_tools: list[str] | None = None,
        completion_preset_id: str | None = None,
        evidence_schema: dict[str, object] | None = None,
    ) -> PaybondPolicyIntentCreateInput:
        """Build kwargs for :meth:`PaybondIntents.create_with_policy_binding` from policy alignment."""
        return policy_to_intent_create_input(
            self.document,
            principal_did=principal_did,
            principal_signing_seed=principal_signing_seed,
            payee_did=payee_did,
            payee_signing_seed=payee_signing_seed,
            deadline_rfc3339=deadline_rfc3339,
            settlement_rail=settlement_rail,  # type: ignore[arg-type]
            recognition_proof=recognition_proof,
            materialized_predicate=materialized_predicate,
            policy_template_id=policy_template_id,
            policy_version_seq=policy_version_seq,
            policy_content_digest_hex=policy_content_digest_hex,
            intent_id=intent_id,
            predicate_ref=predicate_ref,
            amount_cents=amount_cents,
            currency=currency,
            budget=budget,
            allowed_tools=allowed_tools,
            completion_preset_id=completion_preset_id,
            evidence_schema=evidence_schema,
        )

    def validate(self, options: PolicyValidatorOptions | None = None) -> PolicyValidatorResult:
        """Run client-side alignment checks (registry, presets, optional gateway template lookup)."""
        return PolicyValidator.validate_document(self.document, options)

    async def validate_remote(
        self,
        gateway: PolicyRemoteValidateClient,
        *,
        options: PolicyRemoteValidateOptions | None = None,
    ) -> PolicyRemoteValidateResult:
        """Validate against the tenant-scoped Gateway registry (POST /v1/policy/validate)."""
        return await validate_policy_remote(self.document, gateway, options=options)

    @classmethod
    async def validate_overlay_remote(
        cls,
        overlay: PaybondPolicyLoadSource,
        gateway: PolicyRemoteValidateClient,
        *,
        options: PolicyRemoteValidateOptions | None = None,
    ) -> PolicyRemoteValidateResult:
        """Validate a tenant overlay with server-side org-base merge."""
        overlay_payload = cls._load_overlay_payload(overlay)
        merged_options = PolicyRemoteValidateOptions(
            strict=options.strict if options is not None else None,
            resolve_inheritance=True,
        )
        return await validate_policy_payload_remote(overlay_payload, gateway, options=merged_options)

    def sandbox_bootstrap(
        self,
        options: PaybondPolicySandboxBootstrapOptions | None = None,
    ) -> PaybondRunBindingSandboxBootstrapInput:
        """Build sandbox bootstrap input for :meth:`PaybondAgentRun.bind` from this policy."""
        return policy_sandbox_bootstrap(self.document, options)
