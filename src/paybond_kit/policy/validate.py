"""Client-side paybond.policy.yaml alignment checks."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol

from paybond_kit.completion_catalog import get_completion_preset, list_completion_preset_ids
from paybond_kit.completion_resolve import is_vendor_pack
from paybond_kit.policy.schema import PaybondPolicyDocumentV1, PaybondPolicyValidationError


@dataclass(frozen=True, slots=True)
class PolicyValidatorError:
    path: str
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class PolicyValidatorToolCounts:
    side_effecting: int
    read_only: int


@dataclass(frozen=True, slots=True)
class PolicyValidatorResult:
    valid: bool
    policy_name: str | None
    tools: PolicyValidatorToolCounts
    errors: tuple[PolicyValidatorError, ...]


class PolicyGatewayTemplateLookup(Protocol):
    def list_template_ids(self) -> list[str]:
        """Return Harbor managed policy template ids."""
        ...


@dataclass(frozen=True, slots=True)
class PolicyValidatorOptions:
    strict: bool | None = None
    check_gateway: bool = False
    gateway: PolicyGatewayTemplateLookup | None = None


def _push_error(errors: list[PolicyValidatorError], path: str, code: str, message: str) -> None:
    errors.append(PolicyValidatorError(path=path, code=code, message=message))


def _count_tools(document: PaybondPolicyDocumentV1) -> PolicyValidatorToolCounts:
    side_effecting = 0
    read_only = 0
    for entry in document.tools.values():
        if entry.side_effecting:
            side_effecting += 1
        else:
            read_only += 1
    return PolicyValidatorToolCounts(side_effecting=side_effecting, read_only=read_only)


def _catalog_has_preset(preset_id: str) -> bool:
    return preset_id in list_completion_preset_ids()


def _validate_preset_reference(errors: list[PolicyValidatorError], tool_name: str, preset_id: str) -> None:
    if not _catalog_has_preset(preset_id):
        _push_error(
            errors,
            f"tools.{tool_name}.evidence_preset",
            "policy.unknown_evidence_preset",
            f"unknown completion preset: {preset_id}",
        )
        return
    try:
        get_completion_preset(preset_id)
    except ValueError:
        _push_error(
            errors,
            f"tools.{tool_name}.evidence_preset",
            "policy.unknown_evidence_preset",
            f"unknown completion preset: {preset_id}",
        )


def _validate_vendor_pack_reference(errors: list[PolicyValidatorError], tool_name: str, vendor_pack_id: str) -> None:
    try:
        preset = get_completion_preset(vendor_pack_id)
    except ValueError:
        _push_error(
            errors,
            f"tools.{tool_name}.vendor_pack",
            "policy.unknown_vendor_pack",
            f"unknown vendor pack preset: {vendor_pack_id}",
        )
        return
    if not is_vendor_pack(preset):
        _push_error(
            errors,
            f"tools.{tool_name}.vendor_pack",
            "policy.invalid_vendor_pack",
            f"preset {vendor_pack_id} is not a vendor_pack entry",
        )


def _validate_intent_alignment(
    document: PaybondPolicyDocumentV1,
    errors: list[PolicyValidatorError],
    *,
    strict: bool,
) -> None:
    intent = document.intent
    if intent is None or not intent.allowed_tools:
        return

    registered = set(document.tools.keys())
    for tool_name in intent.allowed_tools:
        if tool_name not in registered:
            _push_error(
                errors,
                "intent.allowed_tools",
                "policy.allowed_tool_not_registered",
                f'allowed tool "{tool_name}" is not declared in tools',
            )

    if not strict or not document.default_deny:
        return

    allowed = set(intent.allowed_tools)
    for tool_name, entry in document.tools.items():
        if entry.side_effecting and tool_name not in allowed:
            _push_error(
                errors,
                f"tools.{tool_name}",
                "policy.side_effecting_not_allowed",
                f'side-effecting tool "{tool_name}" is missing from intent.allowed_tools (default_deny is true)',
            )


def _validate_tool_entries(document: PaybondPolicyDocumentV1, errors: list[PolicyValidatorError]) -> None:
    for tool_name, entry in document.tools.items():
        if entry.side_effecting:
            if not entry.evidence_preset:
                _push_error(
                    errors,
                    f"tools.{tool_name}.evidence_preset",
                    "policy.missing_evidence_preset",
                    "side-effecting tools must declare evidence_preset",
                )
            elif entry.evidence_preset:
                _validate_preset_reference(errors, tool_name, entry.evidence_preset)
        elif entry.evidence_preset:
            _validate_preset_reference(errors, tool_name, entry.evidence_preset)

        if entry.vendor_pack:
            _validate_vendor_pack_reference(errors, tool_name, entry.vendor_pack)


def _validate_gateway_template(
    document: PaybondPolicyDocumentV1,
    errors: list[PolicyValidatorError],
    gateway: PolicyGatewayTemplateLookup,
) -> None:
    intent = document.intent
    if intent is None or intent.policy_binding is None:
        return
    template_id = intent.policy_binding.template_id
    if template_id not in gateway.list_template_ids():
        _push_error(
            errors,
            "intent.policy_binding.template_id",
            "policy.unknown_policy_template",
            f'policy template "{template_id}" was not found in the Harbor catalog',
        )


def _validate_document_sync(document: PaybondPolicyDocumentV1, options: PolicyValidatorOptions) -> PolicyValidatorResult:
    strict = options.strict if options.strict is not None else PolicyValidator.is_strict_from_env()
    errors: list[PolicyValidatorError] = []
    _validate_tool_entries(document, errors)
    _validate_intent_alignment(document, errors, strict=strict)
    return PolicyValidatorResult(
        valid=len(errors) == 0,
        policy_name=document.name,
        tools=_count_tools(document),
        errors=tuple(errors),
    )


def policy_validator_result_to_dict(result: PolicyValidatorResult) -> dict[str, Any]:
    return {
        "valid": result.valid,
        "policy_name": result.policy_name,
        "tools": {
            "side_effecting": result.tools.side_effecting,
            "read_only": result.tools.read_only,
        },
        "errors": [
            {"path": issue.path, "code": issue.code, "message": issue.message}
            for issue in result.errors
        ],
    }


class PolicyValidator:
    """Client-side policy alignment checks before deploy or agent bind."""

    @staticmethod
    def is_strict_from_env() -> bool:
        return os.environ.get("PAYBOND_POLICY_STRICT") == "1"

    @classmethod
    def validate(cls, source: object, options: PolicyValidatorOptions | None = None) -> PolicyValidatorResult:
        from paybond_kit.policy.load import PaybondPolicy

        opts = options or PolicyValidatorOptions()
        try:
            policy = PaybondPolicy.load(source)  # type: ignore[arg-type]
            return cls.validate_document(policy.document, opts)
        except PaybondPolicyValidationError as exc:
            return PolicyValidatorResult(
                valid=False,
                policy_name=None,
                tools=PolicyValidatorToolCounts(side_effecting=0, read_only=0),
                errors=(
                    PolicyValidatorError(
                        path=exc.path,
                        code="policy.schema_invalid",
                        message=str(exc),
                    ),
                ),
            )

    @classmethod
    def validate_document(
        cls,
        document: PaybondPolicyDocumentV1,
        options: PolicyValidatorOptions | None = None,
    ) -> PolicyValidatorResult:
        opts = options or PolicyValidatorOptions()
        result = _validate_document_sync(document, opts)
        if opts.check_gateway and opts.gateway is not None:
            errors = list(result.errors)
            _validate_gateway_template(document, errors, opts.gateway)
            return PolicyValidatorResult(
                valid=len(errors) == 0,
                policy_name=result.policy_name,
                tools=result.tools,
                errors=tuple(errors),
            )
        return result
