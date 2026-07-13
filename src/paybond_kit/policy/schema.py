"""paybond.policy.yaml v1 schema — dataclasses and JSON Schema validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

PAYBOND_POLICY_SCHEMA_VERSION: Final = 1
PAYBOND_POLICY_SCHEMA_VERSION_V2: Final = 2

_IDENTIFIER_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_POLICY_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_JSON_PATH_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.]*$")
_HEAD_DIGEST_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
_CURRENCY_RE = re.compile(r"^[a-z]{3}$")
_ORG_ID_RE = re.compile(r"^org_[a-z][a-z0-9_]{0,57}$")

_BUNDLED_SCHEMA = (
    Path(__file__).resolve().parent.parent / "data" / "policy" / "policy.schema.json"
)
_REPO_SCHEMA = Path(__file__).resolve().parents[4] / "policy" / "policy.schema.json"


class PaybondPolicyValidationError(ValueError):
    """Raised when a policy document fails schema validation."""

    def __init__(self, message: str, *, path: str = "(root)") -> None:
        self.path = path
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class PaybondPolicyToolEntry:
    side_effecting: bool
    max_spend_cents: int | None = None
    spend_from_args: str | None = None
    evidence_preset: str | None = None
    vendor_pack: str | None = None
    operation: str | None = None


@dataclass(frozen=True, slots=True)
class PaybondPolicyBinding:
    template_id: str
    version_seq: int | None = None
    head_digest: str | None = None


@dataclass(frozen=True, slots=True)
class PaybondPolicyIntentSection:
    policy_binding: PaybondPolicyBinding | None = None
    budget: dict[str, Any] | None = None
    allowed_tools: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PaybondPolicyAdapterSection:
    deny_provider_executed_tools: bool | None = None


@dataclass(frozen=True, slots=True)
class PaybondPolicyDocumentV1:
    version: Literal[1]
    name: str
    default_deny: bool
    tools: dict[str, PaybondPolicyToolEntry]
    intent: PaybondPolicyIntentSection | None = None
    adapter: PaybondPolicyAdapterSection | None = None


@dataclass(frozen=True, slots=True)
class PaybondPolicyToolOverrideEntry:
    side_effecting: bool | None = None
    max_spend_cents: int | None = None
    spend_from_args: str | None = None
    evidence_preset: str | None = None
    vendor_pack: str | None = None
    operation: str | None = None


@dataclass(frozen=True, slots=True)
class PaybondPolicyBindingOverride:
    template_id: str | None = None
    version_seq: int | None = None
    head_digest: str | None = None


@dataclass(frozen=True, slots=True)
class PaybondPolicyIntentOverrideSection:
    policy_binding: PaybondPolicyBindingOverride | None = None
    budget: dict[str, Any] | None = None
    allowed_tools: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PaybondPolicyExtends:
    org_policy_id: str
    org_id: str
    base_digest: str | None = None
    base_policy: str | None = None


@dataclass(frozen=True, slots=True)
class PaybondPolicyOverrides:
    default_deny: bool | None = None
    tools: dict[str, PaybondPolicyToolOverrideEntry] | None = None
    intent: PaybondPolicyIntentOverrideSection | None = None
    adapter: PaybondPolicyAdapterSection | None = None


@dataclass(frozen=True, slots=True)
class PaybondPolicyDocumentV2:
    version: Literal[2]
    name: str
    default_deny: bool
    tools: dict[str, PaybondPolicyToolEntry]
    extends: PaybondPolicyExtends | None = None
    overrides: PaybondPolicyOverrides | None = None
    intent: PaybondPolicyIntentSection | None = None
    adapter: PaybondPolicyAdapterSection | None = None


PaybondPolicyDocument = PaybondPolicyDocumentV1 | PaybondPolicyDocumentV2


def policy_schema_path() -> Path:
    """Return the bundled JSON Schema path (falls back to repo copy in dev trees)."""
    if _BUNDLED_SCHEMA.is_file():
        return _BUNDLED_SCHEMA
    return _REPO_SCHEMA


def load_policy_json_schema() -> dict[str, Any]:
    """Load the canonical paybond.policy.yaml v1 JSON Schema."""
    return json.loads(policy_schema_path().read_text(encoding="utf-8"))


def _expect_mapping(raw: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PaybondPolicyValidationError(f"{path} must be an object", path=path)
    return raw


def _expect_bool(raw: Any, *, path: str) -> bool:
    if not isinstance(raw, bool):
        raise PaybondPolicyValidationError(f"{path} must be a boolean", path=path)
    return raw


def _expect_int(raw: Any, *, path: str, minimum: int | None = None) -> int:
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise PaybondPolicyValidationError(f"{path} must be an integer", path=path)
    if minimum is not None and raw < minimum:
        raise PaybondPolicyValidationError(f"{path} must be >= {minimum}", path=path)
    return raw


def _expect_str(raw: Any, *, path: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise PaybondPolicyValidationError(f"{path} must be a non-empty string", path=path)
    return raw


def _parse_tool_entry(raw: Any, *, path: str) -> PaybondPolicyToolEntry:
    entry = _expect_mapping(raw, path=path)
    unknown = set(entry) - {
        "side_effecting",
        "max_spend_cents",
        "spend_from_args",
        "evidence_preset",
        "vendor_pack",
        "operation",
    }
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"{path} has unknown fields: {joined}", path=path)

    side_effecting = _expect_bool(entry.get("side_effecting"), path=f"{path}.side_effecting")

    max_spend_cents: int | None = None
    if "max_spend_cents" in entry:
        max_spend_cents = _expect_int(entry["max_spend_cents"], path=f"{path}.max_spend_cents", minimum=0)

    spend_from_args: str | None = None
    if "spend_from_args" in entry:
        spend_from_args = _expect_str(entry["spend_from_args"], path=f"{path}.spend_from_args")
        if not _JSON_PATH_RE.fullmatch(spend_from_args):
            raise PaybondPolicyValidationError(
                f"{path}.spend_from_args must be a dot-separated JSON path",
                path=f"{path}.spend_from_args",
            )

    if max_spend_cents is not None and spend_from_args is not None:
        raise PaybondPolicyValidationError(
            f"{path}: max_spend_cents and spend_from_args are mutually exclusive",
            path=path,
        )

    evidence_preset: str | None = None
    if "evidence_preset" in entry:
        evidence_preset = _expect_str(entry["evidence_preset"], path=f"{path}.evidence_preset")
        if not _IDENTIFIER_RE.fullmatch(evidence_preset):
            raise PaybondPolicyValidationError(
                f"{path}.evidence_preset must be a snake_case identifier",
                path=f"{path}.evidence_preset",
            )

    if side_effecting and not evidence_preset:
        raise PaybondPolicyValidationError(
            f"{path}: side-effecting tools must declare evidence_preset",
            path=f"{path}.evidence_preset",
        )

    vendor_pack: str | None = None
    if "vendor_pack" in entry:
        vendor_pack = _expect_str(entry["vendor_pack"], path=f"{path}.vendor_pack")
        if not _IDENTIFIER_RE.fullmatch(vendor_pack):
            raise PaybondPolicyValidationError(
                f"{path}.vendor_pack must be a snake_case identifier",
                path=f"{path}.vendor_pack",
            )

    operation: str | None = None
    if "operation" in entry:
        operation = _expect_str(entry["operation"], path=f"{path}.operation")
        if len(operation) > 128:
            raise PaybondPolicyValidationError(
                f"{path}.operation must be at most 128 characters",
                path=f"{path}.operation",
            )

    return PaybondPolicyToolEntry(
        side_effecting=side_effecting,
        max_spend_cents=max_spend_cents,
        spend_from_args=spend_from_args,
        evidence_preset=evidence_preset,
        vendor_pack=vendor_pack,
        operation=operation,
    )


def _parse_policy_binding(raw: Any, *, path: str) -> PaybondPolicyBinding:
    binding = _expect_mapping(raw, path=path)
    unknown = set(binding) - {"template_id", "version_seq", "head_digest"}
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"{path} has unknown fields: {joined}", path=path)

    template_id = _expect_str(binding.get("template_id"), path=f"{path}.template_id")
    if not _IDENTIFIER_RE.fullmatch(template_id):
        raise PaybondPolicyValidationError(
            f"{path}.template_id must be a snake_case identifier",
            path=f"{path}.template_id",
        )

    version_seq: int | None = None
    if "version_seq" in binding:
        version_seq = _expect_int(binding["version_seq"], path=f"{path}.version_seq", minimum=1)

    head_digest: str | None = None
    if "head_digest" in binding:
        head_digest = _expect_str(binding["head_digest"], path=f"{path}.head_digest")
        if not _HEAD_DIGEST_RE.fullmatch(head_digest):
            raise PaybondPolicyValidationError(
                f"{path}.head_digest must be sha256:<64-hex>",
                path=f"{path}.head_digest",
            )

    return PaybondPolicyBinding(
        template_id=template_id,
        version_seq=version_seq,
        head_digest=head_digest,
    )


def _parse_budget(raw: Any, *, path: str) -> dict[str, Any]:
    budget = _expect_mapping(raw, path=path)
    currency_raw = budget.get("currency")
    currency = _expect_str(currency_raw, path=f"{path}.currency")
    if not _CURRENCY_RE.fullmatch(currency):
        raise PaybondPolicyValidationError(
            f"{path}.currency must be a lowercase ISO-4217 code",
            path=f"{path}.currency",
        )
    if "max_spend_usd" in budget and not isinstance(budget["max_spend_usd"], (int, float)):
        raise PaybondPolicyValidationError(
            f"{path}.max_spend_usd must be a number",
            path=f"{path}.max_spend_usd",
        )
    if isinstance(budget.get("max_spend_usd"), (int, float)) and budget["max_spend_usd"] < 0:
        raise PaybondPolicyValidationError(
            f"{path}.max_spend_usd must be >= 0",
            path=f"{path}.max_spend_usd",
        )
    return dict(budget)


def _parse_intent(raw: Any, *, path: str) -> PaybondPolicyIntentSection:
    intent = _expect_mapping(raw, path=path)
    unknown = set(intent) - {"policy_binding", "budget", "allowed_tools"}
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"{path} has unknown fields: {joined}", path=path)

    policy_binding = None
    if "policy_binding" in intent:
        policy_binding = _parse_policy_binding(intent["policy_binding"], path=f"{path}.policy_binding")

    budget = None
    if "budget" in intent:
        budget = _parse_budget(intent["budget"], path=f"{path}.budget")

    allowed_tools: list[str] = []
    if "allowed_tools" in intent:
        tools_raw = intent["allowed_tools"]
        if not isinstance(tools_raw, list):
            raise PaybondPolicyValidationError(f"{path}.allowed_tools must be an array", path=f"{path}.allowed_tools")
        seen: set[str] = set()
        for index, item in enumerate(tools_raw):
            item_path = f"{path}.allowed_tools[{index}]"
            tool_name = _expect_str(item, path=item_path)
            if not _TOOL_NAME_RE.fullmatch(tool_name):
                raise PaybondPolicyValidationError(
                    f"{item_path} must be a lowercase tool name",
                    path=item_path,
                )
            if tool_name in seen:
                raise PaybondPolicyValidationError(
                    f"{path}.allowed_tools must be unique",
                    path=f"{path}.allowed_tools",
                )
            seen.add(tool_name)
            allowed_tools.append(tool_name)

    return PaybondPolicyIntentSection(
        policy_binding=policy_binding,
        budget=budget,
        allowed_tools=tuple(allowed_tools),
    )


def _parse_tool_override_entry(raw: Any, *, path: str) -> PaybondPolicyToolOverrideEntry:
    entry = _expect_mapping(raw, path=path)
    unknown = set(entry) - {
        "side_effecting",
        "max_spend_cents",
        "spend_from_args",
        "evidence_preset",
        "vendor_pack",
        "operation",
    }
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"{path} has unknown fields: {joined}", path=path)
    if not entry:
        raise PaybondPolicyValidationError(f"{path} must set at least one field", path=path)

    side_effecting = None
    if "side_effecting" in entry:
        side_effecting = _expect_bool(entry["side_effecting"], path=f"{path}.side_effecting")

    max_spend_cents: int | None = None
    if "max_spend_cents" in entry:
        max_spend_cents = _expect_int(entry["max_spend_cents"], path=f"{path}.max_spend_cents", minimum=0)

    spend_from_args: str | None = None
    if "spend_from_args" in entry:
        spend_from_args = _expect_str(entry["spend_from_args"], path=f"{path}.spend_from_args")
        if not _JSON_PATH_RE.fullmatch(spend_from_args):
            raise PaybondPolicyValidationError(
                f"{path}.spend_from_args must be a dot-separated JSON path",
                path=f"{path}.spend_from_args",
            )

    if max_spend_cents is not None and spend_from_args is not None:
        raise PaybondPolicyValidationError(
            f"{path}: max_spend_cents and spend_from_args are mutually exclusive",
            path=path,
        )

    evidence_preset: str | None = None
    if "evidence_preset" in entry:
        evidence_preset = _expect_str(entry["evidence_preset"], path=f"{path}.evidence_preset")
        if not _IDENTIFIER_RE.fullmatch(evidence_preset):
            raise PaybondPolicyValidationError(
                f"{path}.evidence_preset must be a snake_case identifier",
                path=f"{path}.evidence_preset",
            )

    vendor_pack: str | None = None
    if "vendor_pack" in entry:
        vendor_pack = _expect_str(entry["vendor_pack"], path=f"{path}.vendor_pack")
        if not _IDENTIFIER_RE.fullmatch(vendor_pack):
            raise PaybondPolicyValidationError(
                f"{path}.vendor_pack must be a snake_case identifier",
                path=f"{path}.vendor_pack",
            )

    operation: str | None = None
    if "operation" in entry:
        operation = _expect_str(entry["operation"], path=f"{path}.operation")
        if len(operation) > 128:
            raise PaybondPolicyValidationError(
                f"{path}.operation must be at most 128 characters",
                path=f"{path}.operation",
            )

    if side_effecting and not evidence_preset:
        raise PaybondPolicyValidationError(
            f"{path}: side-effecting tools must declare evidence_preset",
            path=f"{path}.evidence_preset",
        )

    return PaybondPolicyToolOverrideEntry(
        side_effecting=side_effecting,
        max_spend_cents=max_spend_cents,
        spend_from_args=spend_from_args,
        evidence_preset=evidence_preset,
        vendor_pack=vendor_pack,
        operation=operation,
    )


def _parse_policy_binding_override(raw: Any, *, path: str) -> PaybondPolicyBindingOverride:
    binding = _expect_mapping(raw, path=path)
    unknown = set(binding) - {"template_id", "version_seq", "head_digest"}
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"{path} has unknown fields: {joined}", path=path)
    if not binding:
        raise PaybondPolicyValidationError(f"{path} must set at least one field", path=path)

    template_id: str | None = None
    if "template_id" in binding:
        template_id = _expect_str(binding["template_id"], path=f"{path}.template_id")
        if not _IDENTIFIER_RE.fullmatch(template_id):
            raise PaybondPolicyValidationError(
                f"{path}.template_id must be a snake_case identifier",
                path=f"{path}.template_id",
            )

    version_seq: int | None = None
    if "version_seq" in binding:
        version_seq = _expect_int(binding["version_seq"], path=f"{path}.version_seq", minimum=1)

    head_digest: str | None = None
    if "head_digest" in binding:
        head_digest = _expect_str(binding["head_digest"], path=f"{path}.head_digest")
        if not _HEAD_DIGEST_RE.fullmatch(head_digest):
            raise PaybondPolicyValidationError(
                f"{path}.head_digest must be sha256:<64-hex>",
                path=f"{path}.head_digest",
            )

    return PaybondPolicyBindingOverride(
        template_id=template_id,
        version_seq=version_seq,
        head_digest=head_digest,
    )


def _parse_intent_override(raw: Any, *, path: str) -> PaybondPolicyIntentOverrideSection:
    intent = _expect_mapping(raw, path=path)
    unknown = set(intent) - {"policy_binding", "budget", "allowed_tools"}
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"{path} has unknown fields: {joined}", path=path)
    if not intent:
        raise PaybondPolicyValidationError(f"{path} must set at least one field", path=path)

    policy_binding = None
    if "policy_binding" in intent:
        policy_binding = _parse_policy_binding_override(
            intent["policy_binding"],
            path=f"{path}.policy_binding",
        )

    budget = None
    if "budget" in intent:
        budget = _parse_budget(intent["budget"], path=f"{path}.budget")

    allowed_tools: list[str] = []
    if "allowed_tools" in intent:
        tools_raw = intent["allowed_tools"]
        if not isinstance(tools_raw, list):
            raise PaybondPolicyValidationError(f"{path}.allowed_tools must be an array", path=f"{path}.allowed_tools")
        seen: set[str] = set()
        for index, item in enumerate(tools_raw):
            item_path = f"{path}.allowed_tools[{index}]"
            tool_name = _expect_str(item, path=item_path)
            if not _TOOL_NAME_RE.fullmatch(tool_name):
                raise PaybondPolicyValidationError(
                    f"{item_path} must be a lowercase tool name",
                    path=item_path,
                )
            if tool_name in seen:
                raise PaybondPolicyValidationError(
                    f"{path}.allowed_tools must be unique",
                    path=f"{path}.allowed_tools",
                )
            seen.add(tool_name)
            allowed_tools.append(tool_name)

    return PaybondPolicyIntentOverrideSection(
        policy_binding=policy_binding,
        budget=budget,
        allowed_tools=tuple(allowed_tools),
    )


def _parse_extends(raw: Any, *, path: str) -> PaybondPolicyExtends:
    extends = _expect_mapping(raw, path=path)
    unknown = set(extends) - {"org_policy_id", "org_id", "base_digest", "base_policy"}
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"{path} has unknown fields: {joined}", path=path)

    org_policy_id = _expect_str(extends.get("org_policy_id"), path=f"{path}.org_policy_id")
    if not _POLICY_NAME_RE.fullmatch(org_policy_id):
        raise PaybondPolicyValidationError(
            f"{path}.org_policy_id must be a lowercase policy name",
            path=f"{path}.org_policy_id",
        )

    org_id = _expect_str(extends.get("org_id"), path=f"{path}.org_id")
    if not _ORG_ID_RE.fullmatch(org_id):
        raise PaybondPolicyValidationError(
            f"{path}.org_id must be an org identifier (org_<snake_case>)",
            path=f"{path}.org_id",
        )

    base_digest: str | None = None
    if "base_digest" in extends:
        base_digest = _expect_str(extends["base_digest"], path=f"{path}.base_digest")
        if not _HEAD_DIGEST_RE.fullmatch(base_digest):
            raise PaybondPolicyValidationError(
                f"{path}.base_digest must be sha256:<64-hex>",
                path=f"{path}.base_digest",
            )

    base_policy: str | None = None
    if "base_policy" in extends:
        base_policy = _expect_str(extends["base_policy"], path=f"{path}.base_policy")
        if len(base_policy) > 512:
            raise PaybondPolicyValidationError(
                f"{path}.base_policy must be at most 512 characters",
                path=f"{path}.base_policy",
            )

    return PaybondPolicyExtends(
        org_policy_id=org_policy_id,
        org_id=org_id,
        base_digest=base_digest,
        base_policy=base_policy,
    )


def _parse_adapter(raw: Any, *, path: str) -> PaybondPolicyAdapterSection:
    adapter = _expect_mapping(raw, path=path)
    unknown = set(adapter) - {"deny_provider_executed_tools"}
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"{path} has unknown fields: {joined}", path=path)

    deny_provider_executed_tools: bool | None = None
    if "deny_provider_executed_tools" in adapter:
        deny_provider_executed_tools = _expect_bool(
            adapter["deny_provider_executed_tools"],
            path=f"{path}.deny_provider_executed_tools",
        )

    if deny_provider_executed_tools is None:
        raise PaybondPolicyValidationError(f"{path} must set at least one field", path=path)

    return PaybondPolicyAdapterSection(
        deny_provider_executed_tools=deny_provider_executed_tools,
    )


def _parse_overrides(raw: Any, *, path: str) -> PaybondPolicyOverrides:
    overrides = _expect_mapping(raw, path=path)
    unknown = set(overrides) - {"default_deny", "tools", "intent", "adapter"}
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"{path} has unknown fields: {joined}", path=path)

    default_deny: bool | None = None
    if "default_deny" in overrides:
        default_deny = _expect_bool(overrides["default_deny"], path=f"{path}.default_deny")

    tools: dict[str, PaybondPolicyToolOverrideEntry] | None = None
    if "tools" in overrides:
        tools_raw = overrides["tools"]
        if not isinstance(tools_raw, dict) or not tools_raw:
            raise PaybondPolicyValidationError(f"{path}.tools must declare at least one entry", path=f"{path}.tools")
        tools = {}
        for tool_name, entry_raw in tools_raw.items():
            if not isinstance(tool_name, str) or not _TOOL_NAME_RE.fullmatch(tool_name):
                raise PaybondPolicyValidationError(
                    f'{path}.tools key "{tool_name}" must be a lowercase tool name',
                    path=f"{path}.tools",
                )
            tools[tool_name] = _parse_tool_override_entry(entry_raw, path=f"{path}.tools.{tool_name}")

    intent = None
    if "intent" in overrides:
        intent = _parse_intent_override(overrides["intent"], path=f"{path}.intent")

    adapter = None
    if "adapter" in overrides:
        adapter = _parse_adapter(overrides["adapter"], path=f"{path}.adapter")

    if default_deny is None and not tools and intent is None and adapter is None:
        raise PaybondPolicyValidationError(
            f"{path} must set default_deny, tools, intent, and/or adapter",
            path=path,
        )

    return PaybondPolicyOverrides(
        default_deny=default_deny,
        tools=tools,
        intent=intent,
        adapter=adapter,
    )


def _parse_tools_map(raw: Any, *, path: str, min_entries: int) -> dict[str, PaybondPolicyToolEntry]:
    if not isinstance(raw, dict):
        raise PaybondPolicyValidationError(f"{path} must be an object", path=path)
    if len(raw) < min_entries:
        raise PaybondPolicyValidationError(
            f"{path} must declare at least {min_entries} entr{'y' if min_entries == 1 else 'ies'}",
            path=path,
        )

    tools: dict[str, PaybondPolicyToolEntry] = {}
    for tool_name, entry_raw in raw.items():
        if not isinstance(tool_name, str) or not _TOOL_NAME_RE.fullmatch(tool_name):
            raise PaybondPolicyValidationError(
                f'{path} key "{tool_name}" must be a lowercase tool name',
                path=path,
            )
        tools[tool_name] = _parse_tool_entry(entry_raw, path=f"{path}.{tool_name}")
    return tools


def parse_paybond_policy_document_v1(raw: Any) -> PaybondPolicyDocumentV1:
    """Parse and validate a v1 policy document."""
    doc = _expect_mapping(raw, path="(root)")
    unknown = set(doc) - {"version", "name", "default_deny", "tools", "intent", "adapter", "$schema"}
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"(root) has unknown fields: {joined}", path="(root)")

    version = doc.get("version")
    if version != PAYBOND_POLICY_SCHEMA_VERSION:
        raise PaybondPolicyValidationError(
            f"version must be {PAYBOND_POLICY_SCHEMA_VERSION}",
            path="version",
        )

    name = _expect_str(doc.get("name"), path="name")
    if not _POLICY_NAME_RE.fullmatch(name):
        raise PaybondPolicyValidationError("name must be a lowercase policy name", path="name")

    default_deny = _expect_bool(doc.get("default_deny"), path="default_deny")
    tools = _parse_tools_map(doc.get("tools"), path="tools", min_entries=1)

    intent = None
    if "intent" in doc:
        intent = _parse_intent(doc["intent"], path="intent")

    adapter = None
    if "adapter" in doc:
        adapter = _parse_adapter(doc["adapter"], path="adapter")

    return PaybondPolicyDocumentV1(
        version=PAYBOND_POLICY_SCHEMA_VERSION,
        name=name,
        default_deny=default_deny,
        tools=tools,
        intent=intent,
        adapter=adapter,
    )


def parse_paybond_policy_document_v2(raw: Any) -> PaybondPolicyDocumentV2:
    """Parse and validate a v2 org-base or tenant-overlay policy document."""
    doc = _expect_mapping(raw, path="(root)")
    unknown = set(doc) - {
        "version",
        "name",
        "default_deny",
        "tools",
        "intent",
        "adapter",
        "extends",
        "overrides",
        "$schema",
    }
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise PaybondPolicyValidationError(f"(root) has unknown fields: {joined}", path="(root)")

    version = doc.get("version")
    if version != PAYBOND_POLICY_SCHEMA_VERSION_V2:
        raise PaybondPolicyValidationError(
            f"version must be {PAYBOND_POLICY_SCHEMA_VERSION_V2}",
            path="version",
        )

    name = _expect_str(doc.get("name"), path="name")
    if not _POLICY_NAME_RE.fullmatch(name):
        raise PaybondPolicyValidationError("name must be a lowercase policy name", path="name")

    default_deny = _expect_bool(doc.get("default_deny"), path="default_deny")

    extends = None
    if "extends" in doc:
        extends = _parse_extends(doc["extends"], path="extends")

    overrides = None
    if "overrides" in doc:
        overrides = _parse_overrides(doc["overrides"], path="overrides")

    min_tools = 0 if extends is not None else 1
    tools = _parse_tools_map(doc.get("tools"), path="tools", min_entries=min_tools)

    intent = None
    if "intent" in doc:
        intent = _parse_intent(doc["intent"], path="intent")

    adapter = None
    if "adapter" in doc:
        adapter = _parse_adapter(doc["adapter"], path="adapter")

    return PaybondPolicyDocumentV2(
        version=PAYBOND_POLICY_SCHEMA_VERSION_V2,
        name=name,
        default_deny=default_deny,
        tools=tools,
        extends=extends,
        overrides=overrides,
        intent=intent,
        adapter=adapter,
    )


def is_paybond_policy_overlay(document: PaybondPolicyDocumentV2) -> bool:
    """True when a v2 document is a tenant overlay (declares extends)."""
    return document.extends is not None


def parse_paybond_policy_document(raw: Any) -> PaybondPolicyDocument:
    """Parse and validate a raw policy document (decoded JSON or YAML object)."""
    doc = _expect_mapping(raw, path="(root)")
    version = doc.get("version")
    if version == PAYBOND_POLICY_SCHEMA_VERSION:
        return parse_paybond_policy_document_v1(raw)
    if version == PAYBOND_POLICY_SCHEMA_VERSION_V2:
        return parse_paybond_policy_document_v2(raw)
    raise PaybondPolicyValidationError(
        f"version must be {PAYBOND_POLICY_SCHEMA_VERSION} or {PAYBOND_POLICY_SCHEMA_VERSION_V2}",
        path="version",
    )


def validate_paybond_policy_jsonschema(doc: dict[str, Any]) -> None:
    """Validate a policy document dict against the bundled JSON Schema."""
    import jsonschema

    schema = load_policy_json_schema()
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda err: list(err.absolute_path))
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.absolute_path) or "(root)"
        raise PaybondPolicyValidationError(first.message, path=path)


def policy_document_to_dict(doc: PaybondPolicyDocumentV1) -> dict[str, Any]:
    """Serialize a validated policy document back to JSON-compatible dict form."""
    tools: dict[str, Any] = {}
    for tool_name, entry in doc.tools.items():
        tool_payload: dict[str, Any] = {"side_effecting": entry.side_effecting}
        if entry.max_spend_cents is not None:
            tool_payload["max_spend_cents"] = entry.max_spend_cents
        if entry.spend_from_args is not None:
            tool_payload["spend_from_args"] = entry.spend_from_args
        if entry.evidence_preset is not None:
            tool_payload["evidence_preset"] = entry.evidence_preset
        if entry.vendor_pack is not None:
            tool_payload["vendor_pack"] = entry.vendor_pack
        if entry.operation is not None:
            tool_payload["operation"] = entry.operation
        tools[tool_name] = tool_payload

    payload: dict[str, Any] = {
        "version": doc.version,
        "name": doc.name,
        "default_deny": doc.default_deny,
        "tools": tools,
    }

    if doc.intent is not None:
        intent_payload: dict[str, Any] = {}
        if doc.intent.policy_binding is not None:
            binding_payload: dict[str, Any] = {
                "template_id": doc.intent.policy_binding.template_id,
            }
            if doc.intent.policy_binding.version_seq is not None:
                binding_payload["version_seq"] = doc.intent.policy_binding.version_seq
            if doc.intent.policy_binding.head_digest is not None:
                binding_payload["head_digest"] = doc.intent.policy_binding.head_digest
            intent_payload["policy_binding"] = binding_payload
        if doc.intent.budget is not None:
            intent_payload["budget"] = doc.intent.budget
        if doc.intent.allowed_tools:
            intent_payload["allowed_tools"] = list(doc.intent.allowed_tools)
        payload["intent"] = intent_payload

    if doc.adapter is not None and doc.adapter.deny_provider_executed_tools is not None:
        payload["adapter"] = {
            "deny_provider_executed_tools": doc.adapter.deny_provider_executed_tools,
        }

    return payload
