"""Harbor managed policy helpers backed by the completion preset catalog."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from paybond_kit.cli.core import (
    CliContext,
    CliError,
    consume_boolean_flag,
    consume_flag,
    describe_credential_source,
    gateway_request,
    parse_optional_non_negative_int,
)
from paybond_kit.policy.catalog import list_policy_presets_catalog
from paybond_kit.policy.layers_io import LAYERED_POLICY_PRESET_IDS
from paybond_kit.policy.init import (
    ScaffoldComposedPolicyOptions,
    ScaffoldOrgBasePolicyOptions,
    ScaffoldPaybondPolicyOptions,
    ScaffoldPolicyFromPresetOptions,
    ScaffoldTenantOverlayPolicyOptions,
    render_composed_policy_preview_yaml,
    render_policy_preset_preview_yaml,
    scaffold_composed_policy,
    scaffold_org_base_policy,
    scaffold_paybond_policy,
    scaffold_policy_from_preset,
    scaffold_tenant_overlay_policy,
)
from paybond_kit.policy.presets import is_known_policy_preset_id
from paybond_kit.policy.load import PaybondPolicy
from paybond_kit.policy.schema import PaybondPolicyValidationError, policy_document_to_dict
from paybond_kit.policy.validate import PolicyValidator, PolicyValidatorOptions, policy_validator_result_to_dict
from paybond_kit.policy.validate_remote import (
    parse_policy_remote_validate_response,
    policy_remote_validate_result_to_dict,
    policy_validate_query_string,
)
from paybond_kit.completion_catalog import (
    completion_preset_template_row,
    get_completion_preset,
    get_completion_preset_by_template_id,
    load_completion_catalog,
)
from paybond_kit.completion_resolve import is_vendor_pack, resolve_completion_preset
from paybond_kit.completion_validate_evidence import validate_completion_evidence
from paybond_kit.mcp_sep2828_evidence import map_sep2828_receipts_to_artifact_attested_evidence
from paybond_kit.x402_receipt_evidence import map_x402_receipt_to_artifact_attested_evidence


def _read_json_file(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def handle_policy_presets_list(_ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] not in ("--help", "-h"):
        raise CliError(f"unexpected arguments: {' '.join(argv)}", code="cli.usage.unexpected_args")
    return list_policy_presets_catalog()


def handle_policy_presets_show(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, preset_id, rest = consume_flag(argv, "--preset")
    _, max_spend_raw, rest = consume_flag(rest, "--max-spend")
    _, domain_id, rest = consume_flag(rest, "--domain")
    _, guardrails, rest = consume_flag(rest, "--guardrails")

    positional_preset: str | None = None
    if not preset_id and len(rest) == 1 and not rest[0].startswith("-"):
        positional_preset = rest[0].strip()
        rest = []

    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")

    max_spend_usd = (
        parse_optional_non_negative_int(max_spend_raw, field="--max-spend")
        if max_spend_raw is not None
        else None
    )

    if domain_id:
        domain = domain_id.strip()
        if domain not in LAYERED_POLICY_PRESET_IDS:
            raise CliError(f"unknown policy domain: {domain}", code="cli.policy.domain_invalid")
        if not guardrails:
            raise CliError(
                "policy presets show --domain requires --guardrails",
                code="cli.usage.missing_args",
            )
        if preset_id:
            raise CliError(
                "policy presets show: --preset cannot be combined with --domain",
                code="cli.usage.conflicting_flags",
            )
        try:
            yaml = render_composed_policy_preview_yaml(domain, guardrails)
        except ValueError as exc:
            raise CliError(str(exc), code="cli.policy.presets_show_failed") from exc
        return {
            "domain": domain,
            "guardrails": guardrails,
            "yaml": yaml,
            "yaml_lines": yaml.splitlines(),
        }

    if guardrails:
        raise CliError(
            "policy presets show: --guardrails requires --domain",
            code="cli.usage.missing_args",
        )

    preset = (preset_id or positional_preset or "").strip()
    if not preset:
        raise CliError(
            "policy presets show requires a preset id or --preset",
            code="cli.usage.missing_args",
        )
    if not is_known_policy_preset_id(preset):
        raise CliError(f"unknown policy preset: {preset}", code="cli.policy.preset_invalid")

    yaml = render_policy_preset_preview_yaml(preset, max_spend_usd=max_spend_usd)
    result: dict[str, Any] = {
        "preset": preset,
        "yaml": yaml,
        "yaml_lines": yaml.splitlines(),
    }
    if max_spend_usd is not None:
        result["max_spend_usd"] = max_spend_usd
    return result


def handle_policy_init(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, out_path, rest = consume_flag(argv, "--out")
    _, preset_id, rest = consume_flag(rest, "--preset")
    _, domain_id, rest = consume_flag(rest, "--domain")
    _, guardrails, rest = consume_flag(rest, "--guardrails")
    _, max_spend_raw, rest = consume_flag(rest, "--max-spend")
    _, operation, rest = consume_flag(rest, "--operation")
    _, evidence_preset, rest = consume_flag(rest, "--evidence-preset")
    force_present, rest = consume_boolean_flag(rest, "--force")
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")

    resolved_out = str(Path(ctx.cwd) / (out_path or "paybond.policy.yaml"))
    max_spend_usd = (
        parse_optional_non_negative_int(max_spend_raw, field="--max-spend")
        if max_spend_raw is not None
        else None
    )

    if domain_id:
        domain = domain_id.strip()
        if domain not in LAYERED_POLICY_PRESET_IDS:
            raise CliError(f"unknown policy domain: {domain}", code="cli.policy.domain_invalid")
        if not guardrails:
            raise CliError("policy init --domain requires --guardrails", code="cli.usage.missing_args")
        if preset_id or operation or evidence_preset or max_spend_usd is not None:
            raise CliError(
                "policy init --domain cannot be combined with --preset, --operation, "
                "--evidence-preset, or --max-spend",
                code="cli.usage.conflicting_flags",
            )
        try:
            return scaffold_composed_policy(
                ScaffoldComposedPolicyOptions(
                    out=resolved_out,
                    domain_id=domain,
                    guardrails=guardrails,
                    force=force_present,
                )
            )
        except PaybondPolicyValidationError as exc:
            raise CliError(str(exc), code="cli.policy.init_failed") from exc

    if guardrails:
        raise CliError("policy init --guardrails requires --domain", code="cli.usage.missing_args")

    if preset_id:
        preset = preset_id.strip()
        if not is_known_policy_preset_id(preset):
            raise CliError(f"unknown policy preset: {preset}", code="cli.policy.preset_invalid")
        if operation or evidence_preset:
            raise CliError(
                "policy init: --preset cannot be combined with --operation or --evidence-preset",
                code="cli.usage.conflicting_flags",
            )
        try:
            return scaffold_policy_from_preset(
                ScaffoldPolicyFromPresetOptions(
                    out=resolved_out,
                    preset_id=preset,
                    max_spend_usd=max_spend_usd,
                    force=force_present,
                )
            )
        except PaybondPolicyValidationError as exc:
            raise CliError(str(exc), code="cli.policy.init_failed") from exc

    if max_spend_usd is not None:
        raise CliError("policy init --max-spend requires --preset", code="cli.usage.missing_args")

    try:
        return scaffold_paybond_policy(
            ScaffoldPaybondPolicyOptions(
                out=resolved_out,
                operation=operation or "travel.book_hotel",
                evidence_preset=evidence_preset or "cost_and_completion",
                force=force_present,
            )
        )
    except PaybondPolicyValidationError as exc:
        raise CliError(str(exc), code="cli.policy.init_failed") from exc


def handle_policy_init_org(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, out_path, rest = consume_flag(argv, "--out")
    _, policy_id, rest = consume_flag(rest, "--policy-id")
    _, operation, rest = consume_flag(rest, "--operation")
    _, evidence_preset, rest = consume_flag(rest, "--evidence-preset")
    _, max_spend_raw, rest = consume_flag(rest, "--max-spend-cents")
    force_present, rest = consume_boolean_flag(rest, "--force")
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")
    if not policy_id:
        raise CliError("policy init-org requires --policy-id", code="cli.usage.missing_args")

    max_spend_cents = (
        parse_optional_non_negative_int(max_spend_raw, field="--max-spend-cents")
        if max_spend_raw is not None
        else None
    )
    resolved_out = str(Path(ctx.cwd) / (out_path or f"{policy_id.strip()}.yaml"))
    try:
        return scaffold_org_base_policy(
            ScaffoldOrgBasePolicyOptions(
                out=resolved_out,
                policy_id=policy_id,
                operation=operation or "travel.book_hotel",
                evidence_preset=evidence_preset or "cost_and_completion",
                max_spend_cents=max_spend_cents,
                force=force_present,
            )
        )
    except PaybondPolicyValidationError as exc:
        raise CliError(str(exc), code="cli.policy.init_org_failed") from exc


def handle_policy_extend(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, extends_ref, rest = consume_flag(argv, "--extends")
    _, out_path, rest = consume_flag(rest, "--out")
    _, name, rest = consume_flag(rest, "--name")
    _, operation, rest = consume_flag(rest, "--operation")
    _, evidence_preset, rest = consume_flag(rest, "--evidence-preset")
    _, base_policy, rest = consume_flag(rest, "--base-policy")
    force_present, rest = consume_boolean_flag(rest, "--force")
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")
    if not extends_ref:
        raise CliError(
            "policy extend requires --extends org_id/org_policy_id",
            code="cli.usage.missing_args",
        )

    resolved_out = str(Path(ctx.cwd) / (out_path or "paybond.policy.yaml"))
    try:
        return scaffold_tenant_overlay_policy(
            ScaffoldTenantOverlayPolicyOptions(
                out=resolved_out,
                extends_ref=extends_ref,
                name=name,
                operation=operation,
                evidence_preset=evidence_preset,
                base_policy=base_policy,
                force=force_present,
            )
        )
    except PaybondPolicyValidationError as exc:
        raise CliError(str(exc), code="cli.policy.extend_failed") from exc


def _resolve_policy_validate_tools_mode(
    ctx: CliContext,
    *,
    remote: bool,
    local_only: bool,
    check_gateway: bool,
) -> str:
    if remote and local_only:
        raise CliError(
            "policy validate-tools: --remote and --local-only are mutually exclusive",
            code="cli.usage.conflicting_flags",
        )
    if local_only:
        return "local"
    if remote:
        return "remote"
    if check_gateway:
        return "check_gateway"
    if describe_credential_source(ctx.globals, ctx.cwd)["source"] != "missing":
        return "remote"
    return "local"


def handle_policy_validate_tools(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, file_path, rest = consume_flag(argv, "--file")
    remote_present, rest = consume_boolean_flag(rest, "--remote")
    local_only_present, rest = consume_boolean_flag(rest, "--local-only")
    check_gateway_present, rest = consume_boolean_flag(rest, "--check-gateway")
    strict_present, rest = consume_boolean_flag(rest, "--strict")
    resolve_inheritance_present, rest = consume_boolean_flag(rest, "--resolve-inheritance")
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")
    if not file_path:
        raise CliError("policy validate-tools requires --file", code="cli.usage.missing_args")

    resolved = str(Path(ctx.cwd) / file_path)
    strict = True if strict_present else PolicyValidator.is_strict_from_env()
    mode = _resolve_policy_validate_tools_mode(
        ctx,
        remote=remote_present,
        local_only=local_only_present,
        check_gateway=check_gateway_present,
    )
    if resolve_inheritance_present and mode != "remote":
        raise CliError(
            "policy validate-tools: --resolve-inheritance requires remote validation (use --remote or log in)",
            code="cli.usage.conflicting_flags",
        )

    if mode == "remote":
        from paybond_kit.policy.validate_remote import PolicyRemoteValidateOptions

        options = PolicyRemoteValidateOptions(
            strict=True if strict_present else None,
            resolve_inheritance=True if resolve_inheritance_present else None,
        )
        path = f"/v1/policy/validate{policy_validate_query_string(options=options)}"
        if resolve_inheritance_present:
            overlay_payload = PaybondPolicy._load_overlay_payload(resolved)
            body = gateway_request(ctx, "POST", path, overlay_payload)
        else:
            policy = PaybondPolicy.load(resolved)
            body = gateway_request(ctx, "POST", path, policy_document_to_dict(policy.document))
        report = parse_policy_remote_validate_response(body)
        payload = policy_remote_validate_result_to_dict(report)
    else:
        options = PolicyValidatorOptions(
            strict=True if strict_present else None,
            check_gateway=mode == "check_gateway",
        )
        if mode == "check_gateway":

            class _GatewayLookup:
                def list_template_ids(self) -> list[str]:
                    templates_body = gateway_request(ctx, "GET", "/harbor/policy/v1/templates")
                    rows = templates_body if isinstance(templates_body, list) else templates_body.get("templates", [])
                    if not isinstance(rows, list):
                        return []
                    ids: list[str] = []
                    for row in rows:
                        if isinstance(row, dict) and row.get("template_id"):
                            ids.append(str(row["template_id"]))
                    return ids

            options = PolicyValidatorOptions(
                strict=True if strict_present else None,
                check_gateway=True,
                gateway=_GatewayLookup(),
            )
        report = PolicyValidator.validate(resolved, options)
        payload = policy_validator_result_to_dict(report)

    if not payload["valid"]:
        raise CliError(
            "policy validation failed",
            code="cli.policy.validation_failed",
            category="validation",
            exit_code=3,
            details=payload,
        )
    return payload


def handle_policy_templates(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] not in ("--help", "-h"):
        raise CliError(f"unexpected arguments: {' '.join(argv)}", code="cli.usage.unexpected_args")
    catalog = load_completion_catalog()
    presets = [completion_preset_template_row(preset) for preset in catalog["presets"]]
    return {"catalog_version": catalog["version"], "presets": presets}


def handle_policy_preview(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, template_id, rest = consume_flag(argv, "--template")
    _, preset_id, rest = consume_flag(rest, "--preset")
    _, parameters_file, rest = consume_flag(rest, "--parameters-file")
    _, evidence_file, rest = consume_flag(rest, "--evidence-file")
    _, schema_file, rest = consume_flag(rest, "--schema-file")
    _, amount_cents_raw, rest = consume_flag(rest, "--amount-cents")
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")

    catalog_preset = get_completion_preset(preset_id) if preset_id else None
    resolved = resolve_completion_preset(preset_id) if preset_id else None
    resolved_template = template_id or (resolved["harbor_template_id"] if resolved else "")
    if not resolved_template:
        raise CliError("policy preview requires --template or --preset", code="cli.usage.missing_args")

    if catalog_preset is None:
        catalog_preset = get_completion_preset_by_template_id(resolved_template)

    if parameters_file:
        parameters = _read_json_file(parameters_file)
    elif resolved is not None:
        parameters = resolved["parameters"]
    else:
        raise CliError(
            "policy preview requires --parameters-file when template is not in the catalog",
            code="cli.usage.missing_args",
        )

    if not evidence_file:
        raise CliError("policy preview requires --evidence-file", code="cli.usage.missing_args")
    evidence = _read_json_file(evidence_file)

    if schema_file:
        evidence_schema = _read_json_file(schema_file)
    elif resolved is not None:
        evidence_schema = resolved["evidence_schema"]
    else:
        raise CliError(
            "policy preview requires --schema-file when template is not in the catalog",
            code="cli.usage.missing_args",
        )

    if amount_cents_raw is not None:
        amount_cents = parse_optional_non_negative_int(amount_cents_raw, field="--amount-cents")
    else:
        recommended = catalog_preset.get("recommended_amount_cents") if catalog_preset else None
        amount_cents = int(recommended) if recommended is not None else 100

    preview = gateway_request(
        ctx,
        "POST",
        "/harbor/policy/v1/preview",
        {"template_id": resolved_template, "parameters": parameters},
    )
    test = gateway_request(
        ctx,
        "POST",
        "/harbor/policy/v1/test",
        {
            "template_id": resolved_template,
            "parameters": parameters,
            "evidence": evidence,
            "evidence_schema": evidence_schema,
            "amount_cents": amount_cents,
        },
    )
    evaluation = test.get("predicate_evaluation")
    if not isinstance(evaluation, dict):
        evaluation = {}
    passed = bool(evaluation.get("passed", evaluation.get("pass", evaluation.get("ok"))))
    return {
        "template_id": resolved_template,
        "preset_id": catalog_preset["preset_id"] if catalog_preset else None,
        "materialized_dsl": preview.get("materialized_dsl"),
        "human_summary": preview.get("human_summary"),
        "predicate_evaluation": evaluation,
        "pass": passed,
        "amount_cents": amount_cents,
    }


def handle_policy_validate_evidence(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, preset_id, rest = consume_flag(argv, "--preset")
    _, vendor_file, rest = consume_flag(rest, "--vendor-file")
    _, canonical_file, rest = consume_flag(rest, "--canonical-file")
    _, frozen_api_version, rest = consume_flag(rest, "--frozen-api-version")
    _, frozen_vendor_digest, rest = consume_flag(rest, "--frozen-vendor-schema-digest")
    _, frozen_canonical_digest, rest = consume_flag(rest, "--frozen-canonical-schema-digest")
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")
    if not preset_id:
        raise CliError("policy validate-evidence requires --preset", code="cli.usage.missing_args")

    preset = get_completion_preset(preset_id)
    vendor_payload = _read_json_file(vendor_file) if vendor_file else None
    canonical_payload = _read_json_file(canonical_file) if canonical_file else None

    if is_vendor_pack(preset) and vendor_payload is None and canonical_payload is None:
        raise CliError(
            "policy validate-evidence requires --vendor-file for vendor_pack presets (or --canonical-file)",
            code="cli.usage.missing_args",
        )
    if not is_vendor_pack(preset) and vendor_payload is None and canonical_payload is None:
        raise CliError(
            "policy validate-evidence requires --canonical-file or --vendor-file",
            code="cli.usage.missing_args",
        )

    report = validate_completion_evidence(
        preset_id=preset_id,
        vendor_payload=vendor_payload,
        canonical_payload=canonical_payload,
        frozen_vendor_api_version=frozen_api_version,
        frozen_vendor_schema_digest_hex=frozen_vendor_digest,
        frozen_canonical_schema_digest_hex=frozen_canonical_digest,
    )
    return {**report, "ok": len(report["drift_kinds"]) == 0}


def handle_policy_import_mcp_receipt(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, decision_file, rest = consume_flag(argv, "--decision-file")
    _, outcome_file, rest = consume_flag(rest, "--outcome-file")
    _, write_file, rest = consume_flag(rest, "--write-evidence-file")
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")
    if not decision_file or not outcome_file:
        raise CliError(
            "policy import-mcp-receipt requires --decision-file and --outcome-file",
            code="cli.usage.missing_args",
        )

    decision = _read_json_file(decision_file)
    outcome = _read_json_file(outcome_file)
    evidence = map_sep2828_receipts_to_artifact_attested_evidence(decision, outcome)
    artifact_preset = get_completion_preset("artifact_attested")

    if write_file:
        Path(write_file).write_text(f"{json.dumps(evidence, indent=2)}\n", encoding="utf-8")

    return {
        "preset_id": artifact_preset["preset_id"],
        "harbor_template_id": artifact_preset["harbor_template_id"],
        "evidence": evidence,
        "source": "sep2828_mcp_receipt",
    }


def handle_policy_import_x402_receipt(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, receipt_file, rest = consume_flag(argv, "--receipt-file")
    _, write_file, rest = consume_flag(rest, "--write-evidence-file")
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")
    if not receipt_file:
        raise CliError(
            "policy import-x402-receipt requires --receipt-file",
            code="cli.usage.missing_args",
        )

    receipt = _read_json_file(receipt_file)
    try:
        evidence = map_x402_receipt_to_artifact_attested_evidence(receipt)
    except ValueError as exc:
        raise CliError(str(exc), code="cli.usage.invalid_receipt") from exc
    delivery_preset = get_completion_preset("x402_delivery_receipt")

    if write_file:
        Path(write_file).write_text(f"{json.dumps(evidence, indent=2)}\n", encoding="utf-8")

    return {
        "preset_id": delivery_preset["preset_id"],
        "harbor_template_id": delivery_preset["harbor_template_id"],
        "evidence": evidence,
        "source": "x402_receipt_v1",
    }
