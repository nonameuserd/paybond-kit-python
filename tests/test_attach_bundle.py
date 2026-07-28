from __future__ import annotations

from paybond_kit.agent.attach_bundle import (
    AttachBundlePayloadV1,
    open_attach_bundle,
    redact_attach_bundle,
    resolve_attach_context_from_env,
    seal_attach_bundle,
)


def test_attach_bundle_round_trip() -> None:
    payload = AttachBundlePayloadV1(
        payee_did="did:paybond:middleware:acme:amk_demo:payee",
        payee_signing_seed_hex="a" * 64,
        agent_recognition_key_id="amk_demo",
        agent_recognition_signing_seed_hex="b" * 64,
    )
    bundle = seal_attach_bundle(payload)
    assert bundle.startswith("ab1.")
    assert open_attach_bundle(bundle) == payload


def test_redact_attach_bundle_hides_key_and_ciphertext() -> None:
    payload = AttachBundlePayloadV1(
        payee_did="did:paybond:middleware:acme:amk_demo:payee",
        payee_signing_seed_hex="a" * 64,
        agent_recognition_key_id="amk_demo",
        agent_recognition_signing_seed_hex="b" * 64,
    )
    bundle = seal_attach_bundle(payload)
    redacted = redact_attach_bundle(bundle)
    assert redacted == "ab1.<redacted>"
    assert bundle[4:] not in redacted
    assert redact_attach_bundle("not-a-bundle") == "<redacted>"
    assert redact_attach_bundle("") == "<redacted>"


def test_resolve_attach_context_from_env() -> None:
    payload = AttachBundlePayloadV1(
        payee_did="did:paybond:middleware:acme:amk_demo:payee",
        payee_signing_seed_hex="a" * 64,
        agent_recognition_key_id="amk_demo",
        agent_recognition_signing_seed_hex="b" * 64,
    )
    bundle = seal_attach_bundle(payload)
    context = resolve_attach_context_from_env(
        {
            "PAYBOND_ATTACH_INTENT_ID": "intent-123",
            "PAYBOND_CAPABILITY_TOKEN": "cap-token",
            "PAYBOND_ATTACH_BUNDLE": bundle,
        }
    )
    assert context["intent_id"] == "intent-123"
    assert context["capability_token"] == "cap-token"
    assert context["production_evidence"]["payee_did"] == payload.payee_did
