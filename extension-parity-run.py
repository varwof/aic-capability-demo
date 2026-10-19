#!/usr/bin/env python3
"""Emit canonical extension-API outputs for cross-language parity checks."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from pathlib import Path

import clc_semantics as clc


def error_code(fn) -> str:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - stable prefix is the parity value
        return str(exc).split(":", 1)[0]
    return "none"


def main() -> int:
    capability_dir = Path(
        os.environ.get(
            "CLC_CAPABILITY_DIR",
            Path(__file__).resolve().parent.parent / "capability",
        )
    )
    fixture_path = (
        capability_dir
        / "data/_vectors/clc-v1/extension-parity-vectors.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

    record = clc.record_with_context(
        [fixture["grant"]], fixture["operation"], fixture["context"])

    challenge_params = copy.deepcopy(fixture["challenge_params"])
    action_material = challenge_params.pop("action_material")
    challenge_params["action_digest"] = clc.digest_of(action_material)
    challenge = clc.build_challenge_from_decision(
        fixture["challenge_decision"], challenge_params)

    action_id = clc.compute_action_id(
        fixture["action_definition"],
        clc.SUITE_JCS_SHA256,
        fixture["action"],
    )
    envelope = clc.new_envelope(record)

    authority_digest = clc.digest_of(
        fixture["source_chain"]["authority_material"])
    artifact_digest = clc.digest_of(
        fixture["source_chain"]["artifact_material"])
    source_chain = {
        "sources": [
            {"kind": "authority", "id": "root", "digest": authority_digest},
            {
                "kind": "artifact",
                "id": "child",
                "digest": artifact_digest,
                "references": [authority_digest],
            },
        ],
        "links": [{"from": artifact_digest, "to": authority_digest}],
    }

    requirement_result = clc.evaluate_requirement(
        fixture["requirement"],
        fixture["facts"],
        fixture["requirement_context"],
    )

    missing_digest = copy.deepcopy(record)
    missing_digest.pop("input_digest")
    tampered_record = copy.deepcopy(record)
    tampered_record["verdict"] = clc.VERDICT_DENY
    invalid_requirement = copy.deepcopy(fixture["requirement"])
    invalid_requirement["expression"] = "approver & executor"

    negative_errors = {
        "context_stale": error_code(
            lambda: clc.fresh_context(
                fixture["context"], "2026-10-19T12:02:00Z")),
        "record_missing_digest": error_code(
            lambda: clc.record_verify(missing_digest)),
        "record_tampered_verdict": error_code(
            lambda: clc.record_verify(tampered_record)),
        "challenge_expired": error_code(
            lambda: clc.challenge_usable(
                challenge, "2026-10-19T12:05:00Z")),
        "challenge_retry_not_before": error_code(
            lambda: clc.challenge_usable(
                challenge, "2026-10-19T12:00:00Z")),
        "envelope_no_signature": error_code(
            lambda: clc.envelope_verify_record(
                envelope, lambda _key, _pae, _sig: None)),
        "action_malformed": error_code(
            lambda: clc.parse_action_id(
                "clc-action:1:payment.release:jcs-sha256:!!")),
        "requirement_invalid_expression": error_code(
            lambda: clc.validate_requirement(invalid_requirement)),
    }

    got = {
        "record_canonical_sha256": hashlib.sha256(
            clc.record_canonical_bytes(record).encode("utf-8")).hexdigest(),
        "context_digest": clc.context_digest(fixture["context"]),
        "challenge_digest": clc.challenge_digest(challenge),
        "action_id": action_id,
        "envelope_payload_sha256": hashlib.sha256(
            envelope["payload"].encode("utf-8")).hexdigest(),
        "source_chain_digest": clc.source_chain_digest(source_chain),
        "standing_ids": [
            source["id"]
            for source in clc.standing_on(source_chain, artifact_digest)
        ],
        "requirement_digest": clc.requirement_digest(fixture["requirement"]),
        "requirement_roles": clc.requirement_roles(fixture["requirement"]),
        "requirement_verdict": requirement_result["verdict"],
        "negative_errors": negative_errors,
    }

    if got != fixture["expect"]:
        print("parity mismatch", file=sys.stderr)
        print(json.dumps(fixture["expect"], indent=2, sort_keys=True),
              file=sys.stderr)
        print(json.dumps(got, indent=2, sort_keys=True), file=sys.stderr)
        return 1

    print(json.dumps(got, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
