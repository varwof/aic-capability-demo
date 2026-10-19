#!/usr/bin/env python3
"""Positive/negative checks for the CLC extensions ported to Python/TS.

These cover behavior outside the JSON conformance corpora: decision records,
contexts, source chains, evidence requirements, challenges, DSSE envelopes,
action identities and combining algorithms.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from pathlib import Path

import clc_semantics as clc
import evidence_semantics as legacy
import ocmp
import scheme_decl


GID = "std/database-v1:query:SELECT"
GRANT = {"id": GID, "params": {"limit": 100}}
OP = {"id": GID, "params": {"limit": 50}}
TIME_OBLIGATION = 'varwof/constraint-v1:time:window:[{"start":"00:00","end":"01:00"}]'

FAILS: list[str] = []
COUNT = 0


def check(label: str, got: object, want: object) -> None:
    global COUNT
    COUNT += 1
    if got != want:
        FAILS.append(f"{label}: got {got!r}, want {want!r}")


def expect_error(label: str, prefix: str, fn) -> None:
    global COUNT
    COUNT += 1
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - test harness checks message prefixes
        if prefix not in str(exc):
            FAILS.append(f"{label}: got error {exc!s}, want prefix {prefix!r}")
    else:
        FAILS.append(f"{label}: expected error prefix {prefix!r}, got success")


def expect_ok(label: str, fn) -> None:
    global COUNT
    COUNT += 1
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        FAILS.append(f"{label}: unexpected error: {exc}")


# Combining and obligations -------------------------------------------------

allow = {"verdict": clc.VERDICT_ALLOW}
deny = {"verdict": clc.VERDICT_DENY, "reason": "capability_not_authorized"}
pending = {"verdict": clc.VERDICT_ALLOW_UNRESOLVED, "unresolved": [TIME_OBLIGATION]}

check("deny-overrides chooses deny",
      clc.combine(clc.COMBINING_DENY_OVERRIDES, [pending, deny]), deny)
check("first-applicable keeps first decision",
      clc.combine(clc.COMBINING_FIRST_APPLICABLE, [pending, deny]), pending)
expect_error("empty combine refuses",
             "no_decisions", lambda: clc.combine(clc.COMBINING_DENY_OVERRIDES, []))
expect_error("unknown combine algorithm refuses",
             "unknown_combining_algorithm",
             lambda: clc.combine("majority", [allow]))
expect_error("allow cannot carry obligations",
             "obligation_shape",
             lambda: clc.check_decision_shape({**allow, "unresolved": [TIME_OBLIGATION]}))
expect_ok("discharge accepts a declared obligation",
          lambda: clc.discharge(pending, ["varwof/constraint-v1:time"]))
expect_error("discharge refuses an unknown obligation",
             "obligation_unknown",
             lambda: clc.discharge(pending, []))
expect_error("permit-overrides cannot drop later obligations",
             "combining_would_drop_obligations",
             lambda: clc.combine(clc.COMBINING_PERMIT_OVERRIDES, [allow, pending]))


# Parameter bounds, defaults and public boundary helpers --------------------

check("absent param bounds are unconstrained",
      clc.validate_param_bounds(None, None), "")
check("valid nested param bounds are accepted",
      clc.validate_param_bounds(
          {"profile": {"nested": {
              "tier": {"enum": ["gold"]},
              "note": {"optional": True},
          }}},
          {}),
      "")

bound_errors = [
    ("non-object bound", {"x": 1},
     "invalid_params_binding: bound is not an object"),
    ("unknown bound member", {"x": {"minimum": 1}},
     "invalid_params_binding: unknown Bound member minimum"),
    ("mixed bound families", {"x": {"min": 1, "enum": [1]}},
     "invalid_params_binding: mixed bound families"),
    ("non-boolean optional", {"x": {"min": 1, "optional": "yes"}},
     "invalid_params_binding: optional is not a boolean"),
    ("non-positive step", {"x": {"step": 0}},
     "invalid_params_binding: step must be positive"),
    ("inverted numeric range", {"x": {"min": 2, "max": 1}},
     "invalid_params_binding: min > max"),
    ("non-array enum", {"x": {"enum": 1}},
     "invalid_params_binding: enum is not an array"),
    ("fractional item count", {"x": {"min_items": 1.5}},
     "invalid_params_binding: min_items is not a non-negative integer"),
    ("inverted item range", {"x": {"min_items": 2, "max_items": 1}},
     "invalid_params_binding: min_items > max_items"),
    ("non-object nested bound", {"x": {"nested": []}},
     "invalid_params_binding: nested is not an object"),
    ("invalid nested member", {"x": {"nested": {"y": {"step": -1}}}},
     "invalid_params_binding: step must be positive"),
    ("empty bound key", {"": {"min": 0}},
     "invalid_params_binding: empty key"),
]
for label, bounds, reason in bound_errors:
    check(f"param bounds reject {label}",
          clc.validate_param_bounds(bounds, {}), reason)
check("bound key may not move between representations",
      clc.validate_param_bounds({"limit": {"min": 0}}, {"limit": 50}),
      "invalid_params_binding: limit in both params and param_bounds")

defaulted = clc.materialize_defaults(
    {"id": GID, "params": {"limit": 100},
     "param_bounds": {"mode": {"enum": ["fast", "slow"]}}},
    {"id": GID},
    {"limit": 50, "mode": "slow", "extra": 1})
check("declared defaults are materialized", defaulted,
      {"id": GID, "params": {"limit": 50, "mode": "slow"}})
check("explicit operation values override defaults",
      clc.materialize_defaults(
          {"id": GID, "params": {"limit": 100}},
          {"id": GID, "params": {"limit": 10}},
          {"limit": 50}),
      {"id": GID, "params": {"limit": 10}})

check("authorize_json_text allows valid raw parameters",
      clc.authorize_json_text([GRANT], GID, '{"limit":50}')["verdict"],
      clc.VERDICT_ALLOW)
check("authorize_json_text keeps an absent params object",
      clc.authorize_json_text([{"id": GID}], GID)["verdict"],
      clc.VERDICT_ALLOW)
check("authorize_json_text refuses duplicate object members",
      clc.authorize_json_text([GRANT], GID, '{"limit":1,"limit":2}')["reason"],
      'invalid_params_duplicate_key: "limit"')

expect_ok("constraint_within accepts a narrower value",
          lambda: clc.constraint_within(5, 10))
expect_ok("constraint_within accepts an absent bound",
          lambda: clc.constraint_within(5, None))
expect_error("constraint_within rejects a wider value",
             "params_exceed_grant",
             lambda: clc.constraint_within(11, 10))
expect_error("constraint_within rejects a null value",
             "invalid_params_null",
             lambda: clc.constraint_within(None, 10))
expect_ok("grant and operation params share the same accepted shape",
          lambda: (clc.validate_grant_params({"limit": 1}),
                   clc.validate_operation_params({"cursor": "next"})))
expect_error("grant params reject null values",
             "invalid_params_null",
             lambda: clc.validate_grant_params({"limit": None}))


# Resolve and time-window discharge ----------------------------------------

resolve_now = "2026-10-19T00:30:00Z"
check("terminal deny passes through resolve",
      clc.resolve(deny, [{"constraint": TIME_OBLIGATION, "status": "satisfied"}]),
      deny)
check("terminal allow passes through resolve", clc.resolve(allow), allow)
check("invalid decision verdict denies",
      clc.resolve({"verdict": "maybe"}),
      {"verdict": clc.VERDICT_DENY, "reason": "invalid_resolution"})
check("malformed resolution denies",
      clc.resolve(pending, [{"constraint": "", "status": "satisfied"}]),
      {"verdict": clc.VERDICT_DENY, "reason": "invalid_resolution"})
check("invalid resolution status denies",
      clc.resolve(pending, [{"constraint": TIME_OBLIGATION, "status": "maybe"}]),
      {"verdict": clc.VERDICT_DENY, "reason": "invalid_resolution"})
check("invalid resolve timestamp denies",
      clc.resolve(pending, [], "not-a-time"),
      {"verdict": clc.VERDICT_DENY, "reason": "invalid_timestamp"})
check("satisfied resolution discharges the obligation",
      clc.resolve(pending, [{"constraint": TIME_OBLIGATION, "status": "satisfied"}]),
      {"verdict": clc.VERDICT_ALLOW})
check("unknown resolution keeps the obligation",
      clc.resolve(pending, [{"constraint": TIME_OBLIGATION, "status": "unknown"}]),
      {"verdict": clc.VERDICT_ALLOW_UNRESOLVED,
       "unresolved": [TIME_OBLIGATION]})
check("violated resolution dominates satisfied",
      clc.resolve(pending, [
          {"constraint": TIME_OBLIGATION, "status": "satisfied"},
          {"constraint": TIME_OBLIGATION, "status": "violated"},
      ]),
      {"verdict": clc.VERDICT_DENY, "reason": "time:violated"})
check("time window inside discharges",
      clc.resolve(pending, [], resolve_now),
      {"verdict": clc.VERDICT_ALLOW})
check("time window outside denies",
      clc.resolve(pending, [], "2026-10-19T02:00:00Z"),
      {"verdict": clc.VERDICT_DENY, "reason": "time:violated"})
check("violated report dominates lenient clock",
      clc.resolve(pending, [
          {"constraint": TIME_OBLIGATION, "status": "violated"},
      ], resolve_now),
      {"verdict": clc.VERDICT_DENY, "reason": "time:violated"})


# Evidence constraints ------------------------------------------------------

now = "2026-10-19T12:00:00Z"
fact_fresh = clc.evidence_fact("approver", "alice", "2026-10-19T11:59:00Z", True)
fact_stale = clc.evidence_fact("approver", "alice", "2026-10-19T10:00:00Z", True)
fact_future = clc.evidence_fact("approver", "alice", "2026-10-19T13:00:00Z", True)

check("freshness accepts a fresh eligible fact",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:freshness:sec:60", [fact_fresh], {"now": now})["verdict"],
      clc.EVIDENCE_SATISFIED)
check("freshness rejects a stale fact",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:freshness:sec:60", [fact_stale], {"now": now})["reason"],
      "freshness:stale")
check("freshness rejects a future issuance",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:freshness:sec:60", [fact_future], {"now": now})["reason"],
      "freshness:future_issued")
check("freshness rejects an invalid issuance time",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:freshness:sec:60",
          [clc.evidence_fact("approver", "alice", "not-a-time", True)],
          {"now": now})["reason"],
      "freshness:no_issuance_time")
check("freshness fails closed without an eligible fact",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:freshness:sec:60",
          [clc.evidence_fact("approver", "alice", "2026-10-19T11:59:00Z", False)],
          {"now": now})["reason"],
      "freshness:no_eligible_fact")

quorum_facts = [
    clc.evidence_fact("approver", "alice", "", True),
    clc.evidence_fact("approver", "bob", "", True),
]
check("quorum accepts distinct verified subjects",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:quorum:distinct:2", quorum_facts)["verdict"],
      clc.EVIDENCE_SATISFIED)
check("quorum rejects duplicate subjects",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:quorum:distinct:2",
          [quorum_facts[0], copy.deepcopy(quorum_facts[0])])["verdict"],
      clc.EVIDENCE_VIOLATED)
check("exclusion accepts a different initiator",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:exclusion:initiator",
          [clc.evidence_fact("executor", "bob", "", True)],
          {"initiator": "alice"})["verdict"],
      clc.EVIDENCE_SATISFIED)
check("exclusion rejects the initiator",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:exclusion:initiator",
          [clc.evidence_fact("executor", "alice", "", True)],
          {"initiator": "alice"})["reason"],
      "exclusion:initiator_is_approver")
check("exclusion is unknown without boundary identity",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:exclusion:initiator",
          [clc.evidence_fact("executor", "bob", "", True)])["verdict"],
      clc.EVIDENCE_UNKNOWN)
check("consumption remains residual",
      clc.evaluate_evidence_constraint(
          "varwof/evidence-v1:consumption:once", [])["verdict"],
      clc.EVIDENCE_UNKNOWN)
core_eval = clc.evaluate_evidence_constraint(
    "varwof/evidence-v1:freshness:sec:60", [fact_fresh], {})
check("compatibility evidence evaluator remains aligned",
      legacy.evaluate_constraint(
          "varwof/evidence-v1:freshness:sec:60", [fact_fresh], {}),
      (core_eval["verdict"], core_eval.get("reason", "")))
expect_error("malformed evidence constraint refuses",
             "invalid_evidence_constraint",
             lambda: clc.validate_evidence_constraint("varwof/evidence-v1:quorum:distinct:1"))


# Context and source chain --------------------------------------------------

ctx = clc.decision_context("2026-10-19T12:00:00Z", 60, "context-1")
expect_ok("fresh context is accepted",
          lambda: clc.fresh_context(ctx, "2026-10-19T12:00:30Z"))
expect_error("stale context is refused",
             "context_stale",
             lambda: clc.fresh_context(ctx, "2026-10-19T12:02:00Z"))
expect_error("future context is refused",
             "context_future",
             lambda: clc.fresh_context(ctx, "2026-10-19T11:59:00Z"))
expect_error("zero context is refused",
             "context_missing",
             lambda: clc.validate_decision_context(clc.decision_context()))
expect_error("offset timestamp is not accepted as UTC",
             "context_not_utc",
             lambda: clc.validate_decision_context(
                 clc.decision_context("2026-10-19T12:00:00+00:00", 60, "context-1")))
expect_error("oversized context nonce is refused",
             "nonce longer than",
             lambda: clc.validate_decision_context(
                 clc.decision_context("2026-10-19T12:00:00Z", 60,
                                      "x" * (clc.MAX_CONTEXT_NONCE_BYTES + 1))))
check("context digest is stable",
      clc.context_digest(ctx), clc.context_digest(copy.deepcopy(ctx)))

authority_digest = clc.digest_of({"source": "authority"})
artifact_digest = clc.digest_of({"source": "artifact"})
chain = {
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
expect_ok("source chain validates", lambda: clc.validate_source_chain(chain))
check("standing-on returns child then authority",
      [s["id"] for s in clc.standing_on(chain, artifact_digest)], ["child", "root"])
check("source chain digest is stable",
      clc.source_chain_digest(chain), clc.source_chain_digest(copy.deepcopy(chain)))

unbacked = copy.deepcopy(chain)
unbacked["sources"][1].pop("references")
expect_error("unbacked source edge is refused",
             "source_edge_unbacked",
             lambda: clc.validate_source_chain(unbacked))
expect_error("empty source chain is refused",
             "source_chain_empty",
             lambda: clc.validate_source_chain({"sources": []}))
dangling = copy.deepcopy(chain)
dangling["links"].append({
    "from": artifact_digest,
    "to": clc.digest_of({"source": "missing"}),
})
expect_error("dangling source link is refused",
             "source_dangling_link",
             lambda: clc.validate_source_chain(dangling))

second_authority = clc.digest_of({"source": "authority-2"})
branch = {
    "sources": [
        {"kind": "authority", "id": "root-1", "digest": authority_digest},
        {"kind": "authority", "id": "root-2", "digest": second_authority},
        {
            "kind": "artifact",
            "id": "child",
            "digest": artifact_digest,
            "references": [authority_digest, second_authority],
        },
    ],
    "links": [
        {"from": artifact_digest, "to": authority_digest},
        {"from": artifact_digest, "to": second_authority},
    ],
}
expect_ok("branching source chain is structurally valid",
          lambda: clc.validate_source_chain(branch))
expect_error("branching standing path is indeterminate",
             "source_chain_branch",
             lambda: clc.standing_on(branch, artifact_digest))

cycle = {
    "sources": [
        {"kind": "a", "id": "a", "digest": authority_digest, "references": [artifact_digest]},
        {"kind": "b", "id": "b", "digest": artifact_digest, "references": [authority_digest]},
    ],
    "links": [
        {"from": authority_digest, "to": artifact_digest},
        {"from": artifact_digest, "to": authority_digest},
    ],
}
expect_error("source cycle is refused",
             "source_chain_cycle",
             lambda: clc.validate_source_chain(cycle))


# Decision records ----------------------------------------------------------

rec = clc.record([GRANT], OP)
expect_ok("decision record verifies", lambda: clc.record_verify(rec))
check("decision record recomputes allow",
      clc.record_recompute(rec)["verdict"], clc.VERDICT_ALLOW)

bad_inputs = copy.deepcopy(rec)
bad_inputs["inputs"]["operations"][0]["params"]["limit"] = 150
expect_error("tampered record inputs are refused",
             "record_input_digest_mismatch",
             lambda: clc.record_verify(bad_inputs))
bad_verdict = copy.deepcopy(rec)
bad_verdict["verdict"] = clc.VERDICT_DENY
expect_error("tampered record verdict is refused",
             "record_verdict_mismatch",
             lambda: clc.record_verify(bad_verdict))
bad_revision = copy.deepcopy(rec)
bad_revision["ver"] = "CLC-2.0"
expect_error("unsupported record revision is refused",
             "record_unsupported_revision",
             lambda: clc.record_recompute(bad_revision))
no_op = copy.deepcopy(rec)
no_op["inputs"]["operations"] = []
expect_error("record with wrong operation count is refused",
             "record_operation_count",
             lambda: clc.record_recompute(no_op))
missing_digest = copy.deepcopy(rec)
missing_digest.pop("input_digest")
expect_error("record without input digest fails closed",
             "record_input_digest_mismatch",
             lambda: clc.record_verify(missing_digest))

rec_ctx = clc.record_with_context([GRANT], OP, ctx)
expect_ok("record with context verifies as fresh",
          lambda: clc.record_verify_as_of(rec_ctx, "2026-10-19T12:00:30Z"))
expect_error("record with stale context is refused",
             "context_stale",
             lambda: clc.record_verify_as_of(rec_ctx, "2026-10-19T12:02:00Z"))


# Requirements --------------------------------------------------------------

req = {
    "@version": clc.REQUIREMENT_VERSION,
    "requirement_id": "req-1",
    "expression": "(approver AND executor) OR passkey",
    "constraints": [
        {"role": "approver", "constraint": "varwof/evidence-v1:quorum:distinct:2"},
        {"role": "executor", "constraint": "varwof/evidence-v1:exclusion:initiator"},
    ],
}
req_facts = [
    clc.evidence_fact("approver", "alice", "", True),
    clc.evidence_fact("approver", "bob", "", True),
    clc.evidence_fact("executor", "carol", "", True),
]
result = clc.evaluate_requirement(req, req_facts, {"initiator": "alice"})
check("requirement is satisfied", result["verdict"], clc.EVIDENCE_SATISFIED)
check("compatibility requirement evaluator keeps CLC precedence",
      legacy.evaluate_requirement(
          {
              "@version": clc.REQUIREMENT_VERSION,
              "requirement_id": "paren",
              "expression": "a AND (b OR c)",
              "constraints": [],
          },
          [
              clc.evidence_fact("a", "x", "", True),
              clc.evidence_fact("c", "y", "", True),
          ],
          {}),
      (clc.SATISFACTION_SATISFIED, ""))
check("requirement roles are sorted",
      clc.requirement_roles(req), ["approver", "executor", "passkey"])
check("requirement satisfaction is binary",
      clc.requirement_satisfaction(result)["verdict"], clc.SATISFACTION_SATISFIED)
missing = clc.evaluate_requirement(req, req_facts[:2], {"initiator": "alice"})
check("missing executor violates expression",
      missing["verdict"], clc.EVIDENCE_VIOLATED)
check("missing executor is named",
      missing["missing_roles"], ["executor", "passkey"])
check("unknown evidence is not satisfied",
      clc.requirement_satisfied(
          clc.evaluate_requirement(req, req_facts, {})) , False)
expect_error("wrong requirement version is refused",
             "requirement_version",
             lambda: clc.validate_requirement({**req, "@version": "CLC-REQUIREMENT-v0"}))
expect_error("malformed expression is refused",
             "requirement_expression",
             lambda: clc.validate_requirement({**req, "expression": "approver & executor"}))
expect_error("duplicate role constraint is refused",
             "requirement_shape",
             lambda: clc.validate_requirement(
                 {**req, "constraints": [req["constraints"][0], req["constraints"][0]]}))
expect_error("unknown requirement field is refused",
             'requirement_shape: json: unknown field "extra"',
             lambda: clc.parse_requirement({**req, "extra": True}))
expect_error("oversized requirement expression is refused",
             "expression longer",
             lambda: clc.validate_requirement(
                 {**req, "expression": "a" * (clc.MAX_REQUIREMENT_EXPRESSION_BYTES + 1)}))
expect_error("too many requirement nodes are refused",
             "more than",
             lambda: clc.validate_requirement(
                 {**req, "expression": " OR ".join(["a"] * 66)}))
expect_error("too-deep requirement expression is refused",
             "nesting deeper",
             lambda: clc.validate_requirement(
                 {**req, "expression": "(" * 9 + "a" + ")" * 9}))
check("valid requirement parses",
      clc.parse_requirement(json.dumps(req))["requirement_id"], "req-1")


# Challenges ----------------------------------------------------------------

action_digest = clc.digest_of({"operation": "shed"})
challenge_params = {
    "id": "challenge-1",
    "nonce": "12345678",
    "audience": "agent.example",
    "action_digest": action_digest,
    "now": "2026-10-19T12:00:00Z",
    "ttl_sec": 300,
    "retry_timing": {"not_before": "2026-10-19T12:00:30Z", "jitter_sec": 5},
}
challenge = clc.build_challenge_from_decision(pending, challenge_params)
expect_ok("challenge validates", lambda: clc.validate_challenge(challenge))
check("challenge never authorizes", clc.challenge_authorizes(challenge), False)
expect_ok("challenge is usable in retry window",
          lambda: clc.challenge_usable(challenge, "2026-10-19T12:01:00Z"))
expect_error("challenge before retry time is refused",
             "challenge_retry_not_before",
             lambda: clc.challenge_usable(challenge, "2026-10-19T12:00:00Z"))
expect_error("expired challenge is refused",
             "challenge_expired",
             lambda: clc.challenge_usable(challenge, "2026-10-19T12:05:00Z"))
check("challenge digest is stable",
      clc.challenge_digest(challenge), clc.challenge_digest(copy.deepcopy(challenge)))
bad_nonce = copy.deepcopy(challenge)
bad_nonce["nonce"] = "short"
expect_error("short challenge nonce is refused",
             "nonce must be",
             lambda: clc.validate_challenge(bad_nonce))
expect_error("allow decision produces no challenge",
             "challenge_not_outstanding",
             lambda: clc.build_challenge_from_decision(allow, challenge_params))

req_challenge = {
    "@version": clc.REQUIREMENT_VERSION,
    "requirement_id": "req-challenge",
    "expression": "approver",
    "constraints": [
        {"role": "approver", "constraint": "varwof/evidence-v1:freshness:sec:60"},
    ],
}
req_result = clc.evaluate_requirement(req_challenge, [], {"now": now})
from_requirement = clc.build_challenge_from_requirement(
    req_challenge, req_result, challenge_params)
expect_ok("challenge from requirement validates",
          lambda: clc.validate_challenge(from_requirement))
check("challenge from requirement names missing role and constraint",
      {item["id"] for item in from_requirement["required"]},
      {"approver", "varwof/evidence-v1:freshness:sec:60"})
expect_error("satisfied requirement produces no challenge",
             "challenge_not_outstanding",
             lambda: clc.build_challenge_from_requirement(
                 req, result, challenge_params))
bad_nonce_high = copy.deepcopy(challenge)
bad_nonce_high["nonce"] = "x" * (clc.MAX_CHALLENGE_NONCE_BYTES + 1)
expect_error("oversized challenge nonce is refused",
             "nonce must be",
             lambda: clc.validate_challenge(bad_nonce_high))
bad_jitter = copy.deepcopy(challenge)
bad_jitter["retry_timing"]["jitter_sec"] = -1
expect_error("negative challenge jitter is refused",
             "jitter_sec out of range",
             lambda: clc.validate_challenge(bad_jitter))
bad_retry = copy.deepcopy(challenge)
bad_retry["retry_timing"]["not_before"] = "2026-10-19T12:06:00Z"
expect_error("retry time after expiry is refused",
             "not_before is after expiry",
             lambda: clc.validate_challenge(bad_retry))


# DSSE envelopes ------------------------------------------------------------

def sign(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def verify(_key_id: str, payload: bytes, signature: str) -> None:
    if signature != sign(payload):
        raise ValueError("bad signature")


envelope = clc.new_envelope(rec)
expect_ok("unsigned envelope is internally consistent", lambda: clc.envelope_check(envelope))
expect_error("unsigned envelope cannot verify as signed",
             "envelope_signature",
             lambda: clc.envelope_verify_record(envelope, verify))
clc.envelope_sign(envelope, "key-1", sign)
expect_ok("signed envelope verifies with an explicit verifier",
          lambda: clc.envelope_verify_record(envelope, verify))
check("envelope returns its decision record",
      clc.envelope_decision_record(envelope)["input_digest"],
      rec["input_digest"])

bad_sig = copy.deepcopy(envelope)
bad_sig["signatures"][0]["sig"] = "00"
expect_error("tampered DSSE signature is refused",
             "envelope_signature",
             lambda: clc.envelope_verify_record(bad_sig, verify))
multi_sig = clc.new_envelope(rec)
clc.envelope_sign(multi_sig, "bad-key", lambda _payload: "00")
clc.envelope_sign(multi_sig, "good-key", sign)
expect_ok("a later valid signature can satisfy a multi-signature envelope",
          lambda: clc.envelope_verify_record(multi_sig, verify))
bad_type = copy.deepcopy(envelope)
bad_type["payloadType"] = "application/example"
expect_error("wrong envelope payload type is refused",
             "envelope_payload_type",
             lambda: clc.envelope_check(bad_type))
bad_subject = copy.deepcopy(envelope)
statement = clc.envelope_statement(bad_subject)
statement["subject"][0]["digest"]["sha256"] = "00" * 32
bad_subject["payload"] = json.dumps(statement, separators=(",", ":"), sort_keys=True)
expect_error("retargeted envelope subject is refused",
             "envelope_subject_mismatch",
             lambda: clc.envelope_check(bad_subject))


# Action identities and matching -------------------------------------------

definition = clc.action_type_definition("payment.release", ["amount", "currency"])
action = {"amount": 5, "currency": "USD", "note": "not material"}
check("material projection keeps only declared fields",
      clc.material_projection(definition, action),
      {"amount": 5, "currency": "USD"})
check("material field digests cover every declared field",
      len(clc.material_field_digest(definition, action)), 2)
action_string = clc.compute_action_id(definition, clc.SUITE_JCS_SHA256, action)
observed = clc.parse_action_id(action_string)
check("action id string round-trips",
      clc.action_id_string(observed), action_string)
check("same action identity matches exactly",
      clc.match(observed, copy.deepcopy(observed)), clc.MATCH_EXACT)
other = clc.parse_action_id(
    clc.compute_action_id(definition, clc.SUITE_JCS_SHA256,
                          {"amount": 6, "currency": "USD"}))
check("different material is not equivalent",
      clc.match(observed, other), clc.MATCH_NOT_EQUIVALENT)
cross_type = clc.parse_action_id(
    clc.compute_action_id("payment.cancel", ["amount", "currency"],
                          clc.SUITE_JCS_SHA256,
                          {"amount": 5, "currency": "USD"}))
check("cross-type action identity is indeterminate",
      clc.match(observed, cross_type), clc.MATCH_INDETERMINATE)
expect_error("malformed action id is refused",
             "action_shape",
             lambda: clc.parse_action_id(
                 "clc-action:1:payment.release:jcs-sha256:!!"))
expect_error("missing material field is not matchable",
             "action_not_matchable",
             lambda: clc.material_projection(definition, {"amount": 5}))

profile = clc.action_mapping_profile("profile-1", clc.digest_of({"profile": 1}))
check("mapping profile with digest is pinned",
      clc.mapping_profile_pinned(profile), True)
check("pinned identity projector matches",
      clc.map_and_match(profile, lambda _p, ev: ev, observed, observed),
      clc.MATCH_EXACT)
check("unpinned mapping profile is indeterminate",
      clc.map_and_match(
          {"id": "profile-1"}, lambda _p, ev: ev,
          observed, observed),
      clc.MATCH_INDETERMINATE)
check("projector failure is indeterminate",
      clc.map_and_match(
          profile, lambda _p, _ev: (_ for _ in ()).throw(ValueError("loss")),
          observed, observed),
      clc.MATCH_INDETERMINATE)
check("projection into a foreign type is indeterminate",
      clc.map_and_match(profile, lambda _p, _ev: cross_type, observed, observed),
      clc.MATCH_INDETERMINATE)
check("faithful projection of different content is not equivalent",
      clc.map_and_match(profile, lambda _p, _ev: other, observed, observed),
      clc.MATCH_NOT_EQUIVALENT)


# OCMP offline profile ------------------------------------------------------

ocmp_base = {
    "grant_covers": True,
    "trust_anchor": True,
    "local_policy": True,
    "status": {
        "present": True,
        "verified": True,
        "as_of": 10,
        "valid_until": 100,
        "version": 2,
        "last_accepted": 1,
    },
    "trusted_time": 50,
    "clock_offset": 1,
    "clock_tolerance": 2,
}
check("OCMP valid inputs allow", ocmp.evaluate(ocmp_base), ("allow", ""))

ocmp_cases = [
    ("grant", {**ocmp_base, "grant_covers": False}, "capability_not_authorized"),
    ("trust anchor", {**ocmp_base, "trust_anchor": False}, "trust_anchor_missing"),
    ("local policy", {**ocmp_base, "local_policy": False}, "local_policy_missing"),
    ("missing status", {**ocmp_base, "status": {}}, "status_snapshot_missing"),
    ("unverified status", {**ocmp_base, "status": {**ocmp_base["status"], "verified": False}},
     "status_snapshot_missing"),
    ("status not yet valid", {**ocmp_base, "trusted_time": 5}, "status_snapshot_expired"),
    ("status expired", {**ocmp_base, "trusted_time": 101}, "status_snapshot_expired"),
    ("status rollback", {**ocmp_base, "status": {**ocmp_base["status"], "version": 0}},
     "status_snapshot_rollback"),
    ("revoked", {**ocmp_base, "revoked": True}, "revoked"),
    ("credential expired", {**ocmp_base, "credential_expired": True},
     "capability_not_authorized"),
    ("replay equal", {**ocmp_base, "replay_enabled": True, "counter": 5, "last_consumed": 5},
     "replay_detected"),
    ("replay behind", {**ocmp_base, "replay_enabled": True, "counter": 4, "last_consumed": 5},
     "replay_state_invalid"),
    ("fact unavailable", {**ocmp_base, "required_fact": True, "fact_available": False},
     "fact_unavailable"),
    ("clock skew", {**ocmp_base, "clock_offset": 3, "clock_tolerance": 2},
     "clock_unsynchronized"),
]
for label, inputs, reason in ocmp_cases:
    check("OCMP " + label, ocmp.evaluate(inputs), ("deny", reason))
check("OCMP valid replay counter allows",
      ocmp.evaluate({**ocmp_base, "replay_enabled": True,
                     "counter": 6, "last_consumed": 5}),
      ("allow", ""))
check("OCMP available required fact allows",
      ocmp.evaluate({**ocmp_base, "required_fact": True, "fact_available": True}),
      ("allow", ""))


# Scheme declaration --------------------------------------------------------

scheme_base = {
    "@version": "CLC-SCHEME-v1",
    "scheme": "std/payments-v1",
    "declaration_id": "std/payments-v1@test",
    "clc_revision": "CLC-1.19",
    "capabilities": {
        "transfer": {
            "params": {
                "amount": {"domain": "quantity", "unit": "CNY"},
                "currency": {"domain": "enum"},
                "counterparty": {"domain": "enum"},
                "account": {"domain": "enum"},
            }
        }
    },
}
expect_ok("scheme declaration validates",
          lambda: scheme_decl.validate(scheme_base))
digest_decl = copy.deepcopy(scheme_base)
digest_decl["digest"] = scheme_decl._digest(digest_decl)
expect_ok("scheme declaration digest validates",
          lambda: scheme_decl.validate(digest_decl))

scheme_negatives = [
    ("version", {**scheme_base, "@version": "CLC-SCHEME-v2"},
     "unsupported_declaration"),
    ("missing scheme", {**scheme_base, "scheme": ""}, "invalid_declaration"),
    ("no capabilities", {**scheme_base, "capabilities": {}}, "invalid_declaration"),
    ("capability without params", {
        **scheme_base,
        "capabilities": {"transfer": {}},
    }, "invalid_declaration"),
    ("unknown domain", {
        **scheme_base,
        "capabilities": {
            "transfer": {"params": {"amount": {"domain": "money"}}},
        },
    }, "unsupported_domain"),
    ("quantity without unit", {
        **scheme_base,
        "capabilities": {
            "transfer": {"params": {"amount": {"domain": "quantity"}}},
        },
    }, "invalid_declaration"),
    ("unit outside quantity", {
        **scheme_base,
        "capabilities": {
            "transfer": {"params": {"currency": {"domain": "enum", "unit": "CNY"}}},
        },
    }, "invalid_declaration"),
    ("digest mismatch", {**scheme_base, "digest": "sha256:wrong"},
     "declaration_digest_mismatch"),
]
for label, decl, code in scheme_negatives:
    expect_error("scheme " + label, code,
                 lambda decl=decl: scheme_decl.validate(decl))

capability_dir = Path(
    os.environ.get(
        "CLC_CAPABILITY_DIR",
        Path(__file__).resolve().parent.parent / "capability",
    )
)
scheme_loaded = scheme_decl.load(
    capability_dir / "data/std/payments-v1/clc-declaration.json")
grant_quantity = {
    "id": "std/payments-v1:transfer",
    "params": {
        "amount": {"value": 5000, "unit": "CNY"},
        "currency": ["CNY"],
        "counterparty": ["vendor.example"],
        "account": ["account-1"],
    },
}
op_quantity = {
    "id": "std/payments-v1:transfer",
    "params": {
        "amount": {"value": 3000, "unit": "CNY"},
        "currency": "CNY",
        "counterparty": "vendor.example",
        "account": "account-1",
    },
}
check("scheme authorize allows narrower quantity",
      scheme_decl.authorize(scheme_loaded, "transfer",
                            [grant_quantity], op_quantity)["verdict"],
      "allow")
wider_op = copy.deepcopy(op_quantity)
wider_op["params"]["amount"]["value"] = 6000
check("scheme authorize rejects wider quantity",
      scheme_decl.authorize(scheme_loaded, "transfer",
                            [grant_quantity], wider_op)["reason"],
      "params_exceed_grant")
child_quantity = copy.deepcopy(grant_quantity)
child_quantity["params"]["amount"]["value"] = 3000
check("scheme contains accepts narrower quantity",
      scheme_decl.contains(scheme_loaded, "transfer",
                           grant_quantity, child_quantity)["contains"],
      True)
child_quantity["params"]["counterparty"] = ["other.example"]
check("scheme contains rejects wider enum",
      scheme_decl.contains(scheme_loaded, "transfer",
                           grant_quantity, child_quantity)["contains"],
      False)


if FAILS:
    print("\n".join(FAILS))
    sys.exit(1)
print(f"extended_test: {COUNT} checks passed")
