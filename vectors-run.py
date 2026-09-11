#!/usr/bin/env python3
"""
CLC-v1 vectors runner - reads vectors.json and runs them against the
Python semantics implementation.

Asserts BOTH verdict and reason (canonical code, CLC-v1 §9.4: the code is
everything before the first ':').
"""
import json
import os
import sys

from clc_semantics import (
    authorize,
    entails,
    intersect,
    validate_capability_id,
    validate_raw_params,
    revision_compatible,
    CLCError,
)


def canonical_reason(s):
    """Stable reason code: everything before the first ':' (§9.4)."""
    if not s:
        return ""
    return s.split(":", 1)[0] if ":" in s else s


def check_result(expect: dict, got: dict) -> str:
    """Compare the merged grant against the vector's result assertions (§7)."""
    if "result_params" in expect:
        want = expect["result_params"] or {}
        have = got.get("params") or {}
        if json.dumps(want, sort_keys=True) != json.dumps(have, sort_keys=True):
            return "result_params want=%s got=%s" % (
                json.dumps(want, sort_keys=True), json.dumps(have, sort_keys=True))
    if "result_constraints" in expect:
        want = sorted(expect["result_constraints"] or [])
        have = sorted(got.get("constraints") or [])
        if want != have:
            return "result_constraints want=%s got=%s" % (want, have)
    return ""


def run_vector(v: dict) -> dict:
    """Run a single vector and return the result (verdict + reason check)."""
    r = {"id": v["id"], "kind": v["kind"]}

    kind = v["kind"]
    expect = v["expect"]
    r["expect"] = expect["verdict"]
    r["note"] = ""
    r["exp_reason"] = canonical_reason(expect.get("reason", ""))
    r["reason"] = ""

    # Input-boundary pre-checks. Language revision (§12.1) and raw params
    # normalization (§6.2) resolve before any §9.3 layer, so they
    # short-circuit the whole evaluation when they fail.
    if kind in ("entail", "decide"):
        revision = v.get("clc_revision", "")
        if revision and not revision_compatible(revision):
            r["got"] = "deny"
            r["reason"] = canonical_reason("unsupported_language_revision")
            r["pass"] = r["got"] == r["expect"] and r["reason"] == r["exp_reason"]
            return r
        raw_params = v.get("raw_params", "")
        if raw_params:
            try:
                validate_raw_params(raw_params)
            except CLCError as e:
                r["got"] = "deny"
                r["reason"] = canonical_reason(str(e))
                r["pass"] = r["got"] == r["expect"] and r["reason"] == r["exp_reason"]
                return r

    if kind == "syntax":
        try:
            validate_capability_id(v["request"]["id"])
            r["got"] = "valid"
        except CLCError as e:
            r["got"] = "invalid"
            r["reason"] = canonical_reason(str(e))
        r["pass"] = r["got"] == r["expect"] and r["reason"] == r["exp_reason"]

    elif kind == "entail":
        result = entails(v["grant"], v["request"])
        r["got"] = "allow" if result["entails"] else "deny"
        r["reason"] = canonical_reason(result.get("reason", ""))
        r["pass"] = r["got"] == r["expect"] and r["reason"] == r["exp_reason"]

    elif kind == "intersect":
        # A null grant with no `others` is the zero-source intersection
        # (§7 rule 5 -> absent_source), so the grant is only collected
        # when it is actually present.
        grants = ([] if v.get("grant") is None else [v["grant"]]) + v.get("others", [])
        merged = None
        try:
            merged = intersect(grants)
            r["got"] = "allow"
        except CLCError as e:
            r["got"] = "deny"
            r["reason"] = canonical_reason(str(e))
        note = ""
        if merged is not None:
            note = check_result(expect, merged)
        r["note"] = note
        r["pass"] = (not note) and r["got"] == r["expect"] and r["reason"] == r["exp_reason"]

    elif kind == "decide":
        grant = v.get("grant")
        op = v.get("request")

        others = v.get("others", [])
        if others:
            try:
                grant = intersect([grant] + others)
            except CLCError as e:
                r["got"] = "deny"
                r["reason"] = canonical_reason(str(e))
                r["pass"] = r["got"] == r["expect"] and r["reason"] == r["exp_reason"]
                return r

        # authorize() is fail-closed on absent/empty grant (§9 layer 10).
        result = authorize(grant, op)
        r["got"] = result["verdict"]
        r["reason"] = canonical_reason(result.get("reason", ""))
        r["pass"] = r["got"] == r["expect"] and r["reason"] == r["exp_reason"]

    return r


def main():
    path = os.environ.get("CLC_VECTORS")
    if not path:
        path = os.path.join(
            os.path.dirname(__file__),
            "..", "capability", "data", "_vectors", "clc-v1", "vectors.json"
        )

    with open(path) as f:
        vectors = json.load(f)

    results = []
    pass_count = 0
    fail_count = 0
    reason_fail_count = 0

    for v in vectors:
        r = run_vector(v)
        results.append(r)
        if r["pass"]:
            pass_count += 1
        else:
            if r["reason"] != r["exp_reason"]:
                reason_fail_count += 1
            fail_count += 1

    # Print results
    print(f"{'ID':<20} {'KIND':<8} {'GOT':<12} {'EXP-VERDICT':<19} {'EXP-REASON':<22} {'GOT-REASON':<22} {'NOTE':<30} {'RESULT'}")
    print("-" * 150)
    for r in results:
        status = "PASS" if r["pass"] else "FAIL"
        print(f"{r['id']:<20} {r['kind']:<8} {r['got']:<12} {r['expect']:<19} {r['exp_reason']:<22} {r['reason']:<22} {r.get('note', ''):<30} {status}")
    print("-" * 150)
    print(f"Total: {len(results)} | Pass: {pass_count} | Fail: {fail_count} | Reason-fail: {reason_fail_count}")

    sys.exit(1 if fail_count > 0 else 0)


if __name__ == "__main__":
    main()