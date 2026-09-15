#!/usr/bin/env python3
"""Edge-case checks that a JSON corpus cannot carry (rev CLC-1.4).

JSON cannot represent NaN or +/-Infinity, so the "a value no bound check can
compare must not become an allow" rule is pinned here rather than in
vectors.json.  Run: python3 edge_test.py
"""
import json
import math
import sys

from clc_semantics import (
    MAX_PARAMS_SERIALIZED_BYTES,
    authorize,
    canonical_json,
    validate_params,
    validate_raw_params,
)

GID = "std/database-v1:query:SELECT"
FAILS = []


def check(label, got, want):
    if got != want:
        FAILS.append(f"{label}: got {got}, want {want}")


for name, value in (("NaN", math.nan), ("+Inf", math.inf), ("-Inf", -math.inf)):
    d = authorize({"id": GID, "params": {"limit": 100}}, {"id": GID, "params": {"limit": value}})
    check(f"{name} under a numeric bound", (d.get("verdict"), d.get("reason")),
          ("deny", "invalid_params_number"))

d = authorize({"id": GID, "constraints": ["varwof/constraint-v1:max_rows:10"]},
              {"id": GID, "params": {"max_rows": math.nan}})
check("NaN max_rows (refused at the input boundary, before the constraint runs)",
      d.get("reason"), "invalid_params_number")

# Malformed Unicode on the decoded path (rev CLC-1.6): a lone surrogate must
# yield the same stable denial (the code before the first ":") as the raw
# boundary check.  A Python str can carry a lone surrogate; `.encode("utf-8")`
# on it raises an uncaught UnicodeEncodeError unless it is refused before any
# serialization.
for label, key, value in (
    ("lone surrogate value", "s", "\ud800"),
    ("lone surrogate key", "\udc00", 1),
    ("lone surrogate deep", "s", ["x", {"t": "\udbff"}]),
):
    d = authorize({"id": GID, "params": {"limit": 100}},
                  {"id": GID, "params": {key: value}})
    check(label, (d.get("reason") or "").split(":")[0], "invalid_params_number")

# The decoded size check must count the JCS (RFC 8785) bytes, not json.dumps:
# {"n":1e-06, "a":<494 a's>} is 514 JCS bytes ("0.000001") but json.dumps
# counts 509 ("1e-06") and would allow it.
big_a = {"n": 1e-6, "a": "a" * 494}
assert len(canonical_json(big_a).encode("utf-8")) > MAX_PARAMS_SERIALIZED_BYTES
assert (len(json.dumps(big_a, separators=(",", ":"), sort_keys=True,
                       ensure_ascii=False).encode("utf-8"))
        <= MAX_PARAMS_SERIALIZED_BYTES)
d = authorize({"id": GID, "params": {"limit": 100}}, {"id": GID, "params": big_a})
check("1e-6 + 494 a's (JCS 514, json.dumps 509)", d.get("reason"), "invalid_params_size")

# Reverse divergence: json.dumps counts MORE than JCS for decoded ints (it
# emits the full-precision literal, where JCS renders the ECMAScript double in
# exponent form), so a payload under-limit on JCS bytes but over-limit under
# json.dumps must NOT be refused.
big_int = int("1234567890" * 6)
reverse_ok = {"n%d" % i: big_int for i in range(17)}
assert len(canonical_json(reverse_ok).encode("utf-8")) <= MAX_PARAMS_SERIALIZED_BYTES
assert (len(json.dumps(reverse_ok, separators=(",", ":"), sort_keys=True,
                       ensure_ascii=False).encode("utf-8"))
        > MAX_PARAMS_SERIALIZED_BYTES)
try:
    validate_params(reverse_ok)
    reversed_refused = False
except Exception:
    reversed_refused = True
check("reverse divergence (JCS under-limit must not be refused)", reversed_refused, False)

# Raw path must use JCS octet counting (§3.2.2.2), so the raw boundary agrees
# with the decoded path: non-shortcut control characters (`\u0011`) count 6
# octets, shortcut controls `\t` count 2, `"` and `\` count 2, `&`/`<`/`>`
# count 1, and U+2028/U+2029 count 3 (raw UTF-8).  Each boundary case is
# chosen so one side of the limit is OK and the other refuses.
raw_cases = [
    ("ctl_u0011 x250 invalid (6×250+8=1508 > 512)",
     '{"s":"' + '\\u0011' * 250 + '"}', "invalid_params_size"),
    ("quote x256 invalid (2×256+8=520 > 512)",
     '{"s":"' + '\\u0022' * 256 + '"}', "invalid_params_size"),
    ("backslash x256 invalid (2×256+8=520 > 512)",
     '{"s":"' + '\\u005c' * 256 + '"}', "invalid_params_size"),
    ("u2028 x160 ok (3×160+8=488 ≤ 512)",
     '{"s":"' + '\\u2028' * 160 + '"}', None),
    ("u2028 x169 invalid (3×169+8=515 > 512)",
     '{"s":"' + '\\u2028' * 169 + '"}', "invalid_params_size"),
    ("amp x250 ok (1×250+8=258 ≤ 512)",
     '{"s":"' + '&' * 250 + '"}', None),
    ("tab x250 ok (2×250+8=508 ≤ 512)",
     '{"s":"' + '\\t' * 250 + '"}', None),
]
for label, raw, want in raw_cases:
    try:
        validate_raw_params(raw)
        reason = None
    except Exception as e:
        reason = str(e).split(":")[0]
    check(f"raw {label}", reason, want)

if FAILS:
    print("\n".join(FAILS))
    sys.exit(1)
print("edge_test: 18 checks passed (non-finite, malformed Unicode, raw JCS-size boundary)")
