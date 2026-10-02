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
    IJSON_MAX_INTEGER,
    MAX_PARAMS_SERIALIZED_BYTES,
    _reject_non_finite,
    authorize,
    canonical_json,
    validate_constraint,
    validate_params,
    validate_raw_params,
)

GID = "std/database-v1:query:SELECT"
FAILS = []
COUNT = 0


def check(label, got, want):
    global COUNT
    COUNT += 1
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

# Reverse divergence: json.dumps counts MORE than JCS for a decoded int (it
# emits the full-precision literal, where JCS renders the ECMAScript double in
# exponent form), so a payload under-limit on JCS bytes but over-limit under
# json.dumps must NOT be refused.
#
# Retargeted at rev CLC-1.16 §6.2 step 3.  That gap needs |n| >= 1e21, far past
# the I-JSON range, and the step now refuses every integer above 2^53 - 1 — so
# an in-range integer prints the same digits under both and the direction is
# unreachable.  The bound is what closed it; both halves are pinned so that
# relaxing the bound again surfaces here rather than in production.
big_int = int("1234567890" * 6)   # 12345678901234567890, past 2^53 - 1
try:
    validate_params({"n%d" % i: big_int for i in range(17)})
    over_refused = False
except Exception:
    over_refused = True
check("over-bound int refused (closes the reverse-divergence gap)", over_refused, True)

in_range = {"n": IJSON_MAX_INTEGER}       # 2^53 - 1, the largest legal integer
try:
    validate_params(in_range)
    in_range_accepted = True
except Exception:
    in_range_accepted = False
check("largest legal int is still accepted", in_range_accepted, True)
check("in-range int: JCS and json.dumps agree on octets",
      len(canonical_json(in_range).encode("utf-8")),
      len(json.dumps(in_range, separators=(",", ":"), sort_keys=True,
                     ensure_ascii=False).encode("utf-8")))

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

# I-JSON integer bound (rev CLC-1.16 §6.2 step 3): an integer-valued numeric
# param past 2^53-1 has no exact binary64 representation, so it is refused rather
# than rounded.  Decimal is exact for the literal, so the fraction and exponent
# spellings of an over-bound integer are refused too, while a genuine fraction
# below the bound is not an integer and still reads.
ijson_cases = [
    ("at bound 2^53-1", '{"n":9007199254740991}', None),
    ("2^53-1 minus a half", '{"n":9007199254740990.5}', None),
    ("2^53 over", '{"n":9007199254740992}', "invalid_params_number"),
    ("2^53+1 over", '{"n":9007199254740993}', "invalid_params_number"),
    ("2^53+1 negative over", '{"n":-9007199254740993}', "invalid_params_number"),
    ("2^53+1 fraction spelling", '{"n":9007199254740993.0}', "invalid_params_number"),
    ("2^53+1 exponent spelling", '{"n":9.007199254740993e15}', "invalid_params_number"),
    ("20-digit over", '{"n":100000000000000000000}', "invalid_params_number"),
    ("fraction below bound", '{"n":1.5}', None),
    ("negative fraction", '{"n":-0.25}', None),
    ("zero", '{"n":0}', None),
    ("one", '{"n":1}', None),
]
for label, raw, want in ijson_cases:
    try:
        validate_raw_params(raw)
        reason = None
    except Exception as e:
        reason = str(e).split(":")[0]
    check(f"raw {label}", reason, want)

# The decoded entry point must refuse the same values as the raw path, including
# inside a list, so a caller handing over an already-decoded params object cannot
# carry an integer the raw text would have refused.
decoded_cases = [
    ("at bound", 9007199254740991.0, None),
    ("2^53+1 over", 9007199254740993.0, "invalid_params_number"),
    ("fraction", 1.5, None),
    ("over inside a list", [9007199254740993.0], "invalid_params_number"),
    # json.loads yields an exact int for a literal with neither fraction nor
    # exponent, and Python ints are unbounded — a decoded params object can
    # therefore carry an over-bound integer that never becomes a float.
    ("exact int at bound", 9007199254740991, None),
    ("exact int 2^53 over", 9007199254740992, "invalid_params_number"),
    ("exact int 2^53+1 over", 9007199254740993, "invalid_params_number"),
    ("exact int 20-digit over", 10**20, "invalid_params_number"),
    ("exact int negative over", -(10**20), "invalid_params_number"),
    ("exact int inside a list", [10**20], "invalid_params_number"),
    ("ordinary int", 42, None),
    ("bool is not a numeric param", True, None),
]
for label, value, want in decoded_cases:
    try:
        _reject_non_finite({"n": value})
        reason = None
    except Exception as e:
        reason = str(e).split(":")[0]
    check(f"decoded {label}", reason, want)

# §8.1 states the max_rows constraint operand is not exempt from layer-7 closure:
# an over-bound ceiling would be rounded before the "op <= grant" comparison.  The
# reason code is the §8.1 one (invalid_constraint), not the params one.
constraint_bound_cases = [
    ("at bound", "varwof/constraint-v1:max_rows:9007199254740991", None),
    ("zero", "varwof/constraint-v1:max_rows:0", None),
    ("ordinary", "varwof/constraint-v1:max_rows:1000", None),
    ("2^53 over", "varwof/constraint-v1:max_rows:9007199254740992", "invalid_constraint"),
    ("2^53+1 over", "varwof/constraint-v1:max_rows:9007199254740993", "invalid_constraint"),
    ("20-digit over", "varwof/constraint-v1:max_rows:100000000000000000000", "invalid_constraint"),
    ("not an integer", "varwof/constraint-v1:max_rows:10.5", "invalid_constraint"),
    ("unknown scheme", "foo/db-v1:max_rows:9007199254740993", "unknown_constraint"),
]
for label, c, want in constraint_bound_cases:
    try:
        validate_constraint(c)
        reason = None
    except Exception as e:
        reason = str(e).split(":")[0]
    check(f"constraint {label}", reason, want)

if FAILS:
    print("\n".join(FAILS))
    sys.exit(1)
print(f"edge_test: {COUNT} checks passed (non-finite, malformed Unicode, raw JCS-size boundary, I-JSON integer bound in params and constraints)")
