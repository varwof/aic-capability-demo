#!/usr/bin/env python3
"""CLC differential fuzz: axis-directed case generator.

Emits JSONL cases, one per line:

    {"id": "f000123", "axis": "a08",
     "raw": "{\"n\":1e-6,\"s\":\"...\"}",   # operation params as raw JSON text
     "op_id": "std/database-v1:query:SELECT",
     "grant": {...},                       # decoded grant (may be null / {} )
     "note": "near 512 bytes"}

Optional extensions vs the prompt skeleton (documented in README.md):
  - "op_id": the operation capability id (the decision needs one).
  - "no_params": true  -> the operation carries no params at all (raw ignored,
    ignored consistently by both paths; §6.3 "no params field" behavior).
  - "raw_b64": when present, `raw` is the base64 of the *raw text bytes*
    (used for literal-invalid-UTF-8 cases that a UTF-8 JSONL cannot carry).

Fixed seed by default (20260915); determinism is total: identical bytes for a
given --n/--seed.
"""

import argparse
import base64
import json
import random
import sys
from itertools import permutations

LEGEND = {
    "std/database-v1:query:SELECT": "plain limit-less SELECT",
    "std/database-v1:query:*": "wildcard query",
    "std/data-v1:read:dataset": "data read",
    "std/data-v1:fetch:item:42": "deep id",
    "std/payments-v1:transfer": "payments",
    "std/clinical-v1:prescribe:medication": "clinical",
    "std/robot-line-v1:move:joint": "robot",
    "varwof/app-v1:search:query": "custom scheme",
}

# Valid op/grant ids. All satisfy the §3 scheme grammar.
OP_IDS = list(LEGEND.keys())

BAD_IDS = [
    "*", "a:*", "*:query:SELECT", "::", "a::b",
    "std/document-v1", "not-a-valid-id", "database:query",
    "std/database-v1:query:[a-z]", "std/database-v1:query:{read,write}",
    "std/database-v1:query:SEL*", "std/database-v1:query:SELECT:deep",
    "unknown:scheme:action", "bad:op",
]

KNOWN_CONSTRAINTS = [
    "varwof/constraint-v1:max_rows:10",
    "varwof/constraint-v1:max_rows:100",
    "varwof/constraint-v1:time:window:3600",
    'varwof/constraint-v1:network:cidr:["192.0.2.0/24","2001:db8::/32"]',
]

UNKNOWN_CONSTRAINTS = [
    "unknown:constraint:type",
    "payments:quota:daily:1000000",
    "varwof/constraint-v1:unknown",
]


def esc_elem(cp: int) -> int:
    """JCS (§3.2.2.2) octet length of one decoded character."""
    if cp in (0x22, 0x5C) or cp in (0x08, 0x09, 0x0A, 0x0C, 0x0D):
        return 2
    if cp < 0x20:
        return 6
    return len(chr(cp).encode("utf-8"))


def utf16_units(s: str) -> list:
    out = []
    for ch in s:
        o = ord(ch)
        if o >= 0x10000:
            o -= 0x10000
            out.append(0xD800 + (o >> 10))
            out.append(0xDC00 + (o & 0x3FF))
        else:
            out.append(o)
    return out


def jcs_len(v) -> int:
    """Compact RFC 8785 serialized byte length (for size targeting)."""
    if v is None:
        return 4
    if v is True or v is False:
        return 4 if v else 5
    if isinstance(v, (int, float)):
        return len(_fmt_num(v))
    if isinstance(v, str):
        return 2 + sum(esc_elem(ord(c)) for c in v)
    if isinstance(v, (list, tuple)):
        return 1 + sum(jcs_len(x) for x in v) + max(0, len(v) - 1) + 1
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=utf16_units)
        body = ""
        return 1 + sum(
            (2 + sum(esc_elem(ord(c)) for c in k) + 1 + jcs_len(v[k]) + (1 if i else 0))
            for i, k in enumerate(keys)
        ) + 1
    raise TypeError(type(v))


def _fmt_num(n):
    if isinstance(n, int):
        return str(n)
    if n == 0:
        return "0" if not (1 / n < 0) else "-0"
    if n != n:
        return "null"
    if n in (float("inf"), float("-inf")):
        return "null"
    s = repr(float(n))
    if "e" in s:
        mant, exp = s.split("e")
        exp = int(exp)
        if exp >= 21 or exp <= -7:
            sign = "-" if mant.startswith("-") else ""
            mant = mant.lstrip("-")
            return f"{sign}{mant}e{'%+03d' % exp}"
    return s


def depth_of(v, depth=1):
    if isinstance(v, dict):
        return max([depth] + [depth_of(x, depth + 1) for x in v.values()])
    if isinstance(v, (list, tuple)):
        return max([depth] + [depth_of(x, depth + 1) for x in v])
    return depth


def render(v):
    return json.dumps(v, ensure_ascii=True, separators=(",", ":"))


def wrap_note(axis, note):
    return f"{axis}: {note}"


A = {}


def case(axis, raw, grant, op_id, note, no_params=False, raw_text=None,
        raw_bytes=None):
    c = {
        "axis": axis,
        "raw": raw if raw_text is None else raw_text,
        "op_id": op_id,
        "grant": grant,
        "note": wrap_note(axis, note),
    }
    if no_params:
        c["no_params"] = True
    if raw_bytes is not None:
        c["raw_b64"] = base64.b64encode(raw_bytes).decode("ascii")
        c.pop("raw", None)
    return c


def attrs(op_id):
    return {"id": op_id}


# ----------------------------------------------------------------------------
# axis a01 key order
# ----------------------------------------------------------------------------
def make_key_order(rng, n):
    pool = [
        {"limit": 100, "dataset": "sales", "granular": "day",
         "t\u00e9mp\u00e9rature": 22.5, "\u8d26\u76ee": "ledger",
         "zoo": ["a", "b"], "\U0001f600": 1},
        {"a": 1, "b": 2, "c": 3},
        {"": 0, "k": "v", "\u0001x": 1},
        {"nested": {"inner": {"deep": "v"}, "other": [1, 2, 3]}},
    ]
    out = []
    pid = 0
    for params in pool:
        keys = list(params.keys())
        orders = list(permutations(keys)) if len(keys) <= 5 else [keys, list(reversed(keys))]
        # cap permutations for determinism/size
        rng.shuffle(orders)
        for ord_ in orders[: min(12, len(orders))]:
            ordered = {k: params[k] for k in ord_}
            raw = render(ordered)
            op_id = OP_IDS[pid % len(OP_IDS)]
            out.append(case("a01", raw, attrs(op_id), op_id,
                            "key order %s" % (ord_,)))
            pid += 1
    # augment with purely random key orders
    for _ in range(max(0, n - len(out))):
        k = rng.randint(1, 6)
        params = {}
        for i in range(k):
            key = rng.choice(["p", "zz", "aa", "m", "0", "k\u00e9",
                              "\u00fc", "\u4e00", "A", "B"])
            params[key] = rng.choice([1, "v", True, [], {}, 2.5, None])
        raw = render(params)
        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a01", raw, attrs(op_id), op_id, "random key order"))
    return out


# ----------------------------------------------------------------------------
# axis a02 duplicate keys (raw must reject; decoded path cannot see them)
# ----------------------------------------------------------------------------
def make_dup_keys(rng, n):
    out = []
    templates = [
        ('{"limit":100,"limit":200}', "single dup int"),
        ('{"a":1,"a":2,"a":3}', "triple dup"),
        ('{"k":"x","k":"y"}', "dup string"),
        ('{"o":{"b":1,"b":2}}', "nested dup"),
        ('{"a":{"b":1,"b":2},"c":[1,2]}', "dup + array"),
        ('{"k":null,"k":false}', "dup null/false"),
        ('{"1":1,"1":2}', "numeric-name dup"),
        ('{"a":"\u00e9","a":"\u00ea"}', "dup unicode value"),
    ]
    i = 0
    while len(out) < n:
        if i < len(templates):
            raw, note = templates[i]
            i += 1
        else:
            k = rng.choice(["x", "limit", "a", "1"])
            v1 = rng.choice([1, "v", True, None, [1], {"q": 1}])
            v2 = rng.choice([2, "w", False, 1, [2], {"q": 2}])
            raw = '{%s:%s,%s:%s}' % (json.dumps(k), render(v1), json.dumps(k), render(v2))
            note = "random dup pair"
        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a02", raw, attrs(op_id), op_id, note))
    return out


# ----------------------------------------------------------------------------
# axis a03 unicode
# ----------------------------------------------------------------------------
def make_unicode(rng, n):
    out = []
    valid = [
        # NFC / NFD pairs; escape vs literal; hex case; surrogate pair; exotic
        ('{"s":"\u00e9"}', "NFC \u00e9"),
        ('{"s":"\u0065\u0301"}', "NFD e+combining"),
        ('{"s":"\\u00e9"}', "\\u escape (lowercase hex)"),
        ('{"s":"\\u00E9"}', "\\u escape (uppercase hex)"),
        ('{"s":"caf\\u00e9"}', "\\u mid-word"),
        ('{"s":"\\ud83d\\ude00"}', "valid surrogate pair (emoji)"),
        ('{"s":"\U0001F600"}', "literal astral char"),
        ('{"s":"\u2028"}', "U+2028 raw"),
        ('{"s":"\\u2028"}', "U+2028 escape"),
        ('{"s":"\u2029"}', "U+2029 raw"),
        ('{"s":"\\u007f"}', "DEL escape"),
        ('{"s":"\\u0001"}', "control 0x01 escape"),
        ('{"key\u00e9":"v"}', "non-ascii key"),
        ('{"s":"&<>"}', "& < > raw (JCS keeps raw)"),
        ('{"s":"\\u0026\\u003c\\u003e"}', "& < > as escapes"),
        ('{"s":"a\\"b\\\\c"}', "escaped quote/backslash"),
    ]
    i = 0
    while len(out) < n:
        if i < len(valid):
            raw, note = valid[i]
            i += 1
        else:
            cp = rng.choice([0xE9, 0x4F60, 0x2028, 0x1F600, 0x7F, 0x2603])
            ch = chr(cp) if cp != 0x2028 else "\u2028"
            raw = '{"s":%s}' % (json.dumps(ch, ensure_ascii=rng.random() < 0.5),)
            note = "random unicode"

        # tool the malformed ones: lone surrogate escapes (raw MUST reject)
        if rng.random() < 0.18:
            esc = rng.choice(["\\ud800", "\\udc00", "\\ud83d", "\\ud800\\u0041",
                              "\\udc80", "\\udfff"])
            raw = '{"s":"%s"}' % (esc,)
            note = "lone surrogate escape %s" % esc
            op_id = OP_IDS[rng.randrange(len(OP_IDS))]
            out.append(case("a03", raw, attrs(op_id), op_id, note))
            continue

        # literal invalid-UTF-8 raw bytes (only expressible via raw_b64)
        if rng.random() < 0.04:
            blob = rng.choice([
                b'{"s":"\xff"}',
                b'{"s":"\xed\xa0\x80"}',
                b'{"\xff":1}',
                b'{"s":1}\xff ',
            ])
            op_id = OP_IDS[rng.randrange(len(OP_IDS))]
            out.append(case("a03", "", attrs(op_id), op_id,
                            "literal invalid-UTF-8 bytes (raw_b64)",
                            raw_bytes=blob))
            continue

        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a03", raw, attrs(op_id), op_id, note))
    return out


# ----------------------------------------------------------------------------
# axis a04 numbers
# ----------------------------------------------------------------------------
def make_numbers(rng, n):
    numeric = [
        "1", "1.0", "1.00", "1e0", "1e1", "-0", "-0.0", "0", "-1",
        "1e-6", "0.000001", "0.30000000000000004",
        "12345678901234567890", "99999999999999999", "0.1234567890123456789",
        "1e400", "-1e400", "100000000000000000000",
        "9007199254740993", "2.220446049250313e-16", "5e-324", "1.7976931348623157e308",
        "-2.2250738585072014e-308", "0.1", "0.2", "0.1e-3",
        "123", "12.34", "-12.34", "0.00000000000000001", "1e-999999",
    ]
    i = 0
    out = []
    while len(out) < n:
        if i < len(numeric):
            lit = numeric[i]
            i += 1
            note = "literal %s" % lit
        else:
            lit = rng.choice(numeric)
            note = "random literal reuse"
        as_key = rng.random() < 0.05
        if as_key:
            raw = '{%s:%s}' % (json.dumps(lit), render(rng.choice([1, True, "v", None])))
        else:
            raw = '{"n":%s}' % (lit,)
            if rng.random() < 0.3:
                extra = rng.choice(["k", "z", "\u00e9x"])
                raw = '{"n":%s,"%s":%s}' % (lit, extra, lit)
        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a04", raw, attrs(op_id), op_id, note))
    return out


# ----------------------------------------------------------------------------
# axis a05 missing vs null vs empty
# ----------------------------------------------------------------------------
def make_missing(rng, n):
    templates = [
        ("{}", "empty object"),
        ('{"k":null}', "param null"),
        ('{"k":""}', "param empty string"),
        ('{"k":[]}', "param empty array"),
        ('{"k":{}}', "param empty object"),
    ]
    out = []
    i = 0
    while len(out) < n:
        if i < len(templates):
            raw, note = templates[i]
            i += 1
        else:
            k = rng.choice(["a", "limit", "x", "\u00e9"])
            v = rng.choice([None, "", [], {}, 0, False])
            raw = '{%s:%s}' % (json.dumps(k), render(v))
            note = "random empty-ish value"
        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        # no-params flavor (~15%)
        if rng.random() < 0.15:
            out.append(case("a05", "", attrs(op_id), op_id,
                            "operation without params", no_params=True))
        else:
            out.append(case("a05", raw, attrs(op_id), op_id, note))
    return out


# ----------------------------------------------------------------------------
# axis a06 types
# ----------------------------------------------------------------------------
def make_types(rng, n):
    type_pairs = [
        (1, '"1"'), (True, '"true"'), (False, '"false"'), (None, "false"),
        ([], "{}"), ([1], '""'), (0, "[]"), ({"a": 1}, "{}"),
    ]
    out = []
    i = 0
    while len(out) < n:
        if i < len(type_pairs):
            a, b = type_pairs[i]
            i += 1
            if rng.random() < 0.5:
                a, b = b, a
            av = render(a) if not isinstance(a, str) else a
            bv = render(b) if not isinstance(b, str) else b
            raw = '{"v":%s,"w":%s}' % (av, bv)
            note = "type pair %s vs %s" % (
                json.loads(av).__class__.__name__,
                json.loads(bv).__class__.__name__,
            )
        else:
            values = [1, "1", True, "true", [], {}, None, False]
            ra = rng.choice(values)
            rb = rng.choice(values)
            raw = '{"a":%s,"b":%s}' % (render(ra), render(rb))
            note = "random type pair"
        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a06", raw, attrs(op_id), op_id, note))
    return out


# ----------------------------------------------------------------------------
# axis a07 arrays
# ----------------------------------------------------------------------------
def make_arrays(rng, n):
    variants = [
        [1, 2, 3], [3, 2, 1], [1, 2, 3, 1, 2, 3], [1], [], [[]],
        [True, False, None], [[1, 2], [3]], ["a", "a", "a"],
        [0, 0], [1e0, 1.0, 1],
    ]
    out = []
    for _ in range(n):
        arr = rng.choice(variants)
        if rng.random() < 0.3:
            arr = [rng.choice([1, "x", True, None, 2.5]) for _ in range(rng.randint(0, 6))]
        raw = '{"a":%s}' % (render(arr),)
        note = "array variant"
        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a07", raw, attrs(op_id), op_id, note))
    return out


# ----------------------------------------------------------------------------
# axis a08 size/depth (JCS octets near 512, depth near 32)
# ----------------------------------------------------------------------------
def pad_param_object(rng, target_size):
    """Build an object whose JCS serialized length is exactly target_size."""
    # structural: {"s":"<chars>","d":<int>}
    base = '{"s":"","x":1}'
    fixed = jcs_len({"s": "", "x": 1})
    s_len = target_size - fixed
    s = "a" * s_len
    return {"s": s, "x": 1}


def make_sizes(rng, n):
    out = []
    targets = [508, 509, 510, 511, 512, 513, 514, 515, 516]
    for t in targets:
        obj = pad_param_object(rng, t)
        raw = render(obj)
        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a08", raw, attrs(op_id), op_id,
                        "JCS size %d" % t))
        # non-ascii / &<> flavor at same size
        obj2 = {"s": "&<>" + "a" * (t - jcs_len({"s": "&<>", "x": 1})), "x": 1}
        raw2 = render(obj2)
        op_id2 = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a08", raw2, attrs(op_id2), op_id2,
                        "JCS size %d with &<>" % t))
    for _ in range(max(0, n - len(out))):
        t = rng.choice([506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518])
        obj = pad_param_object(rng, t)
        raw = render(obj)
        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a08", raw, attrs(op_id), op_id,
                        "random size %d" % t))
    return out[:]


def make_depths(rng, n):
    out = []
    for depth in [30, 31, 32, 33, 34, 35]:
        # params object counts as level 1; nest inside arrays alternating
        v = 0
        for _ in range(depth - 1):
            v = [v]
        raw = render(v)
        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a08", raw, attrs(op_id), op_id,
                        "depth %d (array spine)" % depth))
        v = {}
        for _ in range(depth - 1):
            v = {"nx": v}
        raw = render(v)
        out.append(case("a08", raw, attrs(op_id), op_id,
                        "depth %d (object spine)" % depth))
    for _ in range(max(0, n - len(out))):
        depth = rng.choice([29, 30, 31, 32, 33, 34, 35])
        v = 1
        for _ in range(depth - 1):
            v = [v]
        for _ in range(rng.randint(0, 2)):
            k = "k%d" % rng.randint(0, 3)
            v = {k: v}
        op_id = OP_IDS[rng.randrange(len(OP_IDS))]
        out.append(case("a08", render(v), attrs(op_id), op_id,
                        "mixed depth ~%d" % depth))
    return out


# ----------------------------------------------------------------------------
# axis a09 constraint identity
# ----------------------------------------------------------------------------
def make_constraints(rng, n):
    out = []
    templates = [
        (KNOWN_CONSTRAINTS[0], "known max_rows:10"),
        (KNOWN_CONSTRAINTS[1], "known max_rows:100"),
        (KNOWN_CONSTRAINTS[2], "known time:window:3600"),
        (KNOWN_CONSTRAINTS[3], "known network cidr"),
        ("time:window:3600", "segmented-looking constraint (no scheme)"),
        ("max_rows:10", "bare-looking constraint (no scheme)"),
        ("varwof/constraint-v1:max_rows:abc", "max_rows with non-numeric bound"),
        ("varwof/constraint-v1:time:window:oops", "time with bad window"),
        ("payments:quota:daily:1000000", "non-varwof scheme"),
        ("unknown:constraint:type", "unknown constraint type"),
    ]
    i = 0
    while len(out) < n:
        if i < len(templates):
            cons, note = templates[i]
            i += 1
        else:
            cons = rng.choice(KNOWN_CONSTRAINTS + UNKNOWN_CONSTRAINTS)
            note = "random constraint"
        grant = {"id": "std/database-v1:query:SELECT",
                 "constraints": [cons]}
        op_id = "std/database-v1:query:SELECT"
        out.append(case("a09", '{"max_rows":%s}' % rng.choice(["5", "50", "10"]),
                        grant, op_id, note))
    return out


# ----------------------------------------------------------------------------
# axis a10 id shapes
# ----------------------------------------------------------------------------
def make_ids(rng, n):
    out = []
    # op / grant_id pairs
    pairs = [
        ("std/database-v1:query:SELECT", "std/database-v1:query:SELECT", "exact id"),
        ("std/database-v1:query:INSERT", "std/database-v1:query:*", "wildcard grant"),
        ("std/database-v1:query:SELECT", "std/data-v1:read:dataset", "different namespace"),
        ("std/database-v1:query", "std/database-v1:query:*", "short op vs wildcard"),
        ("std/database-v1:query:SELECT:deep", "std/database-v1:query:SELECT", "deep op"),
        ("*", "std/database-v1:query:SELECT", "op bare wildcard"),
        ("a:*", "std/database-v1:query:SELECT", "op malformed scheme"),
        ("*:query:SELECT", "std/database-v1:query:SELECT", "op wildcard head"),
        ("", "std/database-v1:query:SELECT", "empty op id"),
        ("std/database-v1:query:[a-z]", "std/database-v1:query:*", "op with char class"),
    ]
    i = 0
    while len(out) < n:
        if i < len(pairs):
            op_id, grant_id, note = pairs[i]
            i += 1
        else:
            op_id = rng.choice(OP_IDS + BAD_IDS)
            grant_id = rng.choice(OP_IDS + BAD_IDS or [""])
            note = "random id pair"
        grant = {"id": grant_id} if grant_id != "" else {}
        out.append(case("a10", '{"q":1}', grant if grant else None,
                        op_id, note))
    return out


# ----------------------------------------------------------------------------
# boundary-only set (CI candidate, ~2000 cases)
# ----------------------------------------------------------------------------
def make_boundary(rng):
    out = []
    sizes = list(range(506, 519))
    for t in sizes:
        out.append(case("a08", render(pad_param_object(rng, t)),
                        attrs("std/database-v1:query:SELECT"),
                        "std/database-v1:query:SELECT", "size %d" % t))
    for depth in [28, 29, 30, 31, 32, 33, 34, 35, 36]:
        v = 0
        for _ in range(depth - 1):
            v = [v]
        out.append(case("a08", render(v),
                        attrs("std/database-v1:query:SELECT"),
                        "std/database-v1:query:SELECT", "depth %d" % depth))
    sur = ["\\ud800", "\\udc00", "\\ud83d", "\\ud800\\u0041", "\\ud83d\\ude00",
           "\\udfff", "\\udc00\\ud800"]
    for esc in sur:
        out.append(case("a03", '{"s":"%s"}' % esc,
                        attrs("std/database-v1:query:SELECT"),
                        "std/database-v1:query:SELECT",
                        "surrogate edge %s" % esc))
    dup = ['{"k":1,"k":2}', '{"o":{"a":"x","a":"y"}}',
           '{"a":null,"a":false}', '{"1":1,"1":2}']
    for d in dup:
        out.append(case("a02", d, attrs("std/database-v1:query:SELECT"),
                        "std/database-v1:query:SELECT", "dup edge %s" % d))
    nums = ["9999999999999999999", "1e400", "0.30000000000000004", "-0",
            "12345678901234567890", "5e-324"]
    for lit in nums:
        out.append(case("a04", '{"n":%s}' % lit,
                        attrs("std/database-v1:query:SELECT"),
                        "std/database-v1:query:SELECT", "number edge %s" % lit))
    # fill up to ~2000 with random near-boundary sizes
    while len(out) < 2000:
        t = rng.choice([511, 512, 513])
        out.append(case("a08", render(pad_param_object(rng, t)),
                        attrs("std/database-v1:query:SELECT"),
                        "std/database-v1:query:SELECT", "size %d (boundary fill)" % t))
    return out


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="CLC differential fuzz generator")
    ap.add_argument("--n", type=int, default=100000)
    ap.add_argument("--seed", type=int, default=20260915)
    ap.add_argument("--boundary", action="store_true",
                    help="emit only the boundary set (~2000 cases)")
    ap.add_argument("--bypen", type=float, default=1.0,
                    help="multiplier for unicode/dup/number mixing")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    all_cases = []
    if args.boundary:
        all_cases.extend(make_boundary(rng))
    else:
        each = args.n // 10
        builders = [
            (make_key_order, "a01"), (make_dup_keys, "a02"),
            (make_unicode, "a03"), (make_numbers, "a04"),
            (make_missing, "a05"), (make_types, "a06"),
            (make_arrays, "a07"), (make_sizes, "a08"),
            (make_depths, "a08"), (make_constraints, "a09"),
            (make_ids, "a10"),
        ]
        # merge the two a08 sub-generators
        sizes = make_sizes(rng, each // 2 or 1)
        depths = make_depths(rng, max(1, each - len(sizes)))
        seq = [
            (sizes, "a08"),
            (depths, "a08"),
        ]
        order = list(range(10))
        for idx, (fn, ax) in enumerate(builders):
            if ax == "a08":
                continue
            k = each
            if ax == "a03":
                k = int(k * args.bypen)
            elif ax in ("a02", "a04"):
                k = int(k * args.bypen)
            seq.insert(idx, (fn(rng, k), ax))
        for cas, ax in seq:
            all_cases.extend(cas)

    # deterministic id assignment
    rng2 = random.Random(args.seed ^ 0xBEEF)
    counts = {}
    for i, c in enumerate(all_cases):
        c["id"] = "f%06d" % (i + 1)
        counts[c["axis"]] = counts.get(c["axis"], 0) + 1
        sys.stdout.write(json.dumps(c, ensure_ascii=True) + "\n")
    print("axis counts: %s" % json.dumps(counts, sort_keys=True), file=sys.stderr)
    print("total: %d (seed %d, boundary=%s)" % (len(all_cases), args.seed,
                                                args.boundary), file=sys.stderr)


if __name__ == "__main__":
    main()