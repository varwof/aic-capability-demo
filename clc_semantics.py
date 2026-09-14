"""
CLC-v1 Capability Language Core - Python reference implementation.

This is an independent implementation of the CLC-v1 authorization semantics.
It is NOT a translation of the Go implementation; it follows the spec directly.
The对外判决 must match the Go implementation exactly.
"""
import base64
import hashlib
import json
import math
import re
import sys
from decimal import Decimal
from typing import Any, Callable, Optional


class CLCError(Exception):
    """Base error for CLC-v1 violations."""
    pass


class UnsupportedWildcard(CLCError):
    pass


class InvalidCapabilityID(CLCError):
    pass


class MissingCapabilityID(CLCError):
    pass


class InvalidParamsNull(CLCError):
    pass


class ParamsMissing(CLCError):
    pass


class ParamsUndeclared(CLCError):
    pass


class CapabilityNotAuthorized(CLCError):
    pass


class UnknownConstraint(CLCError):
    pass


class InvalidConstraint(CLCError):
    """Recognized constraint type whose value is out of the §8.1 value
    grammar (rev CLC-1.2)."""
    pass


class InvalidParamsDuplicateKey(CLCError):
    pass


class InvalidParamsNumber(CLCError):
    pass


class InvalidParamsSize(CLCError):
    pass


class UnsupportedLanguageRevision(CLCError):
    pass


class CanonicalJSONError(CLCError):
    """A value has no RFC 8785 (JCS) encoding (non-finite number, lone
    surrogate, or a type JSON does not carry)."""
    pass


# Verdicts (rev CLC-1.3: allow_unresolved is the independent verdict for
# recognized-but-unevaluated constraint obligations, §8.4).
VERDICT_ALLOW = "allow"
VERDICT_DENY = "deny"
VERDICT_ALLOW_UNRESOLVED = "allow_unresolved"

# Recognized constraint (scheme,type) identities (§8.1, rev CLC-1.3): the
# type name alone never selects an evaluator.  Only `varwof/constraint-v1`
# declares core-recognized types; any other scheme's constraint fails closed
# with unknown_constraint.
RESERVED_SCHEME = "varwof/constraint-v1"
KNOWN_CONSTRAINT_TYPES = {"max_rows", "time", "network"}
RECOGNIZED_CONSTRAINT_IDENTITIES = {
    f"{RESERVED_SCHEME}:{t}" for t in KNOWN_CONSTRAINT_TYPES
}

# CLC-v1 §12.1: the language revision this implementation declares.
# (rev CLC-1.3 · 2026-09-12: CLC-1.3 is additive — `allow_unresolved`
# verdict + §9.3 identity/aggregation clarifications — so CLC-1.2/1.1
# inputs still read fine.)
# (rev CLC-1.6 · 2026-09-14: `jcs-sha256` is a real RFC 8785 implementation.
# The material projection digest and `clc-action:` identifier change for
# material containing `&`, `<` or `>`; CLC-1.4/1.5 inputs still read.)
CLC_REVISION = "CLC-1.6"
# §6.2 step 4: bounds on the JCS-serialized params form.
MAX_PARAMS_SERIALIZED_BYTES = 512
MAX_PARAMS_NESTING = 32


def validate_capability_id(cid: str) -> None:
    """Validate a capability ID against CLC-v1 §2 grammar."""
    if not cid:
        raise MissingCapabilityID("missing_capability_id")
    if cid == "*":
        raise UnsupportedWildcard("unsupported_wildcard")
    if "**" in cid:
        raise UnsupportedWildcard("unsupported_wildcard")
    if "{" in cid or "}" in cid:
        raise UnsupportedWildcard("unsupported_wildcard")
    if "[" in cid or "]" in cid:
        raise UnsupportedWildcard("unsupported_wildcard")

    parts = cid.split(":")
    for i, p in enumerate(parts):
        if "*" in p:
            if p != "*":
                raise UnsupportedWildcard("unsupported_wildcard")
            if i != len(parts) - 1:
                raise UnsupportedWildcard("unsupported_wildcard")

    if len(parts) < 2:
        raise InvalidCapabilityID("invalid_capability_id")

    # §3 scheme grammar: vendor "/" product "-v" major (rev CLC-1.2).
    if not re.match(r"^[A-Za-z0-9-]+/[A-Za-z0-9-]+-v[0-9]+$", parts[0]):
        raise InvalidCapabilityID("invalid_capability_id")


def _reject_non_finite(value: Any) -> None:
    """Reject non-finite numbers anywhere in params (rev CLC-1.4).  JSON
    cannot represent them, and a value that no bound check can compare must
    not become an allow (NaN compares false against every bound)."""
    if isinstance(value, float) and not math.isfinite(value):
        raise InvalidParamsNumber("invalid_params_number")
    if isinstance(value, dict):
        for v in value.values():
            _reject_non_finite(v)
    elif isinstance(value, list):
        for v in value:
            _reject_non_finite(v)


def validate_params(params: Optional[dict]) -> None:
    """Check for null values in params (CLC-v1 §5.2) and apply the §6.2
    step 4 caps to the decoded-object path (§6.2 step 6, rev CLC-1.2):
    the depth cap uses the decoded structure, the size cap a canonical
    (sorted-key, compact) serialization.  Caps resolve before the null
    check (layer order)."""
    if params is None:
        return
    _reject_non_finite(params)

    if _params_depth(params, 1) > MAX_PARAMS_NESTING:
        raise InvalidParamsSize("invalid_params_size")
    if len(json.dumps(params, separators=(",", ":"), sort_keys=True,
                          ensure_ascii=False).encode("utf-8")) > MAX_PARAMS_SERIALIZED_BYTES:
        raise InvalidParamsSize("invalid_params_size")
    for k, v in params.items():
        if v is None:
            raise InvalidParamsNull(f"invalid_params_null: {k}")


def _params_depth(v: Any, depth: int) -> int:
    """Nesting depth of a decoded params value, counting objects and arrays
    with the params object as level 1 (§6.2 step 4)."""
    max_depth = depth
    if isinstance(v, dict):
        for c in v.values():
            max_depth = max(max_depth, _params_depth(c, depth + 1))
    elif isinstance(v, list):
        for c in v:
            max_depth = max(max_depth, _params_depth(c, depth + 1))
    return max_depth


def _jcs_escape_string(s: str) -> str:
    """RFC 8785 §3.2.2.2 string serialization: escape only `"`, `\\` and the
    control characters; `&`, `<`, `>` and non-ASCII stay raw UTF-8."""
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif o < 0x20:
            out.append('\\u%04x' % o)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _utf16_sort_key(s: str) -> bytes:
    """UTF-16 code-unit order (§3.2.3), as the lexicographic order of the
    big-endian UTF-16 bytes.  Python's default string order compares code
    points, which differs for astral characters (a surrogate pair sorts below
    a BMP code point in 0xE000..0xFFFF)."""
    return s.encode('utf-16-be')


def _canonical_number(value: float) -> str:
    """ECMAScript Number::toString (RFC 8785 §3.2.2.3).  `repr` gives the
    shortest round-tripping decimal; Decimal exposes its digits and decimal
    exponent so the ECMAScript formatting rules can be applied exactly."""
    if value == 0:
        return '0'  # both +0 and -0
    if not math.isfinite(value):
        raise CanonicalJSONError('canonical_invalid_number')
    sign = '-' if value < 0 else ''
    tuple_repr = Decimal(repr(abs(value))).as_tuple()
    digits = ''.join(str(d) for d in tuple_repr.digits)
    exponent = tuple_repr.exponent
    stripped = digits.rstrip('0')
    if stripped == '':
        return sign + '0'
    exponent += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = k + exponent  # value = 0.<digits> * 10**n
    if k <= n <= 21:
        return sign + digits + '0' * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + '.' + digits[n:]
    if -6 < n <= 0:
        return sign + '0.' + '0' * (-n) + digits
    mantissa = digits if k == 1 else digits[0] + '.' + digits[1:]
    e = n - 1
    return sign + mantissa + 'e' + ('+' if e >= 0 else '-') + str(abs(e))


def canonical_json(value: Any) -> str:
    """RFC 8785 (JCS) canonical JSON — the same bytes Go's `CanonicalJSON`
    emits, so the material projection digest is shared across implementations.
    Object keys are ordered by UTF-16 code units, strings use the §3.2.2.2
    escapes, and numbers use ECMAScript `Number::toString`."""
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, str):
        return _jcs_escape_string(value)
    if isinstance(value, int):  # bool is handled above
        return _canonical_number(float(value))
    if isinstance(value, float):
        return _canonical_number(value)
    if isinstance(value, list):
        return '[' + ','.join(canonical_json(item) for item in value) + ']'
    if isinstance(value, dict):
        return '{' + ','.join(
            _jcs_escape_string(key) + ':' + canonical_json(value[key])
            for key in sorted(value.keys(), key=_utf16_sort_key)
        ) + '}'
    raise CanonicalJSONError('canonical_unexpected_type: %s' % type(value).__name__)


def compute_action_id(action_type: str, material_fields, suite: str,
                      action: dict) -> str:
    """§4.3 ActionId over the declared material projection:
    `clc-action:1:<type>:<suite>:<b64url(sha256(JCS(projection)))>`.  A declared
    field that is absent makes the action non-matchable."""
    projection = {}
    for field in material_fields:
        if field not in action:
            raise CanonicalJSONError('action_not_matchable: %s' % field)
        projection[field] = action[field]
    digest = hashlib.sha256(canonical_json(projection).encode('utf-8')).digest()
    return 'clc-action:1:%s:%s:%s' % (
        action_type, suite,
        base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii'))


def _parse_revision(rev: str) -> tuple[Optional[int], Optional[int]]:
    """Split a CLC-<major>.<minor> revision string."""
    m = re.match(r"^CLC-(\d+)\.(\d+)$", rev)
    if not m:
        return None, None
    return int(m.group(1)), int(m.group(2))


def revision_compatible(input_revision: str) -> bool:
    """Report whether an input declaring the given CLC revision may be
    evaluated by this implementation (CLC-v1 §12.1). A mismatch fails
    closed with unsupported_language_revision — never a silent downgrade."""
    i_maj, i_min = _parse_revision(input_revision)
    if i_maj is None:
        return False
    maj, minor = _parse_revision(CLC_REVISION)
    return i_maj == maj and i_min <= minor


def _utf8_len(s: str) -> int:
    """UTF-8 octet length of one source character (§6.2 measures octets, not
    code points or UTF-16 code units)."""
    return len(s.encode("utf-8"))


def _scan_raw_params(t: str) -> tuple[int, int]:
    r"""Return (max nesting depth, compact octet length) of raw JSON params
    text.  Whitespace outside strings is dropped; string content is measured
    after unescaping (a \uXXXX escape counts the UTF-8 octets of the decoded
    character) while duplicate keys stay counted, so the size rule still runs
    before the duplicate-key check (rev CLC-1.4, §6.2 item 5)."""
    depth = 0
    max_depth = 0
    length = 0
    in_string = False
    i = 0
    n = len(t)
    while i < n:
        ch = t[i]
        if in_string:
            if ch == "\\" and i + 1 < n:
                nxt = t[i + 1]
                if nxt == "u" and i + 5 < n:
                    try:
                        dec = chr(int(t[i + 2:i + 6], 16))
                    except ValueError:
                        length += 2
                        i += 2
                        continue
                    length += 2 if ord(dec) < 0x20 else _utf8_len(dec)
                    i += 6
                    continue
                dec = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f"}.get(nxt, nxt)
                length += 2 if ord(dec) < 0x20 else _utf8_len(dec)
                i += 2
                continue
            if ch == '"':
                in_string = False
            length += _utf8_len(ch)
            i += 1
            continue
        if ch == '"':
            in_string = True
            length += 1
        elif ch in "{[":
            depth += 1
            max_depth = max(max_depth, depth)
            length += 1
        elif ch in "}]":
            depth = max(0, depth - 1)
            length += 1
        elif ch not in " \t\n\r":
            length += _utf8_len(ch)
        i += 1
    return max_depth, length


def _significant_digits(lit: str) -> int:
    s = lit
    e = s.lower().find("e")
    if e != -1:
        s = s[:e]
    s = s.lstrip("+-")
    if "." in s:
        s = s.replace(".", "", 1)
    s = s.lstrip("0").rstrip("0")
    return len(s)


def validate_raw_params(raw: str) -> None:
    """Validate the raw JSON text of an operation's params object at the
    input boundary (§6.2, §9.3 layer 2), before any layer runs. Unlike a
    decoded dict, the raw text preserves duplicate keys, number literals,
    nesting depth and serialized size — none of which survive a dict-based
    decode (dicts drop duplicate keys, and JSON cannot carry non-finite
    numbers). Rejections follow §6.2 order: size/depth, then duplicate
    keys, then number shape; malformed input and a non-object params value
    fall into invalid_params_number."""
    t = raw.strip()
    if not t or not t.startswith("{"):
        raise InvalidParamsNumber("invalid_params_number")

    depth, compact_len = _scan_raw_params(t)
    if compact_len > MAX_PARAMS_SERIALIZED_BYTES or depth > MAX_PARAMS_NESTING:
        raise InvalidParamsSize("invalid_params_size")

    dup_key: list[str] = []
    bad_numbers: list[str] = []

    def obj_pairs(pairs: list[tuple[str, Any]]) -> dict:
        seen = set()
        for k, _ in pairs:
            if k in seen:
                if not dup_key:
                    dup_key.append(k)
                break
            seen.add(k)
        return dict(pairs)

    def num_hook(lit: str) -> Any:
        try:
            v = float(lit)
        except (ValueError, OverflowError):
            bad_numbers.append(lit)
            return 0.0
        if not math.isfinite(v) or _significant_digits(lit) > 17:
            bad_numbers.append(lit)
        return v

    try:
        json.loads(
            t,
            parse_int=num_hook,
            parse_float=num_hook,
            object_pairs_hook=obj_pairs,
        )
    except (json.JSONDecodeError, ValueError, RecursionError):
        raise InvalidParamsNumber("invalid_params_number")

    if dup_key:
        raise InvalidParamsDuplicateKey(
            f"invalid_params_duplicate_key: {dup_key[0]}"
        )
    if bad_numbers:
        raise InvalidParamsNumber(f"invalid_params_number: {bad_numbers[0]}")


def canonical_reason(reason: str) -> str:
    """Stable reason code: everything before the first ':' (§9.4).

    Implementations MAY append ": <detail>" as a diagnostic suffix; the
    canonical prefix is what tooling and compatibility checks compare.
    """
    if not reason:
        return ""
    return reason.split(":", 1)[0]


def namespace_of(cap_id: str) -> str:
    """Return scheme:action_class (first two ':'-delimited segments),
    per CLC-v1 §9.3 layer 3."""
    parts = cap_id.split(":")
    return parts[0] + ":" + parts[1] if len(parts) >= 2 else cap_id


def match_id(grant_id: str, op_id: str) -> tuple[bool, str]:
    """Check if grant ID covers operation ID per CLC-v1 §5.1 + §9.3.
    Layer 3 (namespace = scheme + action Class) first, then Layer 4
    (path coverage). Trailing * matches one or more segments."""
    g_parts = grant_id.split(":")
    o_parts = op_id.split(":")

    # §9.3 layer 3: namespace (scheme + action Class)
    if namespace_of(grant_id) != namespace_of(op_id):
        return False, "different_namespace"

    # §9.3 layer 4: path coverage within the same namespace
    if len(g_parts) != len(o_parts):
        if g_parts[-1] == "*":
            if len(o_parts) <= len(g_parts) - 1:
                return False, "wildcard_requires_trailing_segment"
            for i in range(len(g_parts) - 1):
                if g_parts[i] != o_parts[i]:
                    return False, "literal_mismatch"
            return True, ""
        # Exact grant does not broaden to a longer path
        return False, "literal_mismatch"

    for i in range(len(g_parts)):
        if g_parts[i] == "*":
            if i == len(g_parts) - 1:
                return True, ""
            return False, "literal_mismatch"
        if g_parts[i] != o_parts[i]:
            return False, "literal_mismatch"

    return True, ""


def is_empty_bound(v: Any) -> bool:
    """Explicit empty [] or {} param value (CLC-v1 §9.3 layer 5)."""
    return isinstance(v, (list, dict)) and len(v) == 0


def has_empty_bound(params: dict) -> bool:
    return any(is_empty_bound(v) for v in params.values())


def params_subset(op_params: Optional[dict], grant_params: Optional[dict]) -> tuple[bool, str]:
    """Check if operation params are a subset of grant params per CLC-v1 §5.2.
    When several conditions fail at once, the resolved reason follows
    §9.3 layers 5-9 (empty bound, null, presence, enum, bound)."""
    if grant_params is None or len(grant_params) == 0:
        # Rev CLC-1.3 (§9.3): an absent OR empty params object is
        # unconstrained — the empty map declares no keys, so no key closure.
        return True, ""
    if op_params is None:
        return False, "params_missing"

    # §9.3 layer 5: explicit empty bound ([] or {}) on the grant side
    for gv in grant_params.values():
        if is_empty_bound(gv):
            return False, "empty_bound_denies_class"

    # §9.3 layer 6: null values
    for k, gv in grant_params.items():
        if gv is None:
            return False, f"invalid_params_null: {k}"
    for k, ov in op_params.items():
        if ov is None:
            return False, f"invalid_params_null: {k}"

    # §9.3 layer 7: presence (all grant keys must be present in op)
    for k in grant_params:
        if k not in op_params:
            return False, "params_missing"

    # §9.3 layer 7 (request side): key closure — every op key must be
    # declared by the grant; the missing-key check above resolves first.
    for k in op_params:
        if k not in grant_params:
            return False, f"undeclared_param: {k}"

    # §9.3 layers 8-9: per-key value checks (enum membership, bounds)
    for k, gv in grant_params.items():
        ok, reason = value_subset(op_params[k], gv)
        if not ok:
            return False, reason

    return True, ""


def value_subset(op_val: Any, grant_val: Any) -> tuple[bool, str]:
    """Check if a single value is a subset of the grant value."""
    if op_val is None:
        return False, "invalid_params_null"
    if grant_val is None:
        return False, "empty_bound_denies_class"

    # Booleans are exact and are NOT numbers (CLC-v1 §6.2): `True` must not be
    # satisfied by `1`.  Python makes bool a subclass of int, so this branch has
    # to come before the numeric one — otherwise `1 <= True` and the grant
    # silently widens (fail-open).
    if isinstance(grant_val, bool) or isinstance(op_val, bool):
        if not (isinstance(grant_val, bool) and isinstance(op_val, bool)):
            return False, "params_exceed_grant"
        if op_val != grant_val:
            return False, "params_exceed_grant"
        return True, ""

    if isinstance(grant_val, (int, float)):
        if not isinstance(op_val, (int, float)) or isinstance(op_val, bool):
            return False, "params_exceed_grant"
        if op_val > grant_val:
            return False, "params_exceed_grant"
        return True, ""

    if isinstance(grant_val, str):
        if not isinstance(op_val, str) or op_val != grant_val:
            return False, "params_exceed_grant"
        return True, ""

    if isinstance(grant_val, list):
        # v1.1 enum semantics: an array-valued grant parameter is the set
        # of allowed values. The request may supply a scalar (must equal a
        # member) or an array (every element must equal a member). Numbers
        # inside the set are exact values, not bounds. An explicitly empty
        # grant set denies the class.
        if len(grant_val) == 0:
            return False, "empty_bound_denies_class"
        elems = op_val if isinstance(op_val, list) else [op_val]
        for o in elems:
            if o not in grant_val:
                return False, "not_in_enum"
        return True, ""

    if isinstance(grant_val, dict):
        if not isinstance(op_val, dict):
            return False, "params_exceed_grant"
        for k, gvv in grant_val.items():
            if k not in op_val:
                return False, "params_missing"
            ok, reason = value_subset(op_val[k], gvv)
            if not ok:
                return False, reason
        return True, ""

    # Exact equality
    if op_val != grant_val:
        return False, "params_exceed_grant"
    return True, ""


def entails(grant: dict, op: dict) -> dict:
    """Check if a grant covers an operation per CLC-v1 §5."""
    try:
        validate_capability_id(grant["id"])
    except CLCError as e:
        return {"entails": False, "reason": str(e)}

    try:
        validate_capability_id(op["id"])
    except CLCError as e:
        return {"entails": False, "reason": str(e)}

    # §5.3 step 1: scheme check
    g_scheme = grant["id"].split(":")[0]
    o_scheme = op["id"].split(":")[0]
    if g_scheme != o_scheme:
        return {"entails": False, "reason": "different_namespace"}

    # §5.3 step 2: id coverage
    ok, reason = match_id(grant["id"], op["id"])
    if not ok:
        return {"entails": False, "reason": reason}

    # §5.3 step 3: grant params absent OR empty → true (unconstrained;
    # rev CLC-1.3 §9.3 makes {} ≡ absent).
    if not grant.get("params"):
        return {"entails": True}

    # Validate null values
    try:
        validate_params(grant.get("params"))
    except CLCError as e:
        return {"entails": False, "reason": str(e)}

    try:
        validate_params(op.get("params"))
    except CLCError as e:
        return {"entails": False, "reason": str(e)}

    # §5.3 step 4: op params absent → false (bounded grant, fail-closed)
    if op.get("params") is None:
        return {"entails": False, "reason": "params_missing"}

    # §5.3 step 5: params subset
    ok, reason = params_subset(op.get("params"), grant.get("params"))
    if not ok:
        return {"entails": False, "reason": reason}

    return {"entails": True}


def intersect(grants: list[dict]) -> dict:
    """Combine multiple grants per CLC-v1 §6."""
    if not grants:
        raise CapabilityNotAuthorized("absent_source")

    # §9.3 layer 5: deny-when-declared — any source with an explicitly
    # empty bound ([] or {}) denies the class before any member math.
    for g in grants:
        if g.get("params") and has_empty_bound(g["params"]):
            raise CapabilityNotAuthorized("empty_bound_denies_class")

    result = grants[0].copy()

    for g in grants[1:]:
        # Check ID compatibility (§7 rule 2: the result must be covered by
        # every source, so the *narrower* identifier wins).
        if result["id"] != g["id"]:
            # Params-free comparison on purpose: entails() is the authorization
            # relation and fails closed when a bounded grant meets an operation
            # without params (§6.3 step 4), which would make two grants carrying
            # a present-but-empty params object look disjoint.
            if entails({"id": result["id"]}, {"id": g["id"]})["entails"]:
                result["id"] = g["id"]        # g is narrower
            elif not entails({"id": g["id"]}, {"id": result["id"]})["entails"]:
                raise CapabilityNotAuthorized("no_overlap")
            # otherwise result stays the narrower identifier

        # Intersect params.  Both conditions test `is not None`, mirroring the
        # Go implementation exactly: a *present but empty* params object is a
        # source that declares no constraint, and truthiness here used to let it
        # overwrite the accumulated bound (CLC-v1 §7 rule 6; P11).
        if result.get("params") is not None and g.get("params") is not None:
            intersected = {}
            for k, rv in result["params"].items():
                if k in g["params"]:
                    v, err = intersect_value(rv, g["params"][k])
                    if err:
                        raise CapabilityNotAuthorized(err)
                    intersected[k] = v
                else:
                    intersected[k] = rv
            for k, gv in g["params"].items():
                if k not in result["params"]:
                    intersected[k] = gv
            result["params"] = intersected
        elif g.get("params") is None:
            # g declares no constraint at all (params absent): keep the
            # accumulated params.  NB the test is `is None`, not truthiness:
            # an *empty* params object is a present-but-unconstrained source,
            # and treating it as falsy used to overwrite the accumulated bound
            # (CLC-v1 §7 rule 6; P11).  This mirrors the Go implementation.
            pass
        else:
            # result is unconstrained (params absent), adopt g params
            result["params"] = g["params"]

        # Merge constraints (§7 rule 3): constraints are conjunctive, so the
        # merge is a set *union* — every constraint of every source stays in
        # force, and for the same constraint type the tightest one binds.
        result_constraints = set(result.get("constraints", []))
        result_constraints.update(g.get("constraints", []))
        result["constraints"] = list(result_constraints)

    return result


def intersect_value(a: Any, b: Any) -> tuple[Any, str]:
    """Intersect two values."""
    # bools are ints in Python and `True == 1`; keep booleans out of the
    # number branch so `True ∩ 1` and `True ∩ False` never merge (rev
    # CLC-1.2 deterministic-value semantics, matches Go's typed equality).
    a_bool, b_bool = isinstance(a, bool), isinstance(b, bool)
    if a_bool != b_bool:
        return None, "no_overlap"
    if a_bool and b_bool:
        if a == b:
            return a, ""
        return None, "no_overlap"

    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return min(a, b), ""

    if isinstance(a, list) and isinstance(b, list):
        result = [x for x in a if x in b]
        if not result:
            return None, "no_overlap"
        return result, ""

    if isinstance(a, dict) and isinstance(b, dict):
        # Object values intersect per shared key, and only when the key sets
        # are identical (rev CLC-1.2): a shared-keys result would drop a key
        # the other source constrains, so it is not covered by every source
        # (P11 — composition narrows only).  Differing key sets deny
        # no_overlap.
        if set(a.keys()) != set(b.keys()):
            return None, "no_overlap"
        result = {}
        for k in a:
            v, err = intersect_value(a[k], b[k])
            if err:
                return None, err
            result[k] = v
        if not result:
            return None, "no_overlap"
        return result, ""

    if a == b:
        return a, ""
    return None, "no_overlap"


def validate_constraint(c: str) -> None:
    """Check a constraint against the §8.1 identity×value grammar: an
    unrecognized (scheme,type) → unknown_constraint; a recognized type whose
    value is out of grammar → invalid_constraint (rev CLC-1.2/1.3)."""
    parts = c.split(":")
    if len(parts) < 2 or f"{parts[0]}:{parts[1]}" not in RECOGNIZED_CONSTRAINT_IDENTITIES:
        raise UnknownConstraint("unknown_constraint")
    constraint_type = parts[1]

    if constraint_type == "max_rows":
        # Strict JSON non-negative integer, exactly one token (§8.1).
        if len(parts) != 3 or not _is_strict_json_integer(parts[2]):
            raise InvalidConstraint(f"invalid_constraint: {c}")
    elif constraint_type == "time":
        # Value = JSON array of ≤32 {start,end} UTC daily windows (§8.1).
        joined = _constraint_params(c)
        if not joined.startswith("window:") or not _valid_time_window_json(joined[len("window:"):]):
            raise InvalidConstraint(f"invalid_constraint: {c}")
    elif constraint_type == "network":
        # Value = JSON array of ≤32 CIDR strings (§8.1).
        joined = _constraint_params(c)
        if not joined.startswith("cidr:") or not _valid_cidr_list_json(joined[len("cidr:"):]):
            raise InvalidConstraint(f"invalid_constraint: {c}")


def check_constraint(c: str, op: dict) -> Optional[str]:
    """Evaluate a constraint against an operation (§8.1).  Rev CLC-1.2:
    max_rows uses a strict integer and fails closed when the op carries no
    max_rows value (previously a missing op param was silently skipped)."""
    parts = c.split(":")
    if len(parts) < 3:
        return None

    # Defensive identity gate (rev CLC-1.3): validate_constraint is
    # authoritative and rejects non-core schemes first, so this is
    # unreachable via authorize.
    if f"{parts[0]}:{parts[1]}" not in RECOGNIZED_CONSTRAINT_IDENTITIES:
        return None

    constraint_type = parts[1]
    if constraint_type == "max_rows":
        if len(parts) != 3 or not _is_strict_json_integer(parts[2]):
            # Unreachable via authorize (validate_constraint rejects the
            # grant with invalid_constraint first); defensive no-op.
            return None
        max_val = int(parts[2])
        params = op.get("params", {})
        if "max_rows" not in params:
            # Op-absent max_rows → fail closed (§8.1 value-grammar table).
            return "max_rows:violated"
        rows = params["max_rows"]
        # Op-side value domain (rev CLC-1.4): a row count must be a finite
        # non-negative integer; anything else cannot be shown to satisfy the
        # constraint, so it fails closed instead of passing unchecked.
        if isinstance(rows, bool) or not isinstance(rows, (int, float)):
            return "max_rows:violated"
        if isinstance(rows, float) and (not math.isfinite(rows) or not rows.is_integer()):
            return "max_rows:violated"
        if rows < 0:
            return "max_rows:violated"
        if rows > max_val:
            return "max_rows:violated"

    return None


def _core_evaluates_constraint(c: str) -> bool:
    """Report whether the v1 core has an evaluator for a constraint's type
    (§8.1).  Only max_rows is core-evaluated; time/network are
    recognized-but-unevaluated and surface via the decision's unresolved
    field (§8.4 residual-obligation channel)."""
    parts = c.split(":")
    if len(parts) < 2:
        return False
    return parts[0] == RESERVED_SCHEME and parts[1] == "max_rows"


def _constraint_params(c: str) -> str:
    """A constraint's value part — everything after `scheme:type:` — with
    JSON colons preserved (rejoined from the colon-split parts; rev CLC-1.2
    fixes the kind of corruption that chopped window arrays on inner colons).
    Callers strip the type-specific domain crumb (`window:` / `cidr:`)."""
    parts = c.split(":")
    if len(parts) < 3:
        return ""
    return ":".join(parts[2:])


def _is_strict_json_integer(s: str) -> bool:
    """Canonical JSON non-negative integer: digits only, no sign, no
    fraction, no exponent, no leading zero (rev CLC-1.2 value grammar)."""
    if not s:
        return False
    if len(s) > 1 and s[0] == "0":
        return False
    return all("0" <= ch <= "9" for ch in s)


_MAX_TIME_WINDOWS = 32
_MAX_CIDR_LIST = 32

_TIME_OF_DAY_RE = re.compile(r"^([01]?[0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?$")


def _seconds_of_day(t: str) -> int:
    h, m = (int(p) for p in t.split(":")[:2])
    s = int(t.split(":")[2]) if ":" in t[5:] else 0
    return h * 3600 + m * 60 + s


def _valid_time_window_json(raw: str) -> bool:
    """Validate the time constraint's value grammar (§8.1, rev CLC-1.3):
    a non-empty JSON array of ≤32 objects, each exactly {start,end} of a
    time-of-day (HH:MM[:SS]) treated as UTC, daily-repeating.  Each segment
    is SAME-DAY: startSod < endSod where the reserved end "00:00" denotes
    next-day midnight (86400s) — a single segment may not cross midnight
    (22:00→06:00 is invalid and must be split), the full-day segment
    00:00→00:00 is invalid, and the list must be ascending and
    non-overlapping (touching allowed)."""
    try:
        segments = json.loads(raw)
    except (ValueError, TypeError):
        return False
    if not isinstance(segments, list) or not segments or len(segments) > _MAX_TIME_WINDOWS:
        return False
    prev_end = -1
    for s in segments:
        if not isinstance(s, dict) or set(s.keys()) != {"start", "end"}:
            return False
        start, end = s.get("start"), s.get("end")
        if not isinstance(start, str) or not isinstance(end, str):
            return False
        if not (_TIME_OF_DAY_RE.match(start) and _TIME_OF_DAY_RE.match(end)):
            return False
        start_sod = _seconds_of_day(start)
        end_sod = _seconds_of_day(end)
        if end == "00:00":
            end_sod = 86400  # reserved: next-day midnight
        if start_sod >= end_sod:
            return False  # same-day start before end
        if start == "00:00" and end == "00:00":
            return False  # full-day segment is invalid
        if prev_end >= 0 and start_sod < prev_end:
            return False  # not ascending / overlapping (touching allowed)
        prev_end = end_sod
    return True


_IPV4_CIDR_RE = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$")
_IPV6_SHAPE_RE = re.compile(r"^[0-9a-fA-F:]+$")


def _valid_ipv4_octets(ip: str) -> bool:
    try:
        return all(0 <= int(p) <= 255 for p in ip.split("."))
    except ValueError:
        return False


def _valid_cidr_string(s: str) -> bool:
    """Validate a numeric CIDR string (shape-only, §8.1 value grammar; the
    core does not evaluate network constraints — that is the scheme's job
    per §11)."""
    slash = s.rfind("/")
    if slash <= 0 or slash == len(s) - 1:
        return False
    ip_part, prefix = s[:slash], s[slash + 1:]
    if not _is_strict_json_integer(prefix):
        return False
    mask = int(prefix)
    if mask < 0 or mask > 128:
        return False
    if ":" in ip_part:
        if mask > 128:
            return False
        # Shape-only: allow "::"-compressed forms; reject a lone trailing ":".
        return bool(_IPV6_SHAPE_RE.match(ip_part)) and not (ip_part.endswith(":") and not ip_part.endswith("::"))
    if mask > 32:
        return False
    return bool(_IPV4_CIDR_RE.match(s)) and _valid_ipv4_octets(ip_part)


def _valid_cidr_list_json(raw: str) -> bool:
    """Validate the network constraint's value grammar: a non-empty JSON
    array of ≤32 numeric CIDR strings."""
    try:
        cidr_list = json.loads(raw)
    except (ValueError, TypeError):
        return False
    if not isinstance(cidr_list, list) or not cidr_list or len(cidr_list) > _MAX_CIDR_LIST:
        return False
    return all(isinstance(e, str) and _valid_cidr_string(e) for e in cidr_list)


def _is_params_level_reason(reason: str) -> bool:
    """Report whether an entailment failure is a params-level reason
    (propagated by authorize) rather than an ID-level reason (collapsed
    to capability_not_authorized per CLC-v1 §9 step 3)."""
    return reason in {"params_missing", "undeclared_param", "params_exceed_grant",
                      "empty_bound_denies_class", "not_in_enum",
                      "invalid_params_duplicate_key", "invalid_params_number",
                      "invalid_params_size", "unsupported_language_revision"} \
        or reason.startswith("invalid_params_null") or reason.startswith("undeclared_param")


def authorize(effective_grant: dict, op: dict) -> dict:
    """Evaluate the decision function per CLC-v1 §8 with a single effective
    grant (§9.3 single-grant path)."""
    return authorize_set([effective_grant], op)


def authorize_set(grants: list, op: dict) -> dict:
    """Evaluate the §9.3 multi-grant aggregation (rev CLC-1.3):
    - grants all absent (None or empty id) → deny capability_not_authorized
      (resolved before any layer check, matching the single-grant pre-check);
    - otherwise operation layer-1 validation runs first (id, params null);
    - each grant whose id covers the operation is a covering grant; params
      (params_subset) then constraints (validate/check) are evaluated;
    - ANY covering grant whose params+constraints fully allow authorizes the
      operation (union semantics);
    - residual obligations (recognized-but-unevaluated constraints) union
      across the covering-and-allowing grants → allow_unresolved;
    - if no covering grant allows: params/constraint-level denials surface as
      the first covering grant's reason in canonical (input) order; grants
      that did not cover collapse to capability_not_authorized."""
    if not any(g and g.get("id") for g in grants):
        return {"verdict": VERDICT_DENY, "reason": "capability_not_authorized"}

    # Absent operation → fail-closed (layer 1).
    if op is None:
        return {"verdict": VERDICT_DENY, "reason": "missing_capability_id"}

    if not op.get("id"):
        return {"verdict": VERDICT_DENY, "reason": "missing_capability_id"}

    try:
        validate_capability_id(op["id"])
    except CLCError as e:
        return {"verdict": VERDICT_DENY, "reason": str(e)}

    try:
        validate_params(op.get("params"))
    except CLCError as e:
        return {"verdict": VERDICT_DENY, "reason": str(e)}

    unresolved = []
    deny_reason_first = ""  # first covering-grant params/constraint-layer denial (input order)
    any_allowed = False
    for g in grants:
        if not g or not g.get("id"):
            continue
        # Step 2: Check entailment
        result = entails(g, op)
        if not result["entails"]:
            reason = result["reason"]
            if _is_params_level_reason(reason) and not deny_reason_first:
                deny_reason_first = reason
            continue

        # Step 3: Evaluate constraints (§9 step 4; rev CLC-1.2/1.3).
        failed = False
        pg = []
        for c in g.get("constraints", []):
            try:
                validate_constraint(c)
            except CLCError as e:
                failed = True
                if not deny_reason_first:
                    deny_reason_first = str(e)
                break
            violation = check_constraint(c, op)
            if violation:
                failed = True
                if not deny_reason_first:
                    deny_reason_first = violation
                break
            if not _core_evaluates_constraint(c):
                pg.append(c)
        if failed:
            continue

        # This covering grant authorizes the operation; keep scanning so the
        # residual-obligation union is stable across grant order.
        any_allowed = True
        unresolved.extend(pg)

    if not any_allowed:
        if deny_reason_first:
            return {"verdict": VERDICT_DENY, "reason": deny_reason_first}
        return {"verdict": VERDICT_DENY, "reason": "capability_not_authorized"}
    uniq = sorted(set(unresolved))
    if uniq:
        return {"verdict": VERDICT_ALLOW_UNRESOLVED, "unresolved": uniq}
    return {"verdict": VERDICT_ALLOW}
