"""
CLC-v1 Capability Language Core - Python reference implementation.

This is an independent implementation of the CLC-v1 authorization semantics.
It is NOT a translation of the Go implementation; it follows the spec directly.
The对外判决 must match the Go implementation exactly.
"""
import base64
import datetime
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


class InvalidParamsBinding(CLCError):
    pass


class ParamsCardinality(CLCError):
    pass


class ParamsOutOfRange(CLCError):
    pass


class ParamsNotMultiple(CLCError):
    pass


class UnsupportedLanguageRevision(CLCError):
    pass


class CanonicalJSONError(CLCError):
    """A value has no RFC 8785 (JCS) encoding (non-finite number, lone
    surrogate, or a type JSON does not carry)."""
    pass


# Largest int exactly convertible to IEEE-754 binary64 without raising
# OverflowError: float64 max finite value ≈ 2**1024 (≈1.8e308).  Python
# raises OverflowError for abs(int) beyond it during float() (audit
# 2026-09-16, R4); the JCS boundary is the same as any other impl.
_MAX_FLOAT64_INT = sys.float_info.max


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
# material containing `&`, `<` or `>`; the decoded params path refuses
# malformed Unicode (lone surrogates / invalid UTF-8) with
# invalid_params_number and counts the §6.2 size in JCS bytes, not a
# deserializer's re-encoding; the raw params size counts the JCS (RFC 8785
# §3.2.2.2) octets of every decoded character — `"`, `\` and the control
# shortcuts escape as two, every other control as `\u00xx` (six), and
# `&`/`<`/`>`/U+2028/U+2029/non-ASCII stay raw — so the raw and decoded
# limits agree; CLC-1.4/1.5 inputs still read.)
# (rev CLC-1.15 · 2026-09-25: corrective — enum membership compares with JSON
# type-sensitive equality (§6.5 layer 8), so Python's `True == 1` coercion no
# longer leaks into `in`/`==` membership checks; the §6.6 cross-family
# numeric × enum meet is refused (`invalid_params_binding`) in either order
# instead of reducing to the filtered enum.  Inputs without param_bounds are
# unaffected; CLC-1.14 and earlier inputs still read.)
CLC_REVISION = "CLC-1.15"
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
    # fullmatch (not a $ anchor): $ allows a trailing newline, and a
    # capability id with a stray "\n" must not be accepted (audit R13).
    if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9-]+-v[0-9]+", parts[0]):
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


def _reject_unpaired_surrogates(value: Any) -> None:
    """Refuse lone UTF-16 surrogates anywhere in a decoded params structure
    (rev CLC-1.6).  A lone surrogate has no UTF-8 form and no JCS encoding
    (RFC 8785 §3.2.2.2); a careless `.encode("utf-8")` raises an uncaught
    UnicodeEncodeError, and a serializer could silently repair it to U+FFFD.
    It must produce the same stable denial (invalid_params_number) as the raw
    boundary check, and always before any serialization."""
    if isinstance(value, str):
        for ch in value:
            o = ord(ch)
            if 0xD800 <= o <= 0xDFFF:
                raise InvalidParamsNumber("invalid_params_number: lone surrogate U+%04X" % o)
    elif isinstance(value, dict):
        for k, v in value.items():
            _reject_unpaired_surrogates(k)
            _reject_unpaired_surrogates(v)
    elif isinstance(value, list):
        for item in value:
            _reject_unpaired_surrogates(item)


def validate_params(params: Optional[dict]) -> None:
    """Check for null values in params (CLC-v1 §5.2) and apply the §6.2
    step 4 caps to the decoded-object path (§6.2 step 6, rev CLC-1.2):
    the depth cap uses the decoded structure, the size cap the JCS
    (RFC 8785) serialization — the same bytes the other implementations
    count, not json.dumps (rev CLC-1.6).  Caps resolve before the null
    check (layer order)."""
    if params is None:
        return
    if not isinstance(params, dict):
        # §6.2: params must be an object; anything else (top-level array,
        # scalar, ...) is the same stable denial as unparsable JSON.  Checked
        # before the depth/size caps so all three implementations report
        # invalid_params_number rather than one of them reporting a size code.
        raise InvalidParamsNumber("invalid_params_number")
    _reject_non_finite(params)
    _reject_unpaired_surrogates(params)

    if _params_depth(params, 1) > MAX_PARAMS_NESTING:
        raise InvalidParamsSize("invalid_params_size")
    try:
        serialized = canonical_json(params).encode("utf-8")
    except CanonicalJSONError as e:
        raise InvalidParamsNumber("invalid_params_number: %s" % e)
    if len(serialized) > MAX_PARAMS_SERIALIZED_BYTES:
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
        elif 0xD800 <= o <= 0xDFFF:
            # A lone surrogate is not valid Unicode, so it has no UTF-8 form and
            # no JCS encoding: refuse rather than emit an unencodable string.
            raise CanonicalJSONError('canonical_lone_surrogate: U+%04X' % o)
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
        # RFC 8785 §3.2.2.3 canonicalizes via IEEE-754 binary64.  An int beyond
        # the float64 range (|x| > 2**1024, or ~1.8e308) cannot round-trip and
        # float() would raise an uncaught OverflowError (audit 2026-09-16, R4).
        # Reject it as a non-canonical number instead of crashing.
        if value != 0 and (value > _MAX_FLOAT64_INT or value < -_MAX_FLOAT64_INT):
            raise CanonicalJSONError('canonical_invalid_number')
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
    code points or UTF-16 code units).  A lone surrogate has no UTF-8 form;
    it is refused with the same stable denial as the escape-level check rather
    than surfacing as UnicodeEncodeError (rev CLC-1.7)."""
    try:
        return len(s.encode("utf-8"))
    except UnicodeEncodeError:
        raise InvalidParamsNumber("invalid_params_number: lone surrogate in input")


def _jcs_octets(cp: int) -> int:
    """JCS (RFC 8785 §3.2.2.2) octet length of one decoded character: `"`, `\\`
    and the control shortcuts `\\b \\f \\n \\r \\t` escape as two octets, any
    other control character as `\\u00xx` (six), and everything else (`&`, `<`,
    `>`, non-ASCII, astral) is emitted raw as its UTF-8 encoding."""
    if cp in (0x22, 0x5C) or cp in (0x08, 0x09, 0x0A, 0x0C, 0x0D):
        return 2
    if cp < 0x20:
        return 6
    return _utf8_len(chr(cp))


_RAW_NUMBER_TOKEN = re.compile(r'-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?')


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
                        cp = int(t[i + 2:i + 6], 16)
                    except ValueError:
                        length += 2
                        i += 2
                        continue
                    consumed = 6
                    if 0xD800 <= cp <= 0xDBFF:
                        # A high surrogate must be followed by a low surrogate;
                        # the pair is one character, and a lone surrogate is
                        # invalid Unicode that cannot be encoded at all.
                        lo_hex = t[i + 8:i + 12] if i + 11 < n else ""
                        if (t[i + 6:i + 8] != "\\u" or len(lo_hex) != 4
                                or any(c not in "0123456789abcdefABCDEF" for c in lo_hex)):
                            raise CanonicalJSONError("invalid_params_number: lone surrogate escape")
                        lo = int(lo_hex, 16)
                        if not (0xDC00 <= lo <= 0xDFFF):
                            raise CanonicalJSONError("invalid_params_number: lone surrogate escape")
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                        consumed = 12
                    elif 0xDC00 <= cp <= 0xDFFF:
                        raise CanonicalJSONError("invalid_params_number: lone surrogate escape")
                    length += _jcs_octets(cp)
                    i += consumed
                    continue
                dec = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f"}.get(nxt, nxt)
                length += _jcs_octets(ord(dec))
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
        elif ch in "-0123456789":
            token = _RAW_NUMBER_TOKEN.match(t, i)
            if token is not None:
                lit = token.group(0)
                num = float(lit)
                # §6.2 step 4 measures the JCS form, and JCS rewrites the
                # token: 1e-6 becomes 0.000001 and 1.0 becomes 1.  The
                # received token still drives the precision check below.
                length += (len(_canonical_number(num)) if math.isfinite(num)
                           else _utf8_len(lit))
                i = token.end()
                continue
            length += _utf8_len(ch)
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


def json_equal(a: Any, b: Any) -> bool:
    """JSON type-sensitive equality (§6.2 enum rule / §6.5 layer 8, rev
    CLC-1.15).

    Two values are equal only when they have the same JSON type AND the same
    value: `True` is neither `1` nor `0` (Python makes bool a subclass of int —
    this helper is where that coercion MUST NOT leak into membership math), and
    `"1"` is neither `1` nor `True`.  Numbers are compared after the §6.2
    canonicalization — one IEEE-754 binary64 value rendered per ECMAScript
    Number::toString — so `1` and `1.0` (one value, two spellings) ARE equal.
    Lists and objects compare element-wise / member-wise with the same rule.
    Used for enum membership (params arrays and param_bounds enums), the §6.6
    enum intersection, the §7 params-value intersection and §13.4.3 enum
    narrowing, so every membership decision in this module is type-sensitive
    exactly like the Go (CanonicalJSON-bytes) and TypeScript (jsonEqual) cores.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)):
        return (isinstance(b, (int, float)) and not isinstance(b, bool)
                and float(a) == float(b))
    if isinstance(a, str):
        return isinstance(b, str) and a == b
    if isinstance(a, list):
        return (isinstance(b, list) and len(a) == len(b)
                and all(json_equal(x, y) for x, y in zip(a, b)))
    if isinstance(a, dict):
        return (isinstance(b, dict) and a.keys() == b.keys()
                and all(json_equal(a[k], b[k]) for k in a))
    return a is None and b is None


def _render_number(m: Any) -> Any:
    """One JSON value, one spelling (§2.4 / §6.2, rev CLC-1.15): an integral
    float and its int twin are the same IEEE-754 value and must serialize the
    same way (Go/TS always render 1.0 as 1).  Applied to enum-meet and
    params-intersect member outputs so the raw JSON matches their bytes."""
    if isinstance(m, float) and m.is_integer():
        return int(m)
    return m


def _bound_family(b: Any) -> str:
    """§6.6 Bound value family (or 'none' for an empty Bound)."""
    if not isinstance(b, dict):
        return "invalid"
    if "nested" in b:
        return "nested"
    if any(k in b for k in ("enum", "min_items", "max_items")):
        return "enum"
    if any(k in b for k in ("min", "max", "step")):
        return "numeric"
    return "none"


def _canonical_enum_members(members: list) -> list:
    """Dedupe enum members and order them by their JCS rendering (P11).
    Integral floats render as int (rev CLC-1.15, cross-type audit)."""
    seen = {}
    for m in members:
        m = _render_number(m)
        try:
            k = canonical_json(m)
        except Exception:
            k = repr(m)
        if k not in seen:
            seen[k] = m
    return [seen[k] for k in sorted(seen)]


def _bound_denies_class(b: Any) -> bool:
    """A Bound with an explicitly empty enum denies its class (recursing nested)."""
    if not isinstance(b, dict):
        return False
    if isinstance(b.get("enum"), list) and len(b["enum"]) == 0:
        return True
    nm = b.get("nested")
    if isinstance(nm, dict):
        return any(_bound_denies_class(x) for x in nm.values())
    return False


def _bounds_deny_class(bounds: Any) -> bool:
    return isinstance(bounds, dict) and any(_bound_denies_class(b) for b in bounds.values())


def _max_of(a: Any, b: Any) -> tuple[Any, bool]:
    if isinstance(a, (int, float)) and not isinstance(a, bool) and isinstance(b, (int, float)) and not isinstance(b, bool):
        return (a if a > b else b), True
    if isinstance(a, (int, float)) and not isinstance(a, bool):
        return a, True
    if isinstance(b, (int, float)) and not isinstance(b, bool):
        return b, True
    return None, False


def _min_of(a: Any, b: Any) -> tuple[Any, bool]:
    if isinstance(a, (int, float)) and not isinstance(a, bool) and isinstance(b, (int, float)) and not isinstance(b, bool):
        return (a if a < b else b), True
    if isinstance(a, (int, float)) and not isinstance(a, bool):
        return a, True
    if isinstance(b, (int, float)) and not isinstance(b, bool):
        return b, True
    return None, False


def bound_meet(a: Any, b: Any) -> tuple[dict, str]:
    """§6.6 meet of two Bounds for the same key.  Returns (bound, reason);
    reason is '' on success, else the fail-closed §9.2 code."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return {}, "invalid_params_binding"
    am = {k: v for k, v in a.items()}
    bm = {k: v for k, v in b.items()}
    opt = _bound_optional(am) and _bound_optional(bm)
    af, bf = _bound_family(am), _bound_family(bm)
    if af == "invalid" or bf == "invalid":
        return {}, "invalid_params_binding"
    if af == "none" or bf == "none":
        src = bm if af == "none" else am
        res = {k: v for k, v in src.items() if k != "optional"}
        if opt:
            res["optional"] = True
        return res, ""
    if af == "numeric" and bf == "numeric":
        res, err = _numeric_meet(am, bm)
    elif af == "enum" and bf == "enum":
        res, err = _enum_meet(am, bm)
    elif af == "nested" and bf == "nested":
        res, err = _nested_meet(am, bm)
    elif (af == "numeric" and bf == "enum") or (af == "enum" and bf == "numeric"):
        # rev CLC-1.15 §6.6: a cross-family numeric × enum meet has no sound
        # representation — the CLC-1.14 filtered-enum result was broader than
        # either source (it accepted array requests, e.g. [3], that the numeric
        # side fail-closes at §6.5 layer 9).  Refused in either source order
        # and regardless of whether any member falls inside the numeric range:
        # the family clash is decided before any member or range math.
        return {}, "invalid_params_binding"
    elif af == "nested" or bf == "nested":
        # scalar (numeric/enum) ∩ object (nested), either order: refused like
        # the numeric × enum pair — no single-family Bound can carry both the
        # scalar side's shape constraint and the object recursion (§6.6 rev
        # CLC-1.15; design-notes D12).  The family clash is decided before any
        # member, range or key-set math.
        return {}, "invalid_params_binding"
    else:
        return {}, "invalid_params_binding"
    if err:
        return {}, err
    res.pop("optional", None)
    if opt:
        res["optional"] = True
    return res, ""


def _numeric_meet(a: dict, b: dict) -> tuple[dict, str]:
    res: dict = {}
    mv, ok = _max_of(a.get("min"), b.get("min"))
    if ok:
        res["min"] = mv
    mv, ok = _min_of(a.get("max"), b.get("max"))
    if ok:
        res["max"] = mv
    astep, bstep = a.get("step"), b.get("step")
    if isinstance(astep, (int, float)) and isinstance(bstep, (int, float)):
        if _is_multiple_of(astep, bstep):
            res["step"] = astep
        elif _is_multiple_of(bstep, astep):
            res["step"] = bstep
        else:
            return {}, "invalid_params_binding"
    elif isinstance(astep, (int, float)):
        res["step"] = astep
    elif isinstance(bstep, (int, float)):
        res["step"] = bstep
    if "min" in res and "max" in res and res["min"] > res["max"]:
        return {}, "no_overlap"
    return res, ""


def _enum_meet(a: dict, b: dict) -> tuple[dict, str]:
    res: dict = {}
    ae, be = a.get("enum"), b.get("enum")
    if isinstance(ae, list) and isinstance(be, list):
        # rev CLC-1.15: the member sets intersect under JSON type-sensitive
        # equality (§6.5 layer 8) — 1, True and "1" are distinct members.
        inter = [x for x in ae if any(json_equal(x, y) for y in be)]
        if len(inter) == 0:
            return {}, "no_overlap"
        res["enum"] = _canonical_enum_members(inter)
    elif isinstance(ae, list):
        res["enum"] = [_render_number(x) for x in ae]
    elif isinstance(be, list):
        res["enum"] = [_render_number(x) for x in be]
    mv, ok = _max_of(a.get("min_items"), b.get("min_items"))
    if ok:
        res["min_items"] = mv
    mv, ok = _min_of(a.get("max_items"), b.get("max_items"))
    if ok:
        res["max_items"] = mv
    if "min_items" in res and "max_items" in res and res["min_items"] > res["max_items"]:
        return {}, "no_overlap"
    return res, ""


def _nested_meet(a: dict, b: dict) -> tuple[dict, str]:
    an, bn = a.get("nested"), b.get("nested")
    if not isinstance(an, dict) or not isinstance(bn, dict) or len(an) != len(bn):
        return {}, "no_overlap"
    res: dict = {}
    for k, av in an.items():
        if k not in bn:
            return {}, "no_overlap"
        m, err = bound_meet(av, bn[k])
        if err:
            return {}, err
        res[k] = m
    return {"nested": res}, ""


def _intersect_bounds(a: dict, b: dict) -> dict:
    """Union keys and meet shared ones (§6.6)."""
    out = {k: v for k, v in a.items()}
    for k, bv in b.items():
        if k in out:
            m, err = bound_meet(out[k], bv)
            if err:
                if err == "no_overlap":
                    raise CapabilityNotAuthorized(err)
                raise InvalidParamsBinding(err)
            out[k] = m
        else:
            out[k] = bv
    return out


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

    if isinstance(grant_val, list):
        # v1.1 enum semantics: an array-valued grant parameter is the set
        # of allowed values. The request may supply a scalar (must equal a
        # member) or an array (every element must equal a member). Numbers
        # inside the set are exact values, not bounds. An explicitly empty
        # grant set denies the class.  Dispatch on the GRANT type,
        # mirroring TypeScript/Go: a boolean op scalar against an enum
        # grant is not_in_enum (not params_exceed_grant), even though
        # Python's bool-is-int makes the bool branch below tempting —
        # audit 2026-09-16, R6 cross-impl reason fidelity.
        if len(grant_val) == 0:
            return False, "empty_bound_denies_class"
        elems = op_val if isinstance(op_val, list) else [op_val]
        for o in elems:
            # rev CLC-1.15: membership uses JSON type-sensitive equality
            # (§6.5 layer 8), never Python's coercing `in`/`==` (True == 1).
            if not any(json_equal(o, g) for g in grant_val):
                return False, "not_in_enum"
        return True, ""

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

    if isinstance(grant_val, dict):
        if not isinstance(op_val, dict):
            return False, "params_exceed_grant"
        if len(grant_val) == 0:
            # rev CLC-1.3: an empty params object is unconstrained (§9.3),
            # at every nesting depth — it declares no keys, no closure.
            return True, ""
        for k, gvv in grant_val.items():
            if k not in op_val:
                return False, "params_missing"
            ok, reason = value_subset(op_val[k], gvv)
            if not ok:
                return False, reason
        # §9.3 layer 7 (request side): key closure recurses — every op key
        # inside a nested object must be declared by the grant key (audit
        # 2026-09-16, R16), resolved after the missing-key check above.
        for k in op_val:
            if k not in grant_val:
                return False, f"undeclared_param: {k}"
        return True, ""

    # Exact equality
    if op_val != grant_val:
        return False, "params_exceed_grant"
    return True, ""


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _bound_optional(b: Any) -> bool:
    return isinstance(b, dict) and b.get("optional") is True


def _validate_bound(b: Any) -> str:
    """Validate a §6.5 Bound object (rev CLC-1.10); return "" or a reason."""
    if not isinstance(b, dict):
        return "invalid_params_binding: bound is not an object"
    has_numeric = has_enum = has_nested = False
    for k in b:
        if k in ("min", "max", "step"):
            has_numeric = True
        elif k in ("enum", "min_items", "max_items"):
            has_enum = True
        elif k == "nested":
            has_nested = True
        elif k == "optional":
            if not isinstance(b[k], bool):
                return "invalid_params_binding: optional is not a boolean"
        else:
            return f"invalid_params_binding: unknown Bound member {k}"
    if (1 if has_numeric else 0) + (1 if has_enum else 0) + (1 if has_nested else 0) > 1:
        return "invalid_params_binding: mixed bound families"
    for k in ("min", "max", "step"):
        if k in b and not _is_number(b[k]):
            return f"invalid_params_binding: {k} is not a number"
    if "step" in b and b["step"] <= 0:
        return "invalid_params_binding: step must be positive"
    if "min" in b and "max" in b and b["min"] > b["max"]:
        return "invalid_params_binding: min > max"
    if "enum" in b and not isinstance(b["enum"], list):
        return "invalid_params_binding: enum is not an array"
    for k in ("min_items", "max_items"):
        if k in b:
            n = b[k]
            if not _is_number(n) or n < 0 or n != int(n):
                return f"invalid_params_binding: {k} is not a non-negative integer"
    if "min_items" in b and "max_items" in b and b["min_items"] > b["max_items"]:
        return "invalid_params_binding: min_items > max_items"
    if "nested" in b:
        if not isinstance(b["nested"], dict):
            return "invalid_params_binding: nested is not an object"
        for nb in b["nested"].values():
            r = _validate_bound(nb)
            if r:
                return r
    return ""


def validate_param_bounds(bounds: Optional[dict], params: Optional[dict]) -> str:
    """§6.5 bound grammar + one-representation binding rule; "" if valid."""
    if bounds is None:
        return ""
    try:
        validate_params(bounds)
    except CLCError as e:
        return str(e)
    for k, b in bounds.items():
        if k == "":
            return "invalid_params_binding: empty key"
        if params and k in params:
            return f"invalid_params_binding: {k} in both params and param_bounds"
        r = _validate_bound(b)
        if r:
            return r
    return ""


def _is_multiple_of(v: Any, step: Any) -> bool:
    if step == 0:
        return False
    q = v / step
    return q == int(q) and q * step == v


def _nested_subset(op: dict, nested: dict) -> tuple[bool, str]:
    for k, b in nested.items():
        if k not in op:
            if _bound_optional(b):
                continue
            return False, "params_missing"
        ok, reason = bound_subset(op[k], b)
        if not ok:
            return False, reason
    for k in op:
        if k not in nested:
            return False, f"undeclared_param: {k}"
    return True, ""


def bound_subset(op_val: Any, bound: Any) -> tuple[bool, str]:
    """Check an operation value against a §6.5 Bound (rev CLC-1.10)."""
    if not isinstance(bound, dict):
        return False, "invalid_params_binding"
    if "enum" in bound:
        gv = bound["enum"]
        if len(gv) == 0:
            return False, "empty_bound_denies_class"
        elems = op_val if isinstance(op_val, list) else [op_val]
        for o in elems:
            # rev CLC-1.15: JSON type-sensitive equality (§6.5 layer 8) —
            # `True` is not a member of `[1]` and `1` is not a member of
            # `[True]`, whatever Python's `==` coercion says.
            if not any(json_equal(o, g) for g in gv):
                return False, "not_in_enum"
    if "min_items" in bound or "max_items" in bound:
        card = len(op_val) if isinstance(op_val, list) else 1
        if "min_items" in bound and card < bound["min_items"]:
            return False, "params_cardinality"
        if "max_items" in bound and card > bound["max_items"]:
            return False, "params_cardinality"
    if "nested" in bound:
        if not isinstance(op_val, dict):
            return False, "params_exceed_grant"
        return _nested_subset(op_val, bound["nested"])
    if any(k in bound for k in ("min", "max", "step")):
        if not _is_number(op_val):
            return False, "params_exceed_grant"
        if "min" in bound and op_val < bound["min"]:
            return False, "params_out_of_range"
        if "max" in bound and op_val > bound["max"]:
            return False, "params_out_of_range"
        if "step" in bound and not _is_multiple_of(op_val, bound["step"]):
            return False, "params_not_multiple"
    return True, ""


def _entails_declared(op_params: Optional[dict], grant_params: dict,
                      grant_bounds: dict) -> tuple[bool, str]:
    for gv in grant_params.values():
        if is_empty_bound(gv):
            return False, "empty_bound_denies_class"
    for k, gv in grant_params.items():
        if gv is None:
            return False, f"invalid_params_null: {k}"
    if op_params is not None:
        for k, ov in op_params.items():
            if ov is None:
                return False, f"invalid_params_null: {k}"
    declared = set(grant_params) | set(grant_bounds)
    for k in grant_params:
        if op_params is None or k not in op_params:
            return False, "params_missing"
    for k, b in grant_bounds.items():
        if _bound_optional(b):
            continue
        if op_params is None or k not in op_params:
            return False, "params_missing"
    if op_params is not None:
        for k in op_params:
            if k not in declared:
                return False, f"undeclared_param: {k}"
    for k, gv in grant_params.items():
        ok, reason = value_subset(op_params[k], gv)
        if not ok:
            return False, reason
    for k, b in grant_bounds.items():
        if op_params is None or k not in op_params:
            continue
        ok, reason = bound_subset(op_params[k], b)
        if not ok:
            return False, reason
    return True, ""


def materialize_defaults(grant: dict, op: dict, defaults: Optional[dict]) -> dict:
    """Apply the §6.5 scheme-default rule (explicit > default > absent)."""
    if not defaults:
        return op
    declared = set(grant.get("params") or {}) | set(grant.get("param_bounds") or {})
    params = dict(op.get("params") or {})
    injected = False
    for k, dv in defaults.items():
        if k not in declared:
            continue
        if k not in params:
            params[k] = dv
            injected = True
    if not injected:
        return op
    out = dict(op)
    out["params"] = params
    return out


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

    # §5.3 step 3: grant params absent OR the empty OBJECT {} → true
    # (unconstrained; rev CLC-1.3 §9.3 makes {} ≡ absent).  Only absence
    # and {} count: a falsy scalar or an array must NOT be treated as
    # unconstrained — that was a fail-open (audit 2026-09-16, R6); such a
    # grant is invalid_params_number below.  rev CLC-1.10: a grant is
    # unconstrained only when it declares neither params nor param_bounds.
    gp = grant.get("params")
    gb = grant.get("param_bounds")
    has_params = gp is not None and len(gp) > 0
    has_bounds = gb is not None and len(gb) > 0
    if not has_params and not has_bounds:
        return {"entails": True}

    # §9.1 layer 2 (rev CLC-1.10): param_bounds grammar + binding rule.
    r = validate_param_bounds(gb, gp)
    if r:
        return {"entails": False, "reason": r}

    # Validate null values
    if has_params:
        try:
            validate_params(gp)
        except CLCError as e:
            return {"entails": False, "reason": str(e)}

    if op.get("params") is not None:
        try:
            validate_params(op.get("params"))
        except CLCError as e:
            return {"entails": False, "reason": str(e)}

    # §5.3 steps 4-5: presence and subset over the §6.5 declared set.
    ok, reason = _entails_declared(op.get("params"), gp or {}, gb or {})
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

    # rev CLC-1.14 §6.6: an explicit empty enum in a Bound denies the class.
    for g in grants:
        if _bounds_deny_class(g.get("param_bounds")):
            raise CapabilityNotAuthorized("empty_bound_denies_class")

    # rev CLC-1.14 §6.6 "Key site": a key declared in params by one source and
    # in param_bounds by another is refused.
    params_keys, bounds_keys = set(), set()
    for g in grants:
        params_keys.update((g.get("params") or {}).keys())
        bounds_keys.update((g.get("param_bounds") or {}).keys())
    if params_keys & bounds_keys:
        raise InvalidParamsBinding("invalid_params_binding")

    # Null values in any source's params are invalid in v1 (§5.2) — mirror
    # Go's ValidateGrantParams / TS's validateParams (rev CLC-1.15, cross-type
    # audit: previously a null met `intersect_value`'s fallback and surfaced
    # a weaker no_overlap instead of invalid_params_null: <key>).
    for g in grants:
        validate_params(g.get("params"))

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

        # Intersect param_bounds (§6.6 BoundMeet, rev CLC-1.14).
        rb, gb = result.get("param_bounds") or {}, g.get("param_bounds") or {}
        if rb and gb:
            result["param_bounds"] = _intersect_bounds(rb, gb)
        elif gb:
            result["param_bounds"] = dict(gb)

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
        # rev CLC-1.15: element intersection under JSON type-sensitive
        # equality (§6.5 layer 8), matching Go's enumEqual / TS's jsonEqual.
        result = [_render_number(x) for x in a if any(json_equal(x, y) for y in b)]
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


def _bound_within(child: Any, parent: Any) -> Optional[str]:
    """Report whether a child Bound is within a parent Bound (§13.4.3,
    rev CLC-1.10); None means within."""
    if not isinstance(child, dict) or not isinstance(parent, dict):
        return "params_not_narrower"
    if not _bound_optional(parent) and _bound_optional(child):
        return "params_not_narrower"
    if "min" in parent:
        if "min" not in child or child["min"] < parent["min"]:
            return "params_not_narrower"
    if "max" in parent:
        if "max" not in child or child["max"] > parent["max"]:
            return "params_not_narrower"
    if "step" in parent:
        if "step" not in child or not _is_multiple_of(child["step"], parent["step"]):
            return "params_not_narrower"
    if "enum" in parent:
        if "enum" not in child:
            return "params_not_narrower"
        for e in child["enum"]:
            # rev CLC-1.15: subset under JSON type-sensitive equality
            # (§6.5 layer 8) — a child `true` is not inside a parent `[1]`.
            if not any(json_equal(e, p) for p in parent["enum"]):
                return "params_not_narrower"
    if "min_items" in parent:
        if "min_items" not in child or child["min_items"] < parent["min_items"]:
            return "params_not_narrower"
    if "max_items" in parent:
        if "max_items" not in child or child["max_items"] > parent["max_items"]:
            return "params_not_narrower"
    if "nested" in parent:
        if "nested" not in child:
            return "params_not_narrower"
        pc, cc = parent["nested"], child["nested"]
        for k, pbn in pc.items():
            if k not in cc:
                return "params_not_narrower"
            if _bound_within(cc[k], pbn) is not None:
                return "params_not_narrower"
        for k in cc:
            if k not in pc:
                return "params_not_narrower"
    return None


def contains(parent: dict, child: dict) -> dict:
    """Report whether a child grant stays inside a parent grant's declared
    authorization boundary, per draft-wei-clc-ext-00 §4 (CLD-D).

    The relation is compared on DECLARED sets and DECLARED bounds, not on
    behavior (CLC-v1 §12 keeps that scope).  If any layer of §4 fails,
    contains is False with the first failing layer's reason code.

    Layer semantics match the extension draft:
      - layer 1: both grants valid (identifier + params grammar);
      - layer 2: child id covered by parent id via CLC-v1 path coverage;
      - layer 3: child params within parent's declared bounds and child key
        set closed by parent.

    Constraints are deliberately NOT part of this relation.  Constraints are a
    separate axis that composes by UNION (conjunction) across a delegation
    chain (see intersect, §7), not by subset: a child's constraint set is never
    compared to its parent's here.  Delegation mode is likewise a carrier
    concept (AIC-JWT DA binds it); the language relation takes no mode.
    """
    # Layer 1: grant validity — fail-closed on either side.  The reason is a
    # valid CLC-A code (invalid_capability_id, invalid_params_*).
    for g in (parent, child):
        try:
            validate_capability_id(g["id"])
        except CLCError as e:
            return {"contains": False, "reason": str(e)}
        gp = g.get("params")
        if gp is not None:
            try:
                validate_params(gp)
            except CLCError as e:
                return {"contains": False, "reason": str(e)}
        r = validate_param_bounds(g.get("param_bounds"), gp)
        if r:
            return {"contains": False, "reason": r}

    # Layer 2: identifier coverage — the CLC-v1 path-coverage relation,
    # parameters excluded.  The extension §4.2 keeps the core's
    # different_namespace for scheme/action-class mismatch and collapses every
    # other coverage failure into the layer-2 reason child_exceeds_parent.
    ok, reason = match_id(parent["id"], child["id"])
    if not ok:
        if reason == "different_namespace":
            return {"contains": False, "reason": reason}
        return {"contains": False, "reason": "child_exceeds_parent"}

    # Layer 3: parameter narrowing.
    pp = parent.get("params")
    cp = child.get("params")
    pbn = parent.get("param_bounds")
    cbn = child.get("param_bounds")
    if (pp is None or pp == {}) and (pbn is None or pbn == {}):
        # Parent unconstrained (absent OR {}): contains any child params.
        pass
    elif (cp is None or cp == {}) and (cbn is None or cbn == {}):
        # Child unconstrained under a bounded parent: declaring nothing is
        # not "a subset of the parent's bounds" (§4.3 extra rule).
        return {"contains": False, "reason": "params_not_narrower"}
    else:
        pp = pp or {}
        cp = cp or {}
        pbn = pbn or {}
        cbn = cbn or {}
        for k, pv in pp.items():
            if k not in cp:
                # Child omits a key the parent constrains, or declares it in
                # the other representation (§6.5 binding rule).
                return {"contains": False, "reason": "params_not_narrower"}
            if _contains_within(cp[k], pv) is not None:
                return {"contains": False, "reason": "params_not_narrower"}
        for k, pb in pbn.items():
            if k not in cbn:
                return {"contains": False, "reason": "params_not_narrower"}
            if _bound_within(cbn[k], pb) is not None:
                return {"contains": False, "reason": "params_not_narrower"}
        # Key closure is symmetric: a child that adds a key the parent does
        # not declare allows operations the parent denies (undeclared_param).
        for k in cp:
            if k not in pp:
                return {"contains": False, "reason": "params_not_narrower"}
        for k in cbn:
            if k not in pbn:
                return {"contains": False, "reason": "params_not_narrower"}

    return {"contains": True, "reason": ""}


def _contains_within(child_val: Any, parent_bound: Any) -> Optional[str]:
    """Report whether a child declared value is within a parent declared
    bound using the same JSON subset semantic as §5.2 value_subset (numbers
    as upper bounds, arrays as membership sets, objects per key)."""
    if child_val is None:
        return "invalid_params_null"
    if parent_bound is None:
        return None
    ok, reason = value_subset(child_val, parent_bound)
    if not ok:
        return reason
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

_TIME_OF_DAY_RE = re.compile(r"^([01]?[0-9]|2[0-3]):([0-5][0-9])(:([0-5][0-9]))?$")


def _seconds_of_day(t: str) -> int:
    h, m, s = _parse_hms(t)
    return h * 3600 + m * 60 + s


def _parse_hms(t: str) -> tuple[int, int, int]:
    """Split a time-of-day into (h, m, s).  The caller has already matched
    it against _TIME_OF_DAY_RE; index math on the raw string (e.g. a ":" in
    t[5:]) assumes a two-digit hour and silently drops seconds for
    single-digit hours like "9:30:15" (audit 2026-09-16, R14), so parse
    from the split segments instead."""
    m = _TIME_OF_DAY_RE.match(t)
    assert m is not None, f"unmatched time-of-day {t!r}"
    h = int(m.group(1))
    minute = int(m.group(2))
    sec = int(m.group(4)) if m.group(3) is not None else 0
    return h, minute, sec


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
    to capability_not_authorized per CLC-v1 §9 step 3).

    Every params-level reason code is matched as a PREFIX, not an exact
    set: the languages attach a ": <detail>" suffix (e.g.
    ``invalid_params_number: lone surrogate U+D800``), and an exact-set
    match would silently mis-sort those to capability_not_authorized in
    Python while TypeScript's prefix match returned the params reason
    (audit 2026-09-16, R12).  The two implementations must agree code for
    code."""
    return reason.startswith((
        "params_missing",
        "undeclared_param",
        "params_exceed_grant",
        "empty_bound_denies_class",
        "not_in_enum",
        "invalid_params_null",
        "invalid_params_duplicate_key",
        "invalid_params_number",
        "invalid_params_size",
        "unsupported_language_revision",
        # rev CLC-1.10/1.14: the extended-bound reason codes are params-level
        # too, so an authorize() over a grant carrying param_bounds reports
        # the specific bound denial rather than collapsing it.
        "params_cardinality",
        "params_out_of_range",
        "params_not_multiple",
        "invalid_params_binding",
    ))


def authorize(effective_grant: dict, op: dict) -> dict:
    """Evaluate the decision function per CLC-v1 §8 with a single effective
    grant (§9.3 single-grant path).

    The caller must already have run the §6.2 input-boundary checks on the text
    it received, if it received text.  A params value that has been through a
    JSON decoder no longer carries the information those checks use: a lone
    surrogate survives here, but a decoder is free to repair it first, and the
    repaired value is not distinguishable from a legitimate U+FFFD (§6.2 item
    7).  A caller holding the raw text should call authorize_json_text."""
    return authorize_set([effective_grant], op)


def authorize_json_text(grants: list, op_id: str, raw_params: str = "") -> dict:
    """Normative entry point for a caller that holds the operation's params as
    JSON text: run the §6.2 input-boundary checks on that text, then evaluate.
    ``raw_params`` may be empty for an operation that carries no params.

    A refusal is reported as deny with the §6.2 reason code.  Prefer this over
    decoding the text and calling authorize_set: the decode is lossy for exactly
    the inputs §6.2 refuses, because a lone surrogate escape or an invalid UTF-8
    octet is replaced rather than preserved by a general-purpose decoder
    (§6.2 item 7)."""
    params = None
    if raw_params:
        try:
            validate_raw_params(raw_params)
        except CLCError as exc:
            return {"verdict": "deny", "reason": str(exc)}
        try:
            params = json.loads(raw_params)
        except ValueError:
            return {"verdict": "deny", "reason": "invalid_params_number"}
    return authorize_set(grants, {"id": op_id, "params": params})


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


VALID_RESOLUTION_STATUSES = ("satisfied", "violated", "unknown")


_RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def _valid_now(now: str) -> Optional[Any]:
    """Parse an RFC3339 UTC instant; None when malformed (§8.5)."""
    if not isinstance(now, str) or not _RFC3339_RE.match(now):
        return None
    try:
        s = now.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(s)
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(datetime.timezone.utc)


def _eval_core_time_window(c: str, now: Any) -> Optional[bool]:
    """Return True (in window) / False (outside) when c is a core-recognized
    §8.1 time:window obligation, else None (not core-evaluable, §8.5)."""
    try:
        validate_constraint(c)
    except CLCError:
        return None
    parts = c.split(":")
    if len(parts) < 2 or f"{parts[0]}:{parts[1]}" != f"{RESERVED_SCHEME}:time":
        return None
    joined = _constraint_params(c)
    if not joined.startswith("window:"):
        return None
    segments = json.loads(joined[len("window:"):])
    sod = now.hour * 3600 + now.minute * 60 + now.second
    for seg in segments:
        start = _seconds_of_day(seg["start"])
        end = _seconds_of_day(seg["end"])
        if seg["end"] == "00:00":
            end = 86400
        if start <= sod < end:
            return True
    return False


def _violated_reason(c: str) -> str:
    """The {type}:violated code of a constraint (§9.2, §8.5)."""
    parts = c.split(":")
    if len(parts) >= 2 and parts[1]:
        return f"{parts[1]}:violated"
    return "violated"


def _stricter_status(a: str, b: str) -> str:
    rank = {"violated": 2, "satisfied": 1, "unknown": 0}
    return b if rank[b] > rank[a] else a


def resolve(decision: dict, resolutions: Optional[list] = None, now: Optional[str] = None) -> dict:
    """Collapse a decision's §8.4 obligations with consumer reports and an
    optional clock (§8.5, rev CLC-1.11).

    Deterministic, fail-closed, idempotent and monotone; terminal deny/allow
    decisions pass through unchanged; it neither invents nor drops
    obligations."""
    resolutions = resolutions or []
    # Rule 1: terminal verdicts are fixed.
    if decision.get("verdict") in (VERDICT_DENY, VERDICT_ALLOW):
        return dict(decision)
    if decision.get("verdict") != VERDICT_ALLOW_UNRESOLVED:
        return {"verdict": VERDICT_DENY, "reason": "invalid_resolution"}

    # Rule 2: malformed input fails closed, before any discharge.
    for r in resolutions:
        if not isinstance(r, dict) or not r.get("constraint") or r.get("status") not in VALID_RESOLUTION_STATUSES:
            return {"verdict": VERDICT_DENY, "reason": "invalid_resolution"}
    now_dt = None
    if now is not None:
        now_dt = _valid_now(now)
        if now_dt is None:
            return {"verdict": VERDICT_DENY, "reason": "invalid_timestamp"}

    # Rules 3-5: status per obligation, most-restrictive-first.
    obligations = sorted(set(decision.get("unresolved") or []))
    remainder = []
    for o in obligations:
        status = "unknown"
        for r in resolutions:
            if r["constraint"] == o:
                status = _stricter_status(status, r["status"])
        if now_dt is not None:
            clock = _eval_core_time_window(o, now_dt)
            if clock is True:
                status = _stricter_status(status, "satisfied")
            elif clock is False:
                status = _stricter_status(status, "violated")
        if status == "violated":
            return {"verdict": VERDICT_DENY, "reason": _violated_reason(o)}
        if status != "satisfied":
            remainder.append(o)

    if not remainder:
        return {"verdict": VERDICT_ALLOW}
    return {"verdict": VERDICT_ALLOW_UNRESOLVED, "unresolved": remainder}


def constraint_union(chain: list) -> list:
    """The derived chain-constraint projection (§7.1, rev CLC-1.12): the
    normalized union of every constraint string carried by the grants in
    chain — duplicates folded, lexically sorted.  A projection, not a meet:
    it compares no identifiers or params, reads no constraint values and
    checks no containment.  An empty chain fails closed with absent_source
    (§7 rule 5)."""
    if not chain:
        raise CapabilityNotAuthorized("absent_source")
    out = set()
    for g in chain:
        out.update(g.get("constraints") or [])
    return sorted(out)


def authorize_with_chain(chain: list, op: dict) -> dict:
    """The fused chain check (§13.11, rev CLC-1.13, CLC-D): each adjacent hop
    is checked with contains(), and the operation is authorized against
    intersect(chain).  An empty chain denies absent_source; the first hop whose
    containment fails ends the call with that hop's §13.5 reason code (before
    op validation); an intersect refusal is returned as deny(reason).  Judging
    the operation against the intersection is what brings every ancestor's
    params and constraints into force — constraints are outside containment
    (a union axis), so authorizing against the leaf alone would be unsound."""
    if not chain:
        return {"verdict": VERDICT_DENY, "reason": "absent_source"}
    for i in range(len(chain) - 1):
        r = contains(chain[i], chain[i + 1])
        if not r["contains"]:
            return {"verdict": VERDICT_DENY, "reason": r["reason"]}
    try:
        effective = intersect(chain)
    except CLCError as e:
        return {"verdict": VERDICT_DENY, "reason": str(e)}
    return authorize(effective, op)
