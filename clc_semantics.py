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
from decimal import Decimal, InvalidOperation
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
# (rev CLC-1.16 · 2026-09-28: corrective — I-JSON integer bound (§6.2 step 3),
# leading-BOM refusal (step 8), host numeric-carrier normalization (step 9).)
# (rev CLC-1.17 · 2026-10-13: corrective, no verdict change — §6.2 step 3 is
# restated so the I-JSON integer bound is judged on the mathematical value of
# the received token (an exactly-representable value such as 1e100 is refused),
# number identity is the JSON number not its spelling (-0 ≡ 0, 1e3 ≡ 1000), and
# a non-integer token is pinned to its IEEE-754 binary64 value.)
CLC_REVISION = "CLC-1.19"
# §6.2 step 4: bounds on the JCS-serialized params form.
MAX_PARAMS_SERIALIZED_BYTES = 512
MAX_PARAMS_NESTING = 32


def _q(v: Any) -> str:
    """Go's `%q` — a double-quoted string literal.  Python's `%r` prints single
    quotes, so the reference's reason strings would never match byte for byte."""
    return json.dumps(v, ensure_ascii=False) if isinstance(v, str) else repr(v)


def _duration_frac(value: int, base: int, digits: int) -> str:
    if value == 0:
        return ""
    whole, frac = divmod(value, base)
    if frac == 0:
        return str(whole)
    return "%d.%s" % (whole, ("%0*d" % (digits, frac)).rstrip("0"))


def _fmt_duration(seconds: float) -> str:
    """Go's `time.Duration.String()`: the reference prints an age or a bound in
    unit form (`2m0s`, `1m0s`), never as a raw count of seconds."""
    ns = int(round(seconds * 1_000_000_000))
    if ns == 0:
        return "0s"
    neg = ns < 0
    if neg:
        ns = -ns
    if ns < 1_000:
        body = "%dns" % ns
    elif ns < 1_000_000:
        body = _duration_frac(ns, 1_000, 3) + "\u00b5s"
    elif ns < 1_000_000_000:
        body = _duration_frac(ns, 1_000_000, 6) + "ms"
    else:
        secs, nsecs = divmod(ns, 1_000_000_000)
        frac = _duration_frac(nsecs, 1_000_000_000, 9)
        if secs < 60:
            body = "%d%ss" % (secs, frac)
        elif secs < 3600:
            body = "%dm%d%ss" % (secs // 60, secs % 60, frac)
        else:
            body = "%dh%dm%d%ss" % (secs // 3600, secs % 3600 // 60, secs % 60, frac)
    return ("-" if neg else "") + body


def _go_str_list(values: list) -> str:
    """Go's `%v` on a []string: `[a b]` — space separated, unquoted.  `%v` is
    not a Python conversion at all, so the old message raised ValueError."""
    return "[%s]" % " ".join(str(v) for v in values)


def _digest_hex(value: Any) -> str:
    """Go's `%x` on a digest's raw bytes: the reference prints hex, not the
    base64 carrier that JSON carries them in."""
    if not isinstance(value, str):
        return ""
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return ""
    return raw.hex()


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


IJSON_MAX_INTEGER = 2**53 - 1


def _exceeds_ijson_integer_bound(lit: str) -> bool:
    """True when lit is an integer-valued JSON number whose magnitude exceeds
    2^53 - 1 (§6.2 step 3, rev CLC-1.17).  The bound is on the mathematical
    value, not on binary64 representability: an integer-valued literal outside
    [-(2^53 - 1), 2^53 - 1] is refused even when binary64 holds it exactly
    (1e100, 9007199254740992), so acceptance does not turn on the carrier.
    Accepting a larger integer would decide `op <= grant` on a value rounded to
    a neighbour the sender never wrote (9007199254740993 -> 9007199254740992).
    Decimal is exact for the literal, so the fraction and exponent spellings of
    an over-bound integer are recognized too."""
    try:
        d = Decimal(lit)
    except (InvalidOperation, ValueError):
        return False
    if d != d.to_integral_value():
        return False
    return abs(d) > IJSON_MAX_INTEGER


def _reject_non_finite(value: Any) -> None:
    """Reject non-finite numbers anywhere in params (rev CLC-1.4), and an
    integer past the I-JSON bound (rev CLC-1.16 §6.2 step 3).  JSON cannot
    represent non-finite values, and a value that no bound check can compare
    must not become an allow (NaN compares false against every bound).

    The int branch is not redundant with the float one: ``json.loads`` yields an
    exact ``int`` for a literal carrying neither fraction nor exponent, and
    Python's ints are unbounded, so a decoded params object can hold an integer
    the raw path would have refused without ever producing a float to test.
    ``bool`` is a subclass of ``int`` and is not a numeric param."""
    if isinstance(value, bool):
        pass
    elif isinstance(value, int):
        if abs(value) > IJSON_MAX_INTEGER:
            raise InvalidParamsNumber("invalid_params_number")
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidParamsNumber("invalid_params_number")
        if value.is_integer() and abs(value) > IJSON_MAX_INTEGER:
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


def compute_action_id(action_type, material_fields=None, suite=None,
                      action=None) -> str:
    """§4.3 ActionId over the declared material projection:
    `clc-action:1:<type>:<suite>:<b64url(sha256(JCS(projection)))>`.  A declared
    field that is absent makes the action non-matchable.

    Two call layouts are accepted and produce identical bytes:

    - Go reference form — `compute_action_id(def, suite, action)`, where `def`
      is an ActionTypeDefinition object;
    - this demo's historical form —
      `compute_action_id(action_type, material_fields, suite, action)`.
    """
    if isinstance(action_type, dict):
        # Go layout binds the definition to the first parameter, the suite to
        # the second and the action to the third; capture them before
        # overwriting anything.
        definition = action_type
        go_suite = material_fields
        go_action = suite
        action_type = definition["type"]
        material_fields = definition.get("material_fields")
        suite = go_suite
        action = go_action
    # Go `ComputeActionID` dispatches through MaterialProjection (which
    # validates the type definition) and then through the suite-pinned hash, so
    # an unknown suite or an unmatchable projection is refused here too.
    definition = action_type_definition(action_type, material_fields)
    validate_action_type_definition(definition)
    if not _suite_valid(suite):
        raise ActionSuite('action_suite: %s' % _q(suite))
    projection = material_projection(definition, action)
    canonical = canonical_json(projection).encode('utf-8')
    digest = hashlib.sha256(canonical).digest()
    return action_id_string(action_id(
        definition["type"], suite,
        {"alg": _digest_alg_of(suite),
         "value": base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')}))


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
        if (not math.isfinite(v)
                or _exceeds_ijson_integer_bound(lit)
                or _significant_digits(lit) > 17):
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
            "invalid_params_duplicate_key: %s" % _q(dup_key[0])
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
        # The constraint operand is not exempt from the I-JSON bound (§8.1
        # max_rows × key-closure reconciliation): an integer magnitude above
        # 2^53-1 has no exact binary64 representation, so binding it would round
        # the ceiling and decide "op <= grant" on a value the signer never
        # wrote.  Refused as invalid_constraint, the §8.1 reason code.
        if _exceeds_ijson_integer_bound(parts[2]):
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


# --- Declared parameter domains (CLC-1.19 §6.7) --------------------------------
#
# The declaration is applied as a pre-comparison normalization: a value whose
# domain has a numeric normal form is rewritten, and the ordinary relations then
# run unchanged.  `quantity` is normalized to its number; the three string-shaped
# domains (`decimal-string`, `subdomain`, `path-prefix`) are decided in the
# *_with_domains pre-check and then neutralized so the ordinary relation does not
# re-compare them by shape.  A domain name the revision does not define is
# refused with `unsupported_domain`.

_IMPLEMENTED_DOMAINS = {
    "bound", "enum", "exact", "quantity",
    "decimal-string", "subdomain", "path-prefix",
}


def normalize_for_domains(params, dm):
    """Rewrite declared quantity values; return (params, reason)."""
    if not params or not dm:
        return params, ""
    out = {}
    for k, v in params.items():
        spec = dm.get(k)
        if not spec:
            out[k] = v
            continue
        domain = spec.get("domain")
        if domain in ("bound", "enum", "exact", "decimal-string", "subdomain", "path-prefix"):
            out[k] = v
            continue
        if domain not in _IMPLEMENTED_DOMAINS:
            return None, "unsupported_domain"
        val = v.get("value") if isinstance(v, dict) else None
        unit = v.get("unit") if isinstance(v, dict) else None
        if isinstance(val, bool) or not isinstance(val, (int, float)) or not isinstance(unit, str) or not unit:
            return None, "invalid_params_binding"
        if unit != spec.get("unit"):
            return None, "unit_mismatch"
        scale = 0
        if "scale" in v:
            s = v["scale"]
            if isinstance(s, bool) or not isinstance(s, (int, float)) or s != int(s):
                return None, "invalid_params_binding"
            scale = int(s)
        out[k] = float(val) * (10.0 ** -scale)
    return out, ""




_STRING_DOMAINS = {"decimal-string", "subdomain", "path-prefix"}

# A canonical §6.7 `decimal-string` literal.  Decimal() on its own also accepts
# underscores, inf/nan/sNaN and the half-written `500.`/`.5` forms; those are not
# decimal literals, so they are refused here to keep the implementations aligned.
_DECIMAL_RE = re.compile(r"^[+-]?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$")


def _parse_decimal(s):
    if not _DECIMAL_RE.match(s):
        return None
    return Decimal(s)


def _normalize_domain(s):
    """A DNS name or None.

    Lowercases, drops at most one trailing dot (the root), and requires every
    label to be non-empty — mirroring the Go/Java/TS implementations.  A name
    with more than one trailing dot has an empty label and is not a DNS name,
    so it is refused rather than silently collapsed."""
    if any(ch.isspace() for ch in s):
        return None
    t = s.lower()
    if t.endswith("."):
        t = t[:-1]
    if not t or any(label == "" for label in t.split(".")):
        return None
    return t


def _string_domain_covers(domain, parent, child):
    """(ok, reason) for one string-shaped declared domain."""
    import posixpath
    if not isinstance(parent, str) or not isinstance(child, str):
        return False, "invalid_params_binding"
    if domain == "decimal-string":
        p, c = _parse_decimal(parent), _parse_decimal(child)
        if p is None or c is None:
            return False, "invalid_params_binding"
        return (True, "") if c <= p else (False, "params_exceed_grant")
    if domain == "subdomain":
        p, c = _normalize_domain(parent), _normalize_domain(child)
        if p is None or c is None:
            return False, "invalid_params_binding"
        return (True, "") if (c == p or c.endswith("." + p)) else (False, "params_exceed_grant")
    if domain == "path-prefix":
        if not parent.startswith("/") or not child.startswith("/"):
            return False, "invalid_params_binding"
        if parent.startswith("//") or child.startswith("//"):
            return False, "invalid_params_binding"
        if posixpath.normpath(parent) != parent or posixpath.normpath(child) != child:
            return False, "invalid_params_binding"
        p = parent.rstrip("/") or "/"
        return (True, "") if (child == p or child.startswith(p + "/")) else (False, "params_exceed_grant")
    return False, "unsupported_domain"


def authorize_set_with_domains(grants, op, dm):
    op_params = dict(op.get("params") or {})
    opts = []
    for g in grants:
        if any(k in dm for k in (g.get("param_bounds") or {})):
            return {"verdict": VERDICT_DENY, "reason": "invalid_params_binding"}
        g_params = dict(g.get("params") or {})
        usable = True
        for name, spec in dm.items():
            if spec.get("domain") in _STRING_DOMAINS:
                if name not in g_params or name not in op_params:
                    continue
                ok, reason = _string_domain_covers(spec["domain"], g_params[name], op_params[name])
                if not ok:
                    if reason == "invalid_params_binding":
                        return {"verdict": VERDICT_DENY, "reason": reason}
                    usable = False
                    break
                g_params[name] = "domain-covered"
                op_params[name] = "domain-covered"
        if not usable:
            continue
        params, reason = normalize_for_domains(g_params, dm)
        if reason:
            return {"verdict": VERDICT_DENY, "reason": reason}
        opts.append({**g, "params": params})
    if grants and not opts:
        return {"verdict": VERDICT_DENY, "reason": "params_exceed_grant"}
    params, reason = normalize_for_domains(op_params, dm)
    if reason:
        return {"verdict": VERDICT_DENY, "reason": reason}
    return authorize_set(opts, {**op, "params": params})


def entails_with_domains(grant, op, dm):
    gp = dict(grant.get("params") or {})
    opp = dict(op.get("params") or {})
    for name, spec in dm.items():
        if spec.get("domain") in _STRING_DOMAINS and name in gp and name in opp:
            ok, reason = _string_domain_covers(spec["domain"], gp[name], opp[name])
            if not ok:
                return {"entails": False, "reason": reason}
            gp[name] = "domain-covered"
            opp[name] = "domain-covered"
    gp, reason = normalize_for_domains(gp, dm)
    if reason:
        return {"entails": False, "reason": reason}
    opp, reason = normalize_for_domains(opp, dm)
    if reason:
        return {"entails": False, "reason": reason}
    return entails({**grant, "params": gp}, {**op, "params": opp})


def contains_with_domains(parent, child, parent_dm, child_dm):
    if any(k in parent_dm for k in (parent.get("param_bounds") or {})) or \
       any(k in child_dm for k in (child.get("param_bounds") or {})):
        return {"contains": False, "reason": "params_not_narrower"}
    pp = dict(parent.get("params") or {})
    cp = dict(child.get("params") or {})
    for name, pspec in parent_dm.items():
        cspec = child_dm.get(name)
        if not cspec:
            continue
        if pspec.get("domain") != cspec.get("domain"):
            return {"contains": False, "reason": "params_not_narrower"}
        if pspec.get("domain") in _STRING_DOMAINS and name in pp and name in cp:
            ok, _ = _string_domain_covers(pspec["domain"], pp[name], cp[name])
            if not ok:
                return {"contains": False, "reason": "params_not_narrower"}
            pp[name] = "domain-covered"
            cp[name] = "domain-covered"
    pp, reason = normalize_for_domains(pp, parent_dm)
    if reason:
        return {"contains": False, "reason": "params_not_narrower"}
    cp, reason = normalize_for_domains(cp, child_dm)
    if reason:
        return {"contains": False, "reason": "params_not_narrower"}
    return contains({**parent, "params": pp}, {**child, "params": cp})


# =============================================================================
# Go-parity layer — 1:1 port of the Go reference implementation
# (`register/semantics`, CLC-1.19).  Function names, argument order, reason
# strings and layer precedence mirror the Go exports; only the error carrier
# differs (Go returns `error`, Python raises CLCError).
# =============================================================================


# --- register/semantics/semantics.go: ValidateGrantParams / ---              |
#     ValidateOperationParams / ConstraintWithin                              |

class InvalidParamsAbsent(CLCError):
    pass


def validate_grant_params(params: Optional[dict]) -> None:
    """Go `ValidateGrantParams`: null-value check (§5.2) plus the §6.2 step 4
    caps on the decoded-object path (§6.2 step 6)."""
    validate_params(params)


def validate_operation_params(params: Optional[dict]) -> None:
    """Go `ValidateOperationParams`: identical body to ValidateGrantParams —
    both entry points MUST reject the caps."""
    validate_params(params)


def constraint_within(value: Any, bound: Any) -> None:
    """Go `ConstraintWithin(value, bound) error`.

    Publication-boundary check: a rule's constraint value must not exceed the
    signer's constraint value, using the same JSON subset semantic as §5.2
    valueSubset.  A bound of None is nominal (any value accepted); an
    explicitly empty bound ({} or []) denies the class, exactly like §5.2.
    """
    if value is None:
        raise InvalidParamsNull("invalid_params_null")
    if bound is None:
        return None
    ok, reason = value_subset(value, bound)
    if not ok:
        raise CLCError(reason)
    return None


# --- register/semantics/obligations.go ---------------------------------------

class ObligationUnknown(CLCError):
    pass


class ObligationShape(CLCError):
    pass


# §3 scheme grammar, shared with capability ids (P7: one definition, consumed
# everywhere).  Mirrors Go's `capabilitySchemeRE`.
_CAPABILITY_SCHEME_RE = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9-]+-v[0-9]+$")


def obligations(d: dict) -> list:
    """Go `Obligations(d) []string` — an independent copy of the §8.4
    obligation list (empty for deny and for a fully evaluated allow)."""
    return list(d.get("unresolved") or [])


def constraint_identity(c: str) -> str:
    """Go `ConstraintIdentity(c) (string, error)` — the (scheme,type)
    identity of a constraint.  A constraint that does not carry a parseable
    identity cannot be dispatched to any evaluator, so it is reported as an
    unknown obligation rather than passed along as text."""
    parts = c.split(":")
    if len(parts) < 2 or parts[0] == "" or parts[1] == "":
        raise ObligationUnknown("obligation_unknown: %s" % _q(c))
    if not _CAPABILITY_SCHEME_RE.match(parts[0]):
        raise ObligationUnknown("obligation_unknown: %s" % _q(c))
    for r in parts[1]:
        if not (r.isascii() and (r.isalnum() or r in "-_")):
            raise ObligationUnknown("obligation_unknown: %s" % _q(c))
    return parts[0] + ":" + parts[1]


def obligation_identities(d: dict) -> list:
    """Go `ObligationIdentities(d) ([]string, error)` — the sorted,
    deduplicated (scheme,type) identities of the decision's obligations."""
    seen = set()
    out = []
    for c in obligations(d):
        ident = constraint_identity(c)
        if ident in seen:
            continue
        seen.add(ident)
        out.append(ident)
    out.sort()
    return out


def check_decision_shape(d: dict) -> None:
    """Go `checkDecisionShape(d) error` — enforces the §8.4 relation between
    the verdict and the obligation list."""
    ids = obligation_identities(d)
    verdict = d.get("verdict")
    if verdict in (VERDICT_ALLOW, VERDICT_DENY):
        if len(ids) > 0:
            raise ObligationShape("obligation_shape: verdict %s carries obligations %s" % (verdict, ids))
    elif verdict == VERDICT_ALLOW_UNRESOLVED:
        if len(ids) == 0:
            raise ObligationShape("obligation_shape: allow_unresolved without obligations")
    else:
        raise ObligationShape('obligation_shape: unknown verdict %s' % _q(verdict))


def discharge(d: dict, understood: list) -> None:
    """Go `Discharge(d, understood) error` — whether a consumer may act.

    A decision with no obligations always discharges.  Every obligation on an
    allow_unresolved decision must be covered by `understood`; otherwise the
    consumer must deny (XACML §2.13)."""
    ids = obligation_identities(d)
    check_decision_shape(d)
    if d.get("verdict") != VERDICT_ALLOW_UNRESOLVED:
        return None
    have = set(understood)
    for ident in ids:
        if ident not in have:
            raise ObligationUnknown(
                # Go spells this one with %s, not %q — the constraint itself
                # already appears quoted in the shape check above.
                "obligation_unknown: %s (the consumer must understand, can and will discharge it)" % ident)
    return None


# --- register/semantics/combine.go -------------------------------------------

class NoDecisions(CLCError):
    pass


class UnknownCombiningAlgorithm(CLCError):
    pass


class CombiningWouldDropObligations(CLCError):
    pass


COMBINING_DENY_OVERRIDES = "deny-overrides"
COMBINING_PERMIT_OVERRIDES = "permit-overrides"
COMBINING_FIRST_APPLICABLE = "first-applicable"
DEFAULT_COMBINING_ALGORITHM = COMBINING_DENY_OVERRIDES

_COMBINING_ALGORITHMS = {
    COMBINING_DENY_OVERRIDES,
    COMBINING_PERMIT_OVERRIDES,
    COMBINING_FIRST_APPLICABLE,
}


def _has_obligations(decisions: list) -> bool:
    return any(d.get("unresolved") for d in decisions)


def _combine_deny_overrides(decisions: list) -> dict:
    obligations_union: list = []
    saw_allow = False
    for d in decisions:
        verdict = d.get("verdict")
        if verdict == VERDICT_DENY:
            # Deny wins outright; its reason is the reported one.
            return {"verdict": VERDICT_DENY, "reason": d.get("reason", "")}
        if verdict == VERDICT_ALLOW_UNRESOLVED:
            obligations_union.extend(obligations(d))
        elif verdict == VERDICT_ALLOW:
            saw_allow = True
    if obligations_union:
        return {"verdict": VERDICT_ALLOW_UNRESOLVED, "unresolved": sorted(set(obligations_union))}
    if saw_allow:
        return {"verdict": VERDICT_ALLOW}
    # Unreachable while the verdict set is closed, but the fallback must not
    # be allow.
    return {"verdict": VERDICT_DENY, "reason": "capability_not_authorized"}


def _combine_permit_overrides(decisions: list) -> dict:
    obligations_union: list = []
    first_deny: Optional[dict] = None
    for i, d in enumerate(decisions):
        verdict = d.get("verdict")
        if verdict == VERDICT_ALLOW:
            # A later allow would drop the obligations already collected.
            if obligations_union or _has_obligations(decisions[i + 1:]):
                raise CombiningWouldDropObligations("combining_would_drop_obligations")
            return {"verdict": VERDICT_ALLOW}
        if verdict == VERDICT_ALLOW_UNRESOLVED:
            obligations_union.extend(obligations(d))
        elif verdict == VERDICT_DENY:
            if first_deny is None:
                first_deny = d
    if first_deny is not None:
        return {"verdict": VERDICT_DENY, "reason": first_deny.get("reason", "")}
    if obligations_union:
        return {"verdict": VERDICT_ALLOW_UNRESOLVED, "unresolved": sorted(set(obligations_union))}
    return {"verdict": VERDICT_DENY, "reason": "capability_not_authorized"}


def combine(algorithm: str, decisions: list) -> dict:
    """Go `Combine(alg, decisions...) (Decision, error)`.

    Applies a named combining algorithm to independently decided sources.
    Every decision must satisfy the §8.4 shape; a malformed one fails closed.
    """
    if algorithm not in _COMBINING_ALGORITHMS:
        raise UnknownCombiningAlgorithm("unknown_combining_algorithm: %s" % _q(algorithm))
    if len(decisions) == 0:
        raise NoDecisions("no_decisions")
    for i, d in enumerate(decisions):
        try:
            check_decision_shape(d)
        except CLCError as e:
            raise type(e)("decision %d: %s" % (i, e))
    if algorithm == COMBINING_FIRST_APPLICABLE:
        return decisions[0]
    if algorithm == COMBINING_PERMIT_OVERRIDES:
        return _combine_permit_overrides(decisions)
    return _combine_deny_overrides(decisions)


# --- register/semantics/evidence.go ------------------------------------------

class InvalidEvidenceConstraint(CLCError):
    pass


EVIDENCE_SCHEME = "varwof/evidence-v1"
EVIDENCE_FRESHNESS = EVIDENCE_SCHEME + ":freshness"
EVIDENCE_CONSUMPTION = EVIDENCE_SCHEME + ":consumption"
EVIDENCE_QUORUM = EVIDENCE_SCHEME + ":quorum"
EVIDENCE_EXCLUSION = EVIDENCE_SCHEME + ":exclusion"

# Bounds max_age_sec so the seconds arithmetic below cannot wrap.  An absurdly
# large age is a grammar error, not a wrap-around freshness answer.
MAX_EVIDENCE_AGE_SECONDS = 1_000_000_000  # ~31.7 years

EVIDENCE_SATISFIED = "satisfied"
EVIDENCE_VIOLATED = "violated"
EVIDENCE_UNKNOWN = "unknown"


def evidence_fact(type_: str = "", subject: str = "", issued_at: str = "",
                  verified: bool = False) -> dict:
    """Go `EvidenceFact` — one natively verified artifact reduced to the fields
    the core may evaluate over.  Presenter labels are not represented at all,
    so they cannot be counted by accident."""
    return {"type": type_, "subject": subject, "issued_at": issued_at,
            "verified": verified}


def validate_evidence_constraint(c: str) -> None:
    """Go `ValidateEvidenceConstraint(c) error` — the closed value grammar of
    the four evidence-side types.  An unrecognized (scheme,type) is an error,
    never a silent pass."""
    parts = c.split(":")
    if len(parts) < 2:
        raise InvalidEvidenceConstraint("invalid_evidence_constraint: %s" % _q(c))
    identity = parts[0] + ":" + parts[1]
    if identity == EVIDENCE_FRESHNESS:
        if len(parts) != 4 or parts[2] != "sec":
            raise InvalidEvidenceConstraint(
                "invalid_evidence_constraint: %s (want %s:freshness:sec:<n>)" % (_q(c), EVIDENCE_SCHEME))
        if not _is_strict_json_integer(parts[3]):
            raise InvalidEvidenceConstraint(
                "invalid_evidence_constraint: %s (max age must be a non-negative integer)" % (_q(c),))
        if int(parts[3]) > MAX_EVIDENCE_AGE_SECONDS:
            raise InvalidEvidenceConstraint(
                "invalid_evidence_constraint: %s (max age exceeds %d seconds)" % (_q(c), MAX_EVIDENCE_AGE_SECONDS))
    elif identity == EVIDENCE_CONSUMPTION:
        if len(parts) != 3 or parts[2] != "once":
            raise InvalidEvidenceConstraint(
                "invalid_evidence_constraint: %s (want %s:consumption:once)" % (_q(c), EVIDENCE_SCHEME))
    elif identity == EVIDENCE_QUORUM:
        if len(parts) != 4 or parts[2] != "distinct":
            raise InvalidEvidenceConstraint(
                "invalid_evidence_constraint: %s (want %s:quorum:distinct:<n>)" % (_q(c), EVIDENCE_SCHEME))
        if not _is_strict_json_integer(parts[3]):
            raise InvalidEvidenceConstraint(
                "invalid_evidence_constraint: %s (a quorum is greater than one)" % (_q(c),))
        if int(parts[3]) < 2:
            raise InvalidEvidenceConstraint(
                "invalid_evidence_constraint: %s (a quorum is greater than one)" % (_q(c),))
    elif identity == EVIDENCE_EXCLUSION:
        if len(parts) != 3 or parts[2] not in ("initiator", "executor"):
            raise InvalidEvidenceConstraint(
                "invalid_evidence_constraint: %s (want %s:exclusion:initiator|executor)" % (_q(c), EVIDENCE_SCHEME))
    else:
        raise InvalidEvidenceConstraint("invalid_evidence_constraint: %s" % _q(c))
    return None


def _evidence_eligible(facts: list) -> list:
    """Go `eligible` — keeps the facts a verifier actually established
    (AEC §9.4.f: only eligible components contribute)."""
    return [f for f in facts if f.get("verified") is True]


def _distinct_subjects(facts: list) -> set:
    """Go `distinctSubjects` — counts integrity-protected subject identifiers.
    An empty subject is ineligible."""
    return {f.get("subject") for f in _evidence_eligible(facts) if f.get("subject")}


_UTC_SUFFIX_RE = re.compile(r"Z$", re.IGNORECASE)


def _is_utc_instant(s: Any) -> bool:
    """Go's `Location() != time.UTC` test, in the string form the ports hold
    the instant in: only a trailing Z reads as UTC.  `+00:00` names a fixed
    offset, not UTC, and encodes differently."""
    if not isinstance(s, str) or not _RFC3339_RE.fullmatch(s):
        return False
    return _UTC_SUFFIX_RE.search(s) is not None


def _parse_rfc3339(s: Any):
    """Go's `time.Time` JSON handling: a strict RFC3339 instant with an offset.
    A naive (offset-less) or unparseable stamp is not an instant, so it is None
    rather than a silently-localized one."""
    if not s or not isinstance(s, str):
        return None
    try:
        t = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        return None
    return t


def _parse_utc(s: Any):
    """An RFC3339 instant normalized to UTC (the same instant, `astimezone`
    rather than a `replace`, so an offset-stamped value keeps its meaning)."""
    t = _parse_rfc3339(s)
    return None if t is None else t.astimezone(datetime.timezone.utc)


# Go's zero `time.Time` (year 1).  A context that pinned no clock reads as this
# instant, which is how the freshness comparisons below fail closed.
_ZERO_TIME = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)


def evaluate_evidence_constraint(c: str, facts: list, ctx: Optional[dict] = None) -> dict:
    """Go `EvaluateEvidenceConstraint(c, facts, ctx) (EvidenceEvaluation, error)`.

    Evaluates one evidence constraint over the eligible facts of a single
    evidence role.  A malformed constraint raises; a recognized-but-external
    one returns verdict=unknown with reason `evidence_not_core_evaluated`.
    """
    ctx = ctx or {}
    validate_evidence_constraint(c)
    parts = c.split(":")
    out = {"constraint": c}

    identity = parts[0] + ":" + parts[1]
    if identity == EVIDENCE_FRESHNESS:
        max_age = int(parts[3])
        # Go takes `ctx.Now` from the caller; an absent clock reads as the zero
        # instant, which makes any real issuance "future" — fail closed, never
        # a silent pass.
        now = _parse_utc(ctx.get("now")) or _ZERO_TIME
        fs = _evidence_eligible(facts)
        for f in fs:
            t = _parse_utc(f.get("issued_at"))
            if t is None:
                out["verdict"], out["reason"] = EVIDENCE_VIOLATED, "freshness:no_issuance_time"
                return out
            if t > now:
                out["verdict"], out["reason"] = EVIDENCE_VIOLATED, "freshness:future_issued"
                return out
            if (now - t).total_seconds() > max_age:
                out["verdict"], out["reason"] = EVIDENCE_VIOLATED, "freshness:stale"
                return out
        if len(fs) == 0:
            # Nothing eligible to be fresh: the requirement is unfilled.
            out["verdict"], out["reason"] = EVIDENCE_VIOLATED, "freshness:no_eligible_fact"
            return out
        out["verdict"] = EVIDENCE_SATISFIED
        return out

    if identity == EVIDENCE_QUORUM:
        threshold = int(parts[3])
        distinct = _distinct_subjects(facts)
        if len(distinct) < threshold:
            out["verdict"] = EVIDENCE_VIOLATED
            out["reason"] = "quorum:distinct_subjects=%d<threshold=%d" % (len(distinct), threshold)
            return out
        out["verdict"] = EVIDENCE_SATISFIED
        return out

    if identity == EVIDENCE_EXCLUSION:
        who = parts[2]
        excluded = ctx.get("initiator" if who == "initiator" else "executor")
        if not excluded:
            # The boundary-owned identity was not supplied.  Absence is never
            # "not excluded": exclusion cannot be established, so it is unknown.
            out["verdict"], out["reason"] = EVIDENCE_UNKNOWN, "exclusion:identity_not_supplied"
            return out
        for subject in _distinct_subjects(facts):
            if subject == excluded:
                out["verdict"], out["reason"] = EVIDENCE_VIOLATED, "exclusion:%s_is_approver" % who
                return out
        out["verdict"] = EVIDENCE_SATISFIED
        return out

    # evidenceConsumption: durable one-time state lives at the enforcement
    # point; the core must not answer it.  Reported as a residual obligation,
    # never as satisfied.
    out["verdict"], out["reason"] = EVIDENCE_UNKNOWN, "evidence_not_core_evaluated"
    return out


def core_evaluates_evidence_constraint(c: str) -> bool:
    """Go `CoreEvaluatesEvidenceConstraint(c) bool` — whether this revision has
    an evaluator for the constraint.  Unrecognized constraints report False."""
    try:
        validate_evidence_constraint(c)
    except CLCError:
        return False
    parts = c.split(":")
    return parts[0] + ":" + parts[1] != EVIDENCE_CONSUMPTION


def evidence_facts_of_role(facts: list, role: str) -> list:
    """Go `EvidenceFactsOfRole(facts, role) []EvidenceFact` — selects the facts
    filling one evidence role; callers scope first and evaluate second."""
    return [f for f in facts if f.get("type") == role]


# --- register/semantics/record.go --------------------------------------------
#
# Representation note (Python): Go carries `Digest.Value` as `[]byte`, which
# json.Marshal renders as standard base64 with padding.  This port therefore
# carries the digest value as that same base64 text, so a canonical
# re-encoding of a record is byte-identical to Go's and round-trips without a
# lossy bytes<->str step.

RECORD_LANG = "clc-v1"
DIGEST_ALG_SHA256 = "sha-256"


def digest(alg: str = DIGEST_ALG_SHA256, value: Any = "") -> dict:
    """Go `Digest` — a hash over a canonical byte string.  `value` is the
    standard-base64 text of the digest bytes."""
    return {"alg": alg, "value": value}


def digest_equal(d: dict, other: dict) -> bool:
    """Go `(Digest) Equal(o)`."""
    return d.get("alg") == other.get("alg") and d.get("value") == other.get("value")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def digest_of(value: Any) -> dict:
    """Go `DigestOf(v) (Digest, error)` — the SHA-256 of v's canonical (JCS,
    RFC 8785) JSON encoding."""
    raw = canonical_json(value).encode("utf-8")
    return {"alg": DIGEST_ALG_SHA256, "value": _b64(hashlib.sha256(raw).digest())}


def digest_of_canonical(canonical: Any) -> dict:
    """Go `DigestOfCanonical(canonical []byte) Digest` — hashes bytes already
    known to be canonical, so Record does not encode the inputs twice."""
    if isinstance(canonical, str):
        canonical = canonical.encode("utf-8")
    return {"alg": DIGEST_ALG_SHA256, "value": _b64(hashlib.sha256(canonical).digest())}


def digest_usable(d: Optional[dict]) -> bool:
    """Go `digestUsable(d) bool` — an algorithm tag and a non-empty value."""
    return bool(d) and bool(d.get("alg")) and bool(d.get("value"))


def _digest_hex(value: Any) -> str:
    """The hex form of a digest value — Go's `hex.EncodeToString(d.Value)`.

    A value that is not decodable base64 is keyed literally: it can never equal
    a valid digest's key, so a malformed digest stays refused rather than
    silently colliding with a real one.
    """
    if not isinstance(value, str) or value == "":
        return str(value)
    try:
        # The urlsafe decoder accepts both the standard and the urlsafe
        # alphabet, so hex-identical digests key identically regardless of which
        # spelling produced them.
        raw = base64.urlsafe_b64decode(_b64_pad(value))
    except Exception:
        return value
    v = value.rstrip("=")
    if (base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != v
            and base64.b64encode(raw).decode("ascii").rstrip("=") != v):
        # A stray non-alphabet character would have been silently discarded;
        # refuse the value instead of letting two digests share a key.
        return value
    return raw.hex()


def _b64_pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def digest_key(d: dict) -> str:
    """Go `digestKey(d) string` — `alg + ":" + hex(value)`."""
    return "%s:%s" % (d.get("alg", ""), _digest_hex(d.get("value", "")))


def digest_from_hex(alg: str, hexvalue: str) -> dict:
    """Helper: build a Digest from the hex form used by in-toto subjects."""
    return {"alg": alg, "value": _b64(bytes.fromhex(hexvalue))}


# --- register/semantics/context.go -------------------------------------------

def epoch_id_of(v: int) -> int:
    """Go `EpochIDOf(v uint64) *uint64`.

    Go uses a pointer so a legitimate epoch id of zero is distinguishable from
    "not used"; Python carries that distinction as the literal `0` versus an
    absent key, so the function is an identity with the documented contract."""
    return v


def decision_context(at: str = "", max_age_sec: int = 0, nonce: str = "",
                     epoch_id: Any = None, snapshot_digest: Optional[dict] = None) -> dict:
    """Go `DecisionContext` — the freshness input a relying party pins for one
    decision (RATS §10).  At least one mechanism must be present."""
    ctx = {"at": at, "max_age_sec": max_age_sec, "nonce": nonce}
    if epoch_id is not None:
        ctx["epoch_id"] = epoch_id
    if snapshot_digest is not None:
        ctx["snapshot_digest"] = snapshot_digest
    return ctx


# Go's zero `time.Time` as encoding/json spells it: `At` is a struct, so it is
# written even when nothing pinned it.
ZERO_TIME_INSTANT = "0001-01-01T00:00:00Z"


def context_is_zero(ctx: dict) -> bool:
    """Go `(DecisionContext) IsZero() bool` — pins no freshness mechanism.

    `At` is a `time.Time`, so Go's JSON encoding always writes it: a context
    that pinned no clock reads back as year 1's zero instant, which must not be
    mistaken for a pinned `at`."""
    raw = ctx.get("at")
    if not raw:
        at_is_zero = True
    else:
        parsed = _parse_utc(raw)
        at_is_zero = parsed is not None and parsed == _ZERO_TIME
    return at_is_zero and not ctx.get("nonce") and ctx.get("epoch_id") is None


def validate_decision_context(ctx: dict) -> None:
    """Go `(DecisionContext) Validate() error`."""
    if ctx.get("max_age_sec", 0) < 0:
        raise CLCError("context_shape: negative max_age_sec")
    if ctx.get("max_age_sec", 0) > 0 and not ctx.get("at"):
        raise CLCError("context_shape: max_age_sec without at")
    if context_is_zero(ctx):
        raise CLCError("context_missing")
    at = _parse_utc(ctx.get("at"))
    if ctx.get("at") and at is None:
        raise CLCError("context_not_utc: at carries an unparseable instant")
    # Go compares `At.Location() != time.UTC`: the same moment written with a
    # fixed offset encodes differently, and would change a record's input
    # digest.  Only a trailing Z reads as UTC.
    if ctx.get("at") and not _is_utc_instant(ctx.get("at")):
        raise CLCError("context_not_utc: at carries location ")
    if ctx.get("snapshot_digest") is not None:
        d = ctx["snapshot_digest"]
        if not d.get("alg") or not d.get("value"):
            raise CLCError("context_shape: incomplete snapshot digest")
    if ctx.get("nonce") and len(ctx["nonce"].encode("utf-8")) > MAX_CONTEXT_NONCE_BYTES:
        raise CLCError("context_shape: nonce longer than %d bytes" % MAX_CONTEXT_NONCE_BYTES)
    return None


# Bounds a nonce the same way §6.2 bounds other inputs, so a hostile peer
# cannot inflate the record.
MAX_CONTEXT_NONCE_BYTES = 512


def fresh_context(ctx: dict, now: str) -> None:
    """Go `(DecisionContext) Fresh(now time.Time) error`.

    `now` is supplied by the caller (the core never reads a clock).  A context
    that pinned only a nonce or an epoch id has no clock claim to check: this
    raises `context_no_clock` rather than passing.
    """
    validate_decision_context(ctx)
    at = _parse_utc(ctx.get("at"))
    if at is None:
        raise CLCError("context_no_clock")
    when = _parse_utc(now)
    if when is None:
        raise CLCError("invalid_timestamp")
    if when < at:
        raise CLCError("context_future: context at %s, checking instant %s" % (ctx.get("at"), now))
    max_age = int(ctx.get("max_age_sec") or 0)
    if max_age > 0:
        age = (when - at).total_seconds()
        if age > max_age:
            raise CLCError("context_stale: age %s exceeds %s"
                           % (_fmt_duration(age), _fmt_duration(max_age)))
    return None


def context_digest(ctx: dict) -> dict:
    """Go `(DecisionContext) Digest() (Digest, error)` — binds the context so a
    record can identify exactly which freshness input it was decided under."""
    validate_decision_context(ctx)
    return digest_of(_context_wire(ctx))


# --- register/semantics/sources.go -------------------------------------------

def _references_digest(refs: list, want: dict) -> bool:
    return any(digest_equal(r, want) for r in (refs or []))


def _detect_cycle(by_digest: dict, edges: dict) -> None:
    WHITE, GREY, BLACK = 0, 1, 2
    color = {}

    def visit(node: str) -> None:
        color[node] = GREY
        for nxt in edges.get(node, []):
            state = color.get(nxt, WHITE)
            if state == GREY:
                raise CLCError("source_chain_cycle: %s" % by_digest[nxt].get("id"))
            if state == WHITE:
                visit(nxt)
        color[node] = BLACK

    for node in edges:
        if color.get(node, WHITE) == WHITE:
            visit(node)


def validate_source_chain(chain: dict) -> None:
    """Go `(SourceChain) Validate() error` — the chain's structure and, in
    particular, that every claimed relation is backed by the source's own
    references."""
    sources = chain.get("sources") or []
    if len(sources) == 0:
        raise CLCError("source_chain_empty")
    by_digest = {}
    for s in sources:
        if not s.get("kind") or not s.get("id"):
            raise CLCError('source_shape: kind/id required (got "%s"/"%s")' % (s.get("kind", ""), s.get("id", "")))
        if not digest_usable(s.get("digest")):
            raise CLCError("source_shape: source %s/%s has no usable digest" % (s.get("kind"), s.get("id")))
        key = digest_key(s["digest"])
        if key in by_digest:
            raise CLCError("source_duplicate: %s" % key)
        by_digest[key] = s

    edges: dict = {}
    for l in chain.get("links") or []:
        from_key, to_key = digest_key(l.get("from", {})), digest_key(l.get("to", {}))
        src, ok_from = by_digest.get(from_key), from_key in by_digest
        dst, ok_to = by_digest.get(to_key), to_key in by_digest
        if not ok_from or not ok_to:
            raise CLCError("source_dangling_link: %s -> %s" % (from_key, to_key))
        if not _references_digest(src.get("references"), dst["digest"]):
            raise CLCError("source_edge_unbacked: %s does not name %s" % (src.get("id"), dst.get("id")))
        edges.setdefault(from_key, []).append(to_key)

    _detect_cycle(by_digest, edges)
    return None


def source_chain_digest(chain: dict) -> dict:
    """Go `(SourceChain) Digest() (Digest, error)` — the sorted node identities
    plus the sorted links, hashed, never the inline material."""
    validate_source_chain(chain)
    # Go builds `nodeID{kind,id,alg,hex(value)}` and sorts on the hex value, so
    # the sort key and the hashed bytes are both hex here.
    nodes = [{"kind": s.get("kind"), "id": s.get("id"),
              "alg": s["digest"].get("alg"), "value": _digest_hex(s["digest"].get("value"))}
             for s in chain.get("sources") or []]
    nodes.sort(key=lambda n: (n["kind"], n["id"], n["value"]))
    links = sorted("%s->%s" % (digest_key(l.get("from", {})), digest_key(l.get("to", {})))
                   for l in (chain.get("links") or []))
    payload = {"sources": nodes}
    if links:
        payload["links"] = links
    return digest_of(payload)


def standing_on(chain: dict, from_digest: dict) -> list:
    """Go `(SourceChain) StandingOn(from Digest) ([]SourceRef, error)`.

    The walk follows the "artifact names authority" direction, so it returns
    the artifact first and ends at a source that names nothing.  A source that
    names more than one other source in the chain has no single path.
    """
    validate_source_chain(chain)
    by_digest = {digest_key(s["digest"]): s for s in chain.get("sources") or []}
    named: dict = {}
    for l in chain.get("links") or []:
        named.setdefault(digest_key(l.get("from", {})), []).append(
            by_digest[digest_key(l.get("to", {}))])

    key = digest_key(from_digest)
    if key not in by_digest:
        raise CLCError("source_dangling_link: %s" % key)
    current = by_digest[key]
    path: list = []
    seen = set()
    while True:
        key = digest_key(current["digest"])
        if key in seen:
            raise CLCError("source_chain_cycle: %s" % current.get("id"))
        seen.add(key)
        path.append(current)
        nxt = named.get(key, [])
        if len(nxt) == 0:
            return path
        if len(nxt) == 1:
            current = nxt[0]
            continue
        raise CLCError("source_chain_branch: %s names %d sources" % (current.get("id"), len(nxt)))


# --- register/semantics/record.go (record construction) ----------------------

class RecordOperationCount(CLCError):
    pass


class RecordInputDigestMismatch(CLCError):
    pass


class RecordVerdictMismatch(CLCError):
    pass


class RecordRevision(CLCError):
    pass


def _grant_wire(g: dict) -> dict:
    """Go's `Grant` JSON: only the declared members exist, and the optional ones
    carry `,omitempty`, so a null or empty `params` is not written at all.  The
    record hashes the bytes a Go holder would have written."""
    out = {"id": g.get("id", "")}
    if g.get("params"):
        out["params"] = g["params"]
    if g.get("param_bounds"):
        out["param_bounds"] = g["param_bounds"]
    if g.get("constraints"):
        out["constraints"] = list(g["constraints"])
    return out


def _operation_wire(op: dict) -> dict:
    out = {"id": op.get("id", "")}
    if op.get("params"):
        out["params"] = op["params"]
    return out


def _context_wire(ctx: dict) -> dict:
    """Go's `DecisionContext` JSON.  `At` is a `time.Time` struct, which
    encoding/json never omits, so a context without a pinned instant still
    carries year 1's zero time."""
    out = {"at": ctx.get("at") or ZERO_TIME_INSTANT}
    if ctx.get("max_age_sec"):
        out["max_age_sec"] = ctx["max_age_sec"]
    if ctx.get("nonce"):
        out["nonce"] = ctx["nonce"]
    if ctx.get("epoch_id") is not None:
        out["epoch_id"] = ctx["epoch_id"]
    if ctx.get("snapshot_digest") is not None:
        out["snapshot_digest"] = ctx["snapshot_digest"]
    return out


def _digest_wire(d: Any) -> dict:
    d = d or {}
    return {"alg": d.get("alg", ""), "value": d.get("value")}


def _ref_wire(r: dict) -> dict:
    out = {"kind": r.get("kind", ""), "id": r.get("id", "")}
    if r.get("issuer"):
        out["issuer"] = r["issuer"]
    out["digest"] = _digest_wire(r.get("digest"))
    if r.get("references"):
        out["references"] = [_digest_wire(x) for x in r["references"]]
    return out


def _sources_wire(ch: dict) -> dict:
    out = {"sources": [_ref_wire(r) for r in ch.get("sources") or []]}
    if ch.get("links"):
        out["links"] = [{"from": _digest_wire(l.get("from")),
                         "to": _digest_wire(l.get("to"))}
                        for l in ch["links"]]
    return out


def record_inputs(grants: list, op: dict, context: Optional[dict] = None,
                  sources: Optional[dict] = None,
                  requirement_digest: Optional[dict] = None) -> dict:
    """Go `RecordInputs` — the frozen input of a decision.  The field names are
    the record's public schema, not an internal detail."""
    out = {"grants": [_grant_wire(g) for g in grants],
           "operations": [_operation_wire(op)]}
    if context is not None:
        out["context"] = _context_wire(context)
    if sources is not None:
        out["sources"] = _sources_wire(sources)
    if requirement_digest is not None:
        out["requirement_digest"] = requirement_digest
    return out


def _record(grants: list, op: dict, context: Optional[dict] = None,
            sources: Optional[dict] = None,
            requirement: Optional[dict] = None) -> dict:
    """Go `record(grants, op, opts, requirementDigest) (DecisionRecord, error)`.

    The verdict/reason/unresolved are copied from AuthorizeSet unchanged, never
    recomputed or reworded here.
    """
    if not grants:
        # Normalize before encoding: a nil slice would encode as null and then
        # hash differently from the empty list it decodes back to.
        grants = []
    req_digest = None
    if requirement is not None:
        req_digest = requirement_digest(requirement)
    inputs = record_inputs(grants, op, context, sources, req_digest)
    canonical = canonical_json(inputs)
    frozen = json.loads(canonical)
    frozen.setdefault("grants", [])
    if frozen["grants"] is None:
        frozen["grants"] = []

    rec = {
        "ver": CLC_REVISION,
        "lang": RECORD_LANG,
        "inputs": frozen,
        "input_digest": digest_of_canonical(canonical),
    }
    decision = authorize_set(frozen["grants"], frozen["operations"][0])
    rec["verdict"] = decision.get("verdict")
    if decision.get("reason"):
        rec["reason"] = decision.get("reason")
    unresolved = list(decision.get("unresolved") or [])
    # `RecordConstraints.Unresolved` is `,omitempty`: an empty residual channel
    # writes as `{}` and never as `{"unresolved": []}`.
    rec["constraints"] = {"unresolved": unresolved} if unresolved else {}
    return rec


def record_with(grants: list, op: dict, context: Optional[dict] = None,
                sources: Optional[dict] = None,
                requirement: Optional[dict] = None) -> dict:
    """Go `RecordWith(grants, op, opts) (DecisionRecord, error)`.

    Both the freshness context and the authorization source chain are validated
    before anything is written: a chain whose claimed relations its own bytes do
    not back is refused, not recorded.
    """
    if context is not None:
        validate_decision_context(context)
    if sources is not None:
        validate_source_chain(sources)
    return _record(grants, op, context, sources, requirement)


def record(grants: list, op: dict) -> dict:
    """Go `Record(grants, op) (DecisionRecord, error)`."""
    return record_with(grants, op)


def record_with_context(grants: list, op: dict, ctx: dict) -> dict:
    """Go `RecordWithContext(grants, op, ctx) (DecisionRecord, error)`."""
    return record_with(grants, op, context=ctx)


def record_canonical_bytes(rec: dict) -> str:
    """Go `(DecisionRecord) CanonicalBytes() ([]byte, error)` — the stable
    handle a later step signs, or compares between implementations."""
    return canonical_json(rec)


def record_recompute(rec: dict) -> dict:
    """Go `(DecisionRecord) Recompute() (Decision, error)` — re-runs the
    language over the record's frozen inputs.  It needs nothing outside the
    record."""
    operations = rec.get("inputs", {}).get("operations") or []
    if len(operations) != 1:
        raise RecordOperationCount("record_operation_count: %d operations" % len(operations))
    if not revision_compatible(rec.get("ver")):
        raise RecordRevision("record_unsupported_revision: %s" % rec.get("ver"))
    return authorize_set(rec["inputs"].get("grants") or [], operations[0])


def record_verify(rec: dict) -> None:
    """Go `(DecisionRecord) Verify() error` — the digest must match the frozen
    inputs, and re-running the language must reproduce the verdict, reason and
    residual obligations byte for byte."""
    recomputed = record_recompute(rec)
    want = digest_of(rec["inputs"])
    recorded = rec.get("input_digest") or {}
    if not digest_equal(want, recorded):
        raise RecordInputDigestMismatch(
            "record_input_digest_mismatch: recorded %s/%s, recomputed %s/%s" % (
                recorded.get("alg", ""), _digest_hex(recorded.get("value", "")),
                want.get("alg"), _digest_hex(want.get("value"))))
    if recomputed.get("verdict") != rec.get("verdict") or recomputed.get("reason", "") != rec.get("reason", ""):
        raise RecordVerdictMismatch(
            "record_verdict_mismatch: recorded %s/%s, recomputed %s/%s" % (
                _q(rec.get("verdict")), _q(rec.get("reason", "")),
                _q(recomputed.get("verdict")), _q(recomputed.get("reason", ""))))
    got = list(rec.get("constraints", {}).get("unresolved") or [])
    want_unresolved = list(recomputed.get("unresolved") or [])
    if len(got) != len(want_unresolved) or any(a != b for a, b in zip(got, want_unresolved)):
        raise RecordVerdictMismatch(
            "record_verdict_mismatch: recorded unresolved %s, recomputed %s"
            % (_go_str_list(got), _go_str_list(want_unresolved)))
    return None


def record_verify_as_of(rec: dict, now: str) -> None:
    """Go `(DecisionRecord) VerifyAsOf(now) error` — additionally requires the
    decision context to still be fresh at `now` (RATS §10)."""
    record_verify(rec)
    ctx = rec.get("inputs", {}).get("context")
    if ctx is None:
        raise CLCError("context_missing")
    return fresh_context(ctx, now)


# --- register/semantics/requirement.go ---------------------------------------

class RequirementShape(CLCError):
    pass


class RequirementVersion(CLCError):
    pass


class RequirementExpression(CLCError):
    pass


REQUIREMENT_VERSION = "CLC-REQUIREMENT-v1"

MAX_REQUIREMENT_EXPRESSION_BYTES = 512
MAX_REQUIREMENT_NODES = 64
MAX_REQUIREMENT_DEPTH = 8

# Reason codes that are not already carried by a constraint evaluation.
SATISFACTION_REASON_EXPRESSION_FALSE = "requirement:expression_false"
SATISFACTION_REASON_UNSATISFIED = "requirement:unsatisfied"

SATISFACTION_SATISFIED = "SATISFIED"
SATISFACTION_UNSATISFIED = "UNSATISFIED"

_REQUIREMENT_KNOWN_MEMBERS = {"@version", "requirement_id", "purpose", "expression", "constraints"}


def _is_ident_byte(c: int) -> bool:
    """Go `isIdentByte` — letters, digits and the separators . : - _."""
    if 0x61 <= c <= 0x7A or 0x41 <= c <= 0x5A or 0x30 <= c <= 0x39:
        return True
    return c in (0x2E, 0x3A, 0x2D, 0x5F)


def _tokenize_requirement(src: str) -> list:
    """Go `tokenizeRequirement`."""
    tokens: list = []
    data = src.encode("utf-8")
    i = 0
    n = len(data)
    while i < n:
        c = data[i]
        if c in (0x20, 0x09, 0x0A, 0x0D):
            i += 1
        elif c in (0x28, 0x29):  # ( )
            tokens.append(chr(c))
            i += 1
        elif c in (0x26, 0x7C):  # & |
            # The grammar's symbolic operators are doubled; a single one is
            # not a token.
            if i + 1 >= n or data[i + 1] != c:
                raise RequirementExpression("requirement_expression: stray %s" % _q(chr(c)))
            tokens.append(chr(c) * 2)
            i += 2
        elif _is_ident_byte(c):
            start = i
            while i < n and _is_ident_byte(data[i]):
                i += 1
            tokens.append(data[start:i].decode("utf-8"))
        else:
            raise RequirementExpression("requirement_expression: unexpected character %s" % _q(chr(c)))
    if len(tokens) == 0:
        raise RequirementExpression("requirement_expression: empty expression")
    return tokens


def _requirement_operator(tok: str) -> Optional[str]:
    if tok in ("AND", "&&"):
        return "AND"
    if tok in ("OR", "||"):
        return "OR"
    return None


class _RequirementParser:
    """Go `requirementParser` — a bounded, left-to-right parser (AEC §8)."""

    def __init__(self, tokens: list):
        self.tokens = tokens
        self.pos = 0
        self.nodes = 0

    def parse_expr(self, depth: int) -> dict:
        if depth > MAX_REQUIREMENT_DEPTH:
            raise RequirementShape("requirement_shape: nesting deeper than %d" % MAX_REQUIREMENT_DEPTH)
        left = self.parse_term(depth)
        while self.pos < len(self.tokens):
            op = _requirement_operator(self.tokens[self.pos])
            if op is None:
                break
            self.pos += 1
            right = self.parse_term(depth)
            self.nodes += 1
            if self.nodes > MAX_REQUIREMENT_NODES:
                raise RequirementShape("requirement_shape: more than %d terms" % MAX_REQUIREMENT_NODES)
            left = {"op": op, "left": left, "right": right}
        return left

    def parse_term(self, depth: int) -> dict:
        if self.pos >= len(self.tokens):
            raise RequirementExpression("requirement_expression: unexpected end of expression")
        tok = self.tokens[self.pos]
        if tok == "(":
            self.pos += 1
            inner = self.parse_expr(depth + 1)
            if self.pos >= len(self.tokens) or self.tokens[self.pos] != ")":
                raise RequirementExpression("requirement_expression: missing )")
            self.pos += 1
            return inner
        if tok == ")" or _requirement_operator(tok) is not None:
            raise RequirementExpression('requirement_expression: expected a term, got "%s"' % tok)
        self.pos += 1
        return {"ident": tok}


def _parse_requirement_expression(src: str) -> dict:
    """Go `parseRequirementExpression(in) (*requirementExpr, error)`."""
    if not src.strip():
        raise RequirementExpression("requirement_expression: empty expression")
    parser = _RequirementParser(_tokenize_requirement(src))
    expr = parser.parse_expr(0)
    if parser.pos != len(parser.tokens):
        raise RequirementExpression('requirement_expression: unexpected "%s"' % parser.tokens[parser.pos])
    return expr


def _expr_eval(node: dict, present) -> bool:
    """Go `(requirementExpr) eval(present)` — left-to-right, equal binding."""
    if "op" not in node:
        return present(node["ident"])
    if node["op"] == "AND":
        return _expr_eval(node["left"], present) and _expr_eval(node["right"], present)
    return _expr_eval(node["left"], present) or _expr_eval(node["right"], present)


def _expr_roles(node: dict, acc: set) -> None:
    if "op" not in node:
        acc.add(node["ident"])
        return
    _expr_roles(node["left"], acc)
    _expr_roles(node["right"], acc)


def validate_requirement(req: dict) -> None:
    """Go `(Requirement) Validate() error` — the version, the identifiers, every
    constraint's value grammar, and that the expression parses within the
    bounded grammar."""
    if req.get("@version") != REQUIREMENT_VERSION:
        raise RequirementVersion('requirement_version: %s' % _q(req.get("@version")))
    if not req.get("requirement_id"):
        raise RequirementShape("requirement_shape: requirement_id required")
    expression = req.get("expression") or ""
    if len(expression.encode("utf-8")) > MAX_REQUIREMENT_EXPRESSION_BYTES:
        raise RequirementShape("requirement_shape: expression longer than %d bytes" % MAX_REQUIREMENT_EXPRESSION_BYTES)
    _parse_requirement_expression(expression)
    seen = set()
    for c in req.get("constraints") or []:
        if not c.get("role"):
            raise RequirementShape("requirement_shape: constraint without a role")
        validate_evidence_constraint(c.get("constraint", ""))
        key = c["role"] + "\x00" + c["constraint"]
        if key in seen:
            raise RequirementShape('requirement_shape: duplicate constraint for role "%s"' % c["role"])
        seen.add(key)
    return None


def requirement_digest(req: dict) -> dict:
    """Go `(Requirement) Digest() (Digest, error)` — the requirement profile
    digest: the JCS digest of the complete object."""
    validate_requirement(req)
    return digest_of(req)


def requirement_roles(req: dict) -> list:
    """Go `(Requirement) Roles() ([]string, error)` — the sorted distinct role
    identifiers the expression names."""
    expr = _parse_requirement_expression(req.get("expression") or "")
    acc: set = set()
    _expr_roles(expr, acc)
    return sorted(acc)


def parse_requirement(raw: Any) -> dict:
    """Go `ParseRequirement(raw []byte) (Requirement, error)`.

    Decodes a requirement as a closed object: a member this revision does not
    define is an error, never silently dropped."""
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        obj = json.loads(raw)
    else:
        obj = raw
    if not isinstance(obj, dict):
        raise RequirementShape("requirement_shape: not an object")
    unknown = set(obj) - _REQUIREMENT_KNOWN_MEMBERS
    if unknown:
        # Go's decoder reports the first unknown member it reaches, spelled the
        # way encoding/json spells it: `json: unknown field "extra"`.
        raise RequirementShape('requirement_shape: json: unknown field %s'
                               % _q(sorted(unknown)[0]))
    validate_requirement(obj)
    return obj


def evaluate_requirement(req: dict, facts: list, ctx: Optional[dict] = None) -> dict:
    """Go `EvaluateRequirement(req, facts, ctx) (RequirementResult, error)`.

    Decides whether the presented facts fill the relying party's bar.  The
    requirement must come from relying-party configuration: this function takes
    it as an argument and never reads it from the evidence.

    Precedence is violated > unknown > satisfied, so no failure degrades toward
    admission.
    """
    ctx = ctx or {}
    validate_requirement(req)
    out = {"requirement_id": req.get("requirement_id"), "digest": requirement_digest(req)}

    expr = _parse_requirement_expression(req.get("expression") or "")

    def present(role: str) -> bool:
        return any(f.get("verified") for f in evidence_facts_of_role(facts, role))

    out["expression"] = _expr_eval(expr, present)
    if not out["expression"]:
        out["missing_roles"] = [r for r in requirement_roles(req) if not present(r)]

    unknown = False
    violated = False
    evaluations: list = []
    for c in req.get("constraints") or []:
        evaluation = evaluate_evidence_constraint(
            c["constraint"], evidence_facts_of_role(facts, c["role"]), ctx)
        evaluations.append(evaluation)
        if evaluation["verdict"] == EVIDENCE_VIOLATED:
            violated = True
        elif evaluation["verdict"] == EVIDENCE_UNKNOWN:
            unknown = True
    if evaluations:
        out["constraints"] = evaluations

    if violated or not out["expression"]:
        out["verdict"] = EVIDENCE_VIOLATED
    elif unknown:
        out["verdict"] = EVIDENCE_UNKNOWN
    else:
        out["verdict"] = EVIDENCE_SATISFIED
    return out


def requirement_satisfied(result: dict) -> bool:
    """Go `(RequirementResult) Satisfied() bool` — only an explicit satisfied
    verdict counts, so "unknown" can never be read as "yes"."""
    return result.get("verdict") == EVIDENCE_SATISFIED


def requirement_satisfaction(result: dict) -> dict:
    """Go `(RequirementResult) Satisfaction() Satisfaction` — §10's binary
    report form."""
    if result.get("verdict") == EVIDENCE_SATISFIED:
        return {"verdict": SATISFACTION_SATISFIED}
    if not result.get("expression"):
        return {"verdict": SATISFACTION_UNSATISFIED, "reason": SATISFACTION_REASON_EXPRESSION_FALSE}
    for c in result.get("constraints") or []:
        if c.get("verdict") in (EVIDENCE_VIOLATED, EVIDENCE_UNKNOWN):
            return {"verdict": SATISFACTION_UNSATISFIED, "reason": c.get("reason", "")}
    return {"verdict": SATISFACTION_UNSATISFIED, "reason": SATISFACTION_REASON_UNSATISFIED}


# --- register/semantics/challenge.go -----------------------------------------

class ChallengeShape(CLCError):
    pass


class ChallengeExpired(CLCError):
    pass


class ChallengeNotOutstanding(CLCError):
    pass


class ChallengeRetryNotBefore(CLCError):
    pass


CHALLENGE_VERSION = "CLC-CHALLENGE-v1"

MIN_CHALLENGE_NONCE_BYTES = 8
MAX_CHALLENGE_NONCE_BYTES = 128
MAX_CHALLENGE_JITTER_SEC = 300


def _require_utc(s: Any, what: str) -> Any:
    """A UTC instant, as Go requires: `Location() != time.UTC` is refused, and a
    fixed offset — even `+00:00` — is not `time.UTC`."""
    t = _parse_rfc3339(s)
    if t is None or not _is_utc_instant(s):
        raise ChallengeShape("challenge_shape: %s must be a UTC instant" % what)
    return t


def _require_expires(c: dict) -> Any:
    """Go checks `ExpiresAt` in two steps: zero is `expires_at required`, and a
    non-UTC instant is `expires_at must be UTC`."""
    raw = c.get("expires_at")
    if raw is None or raw == "":
        raise ChallengeShape("challenge_shape: expires_at required")
    t = _parse_rfc3339(raw)
    if t is None or not _is_utc_instant(raw):
        raise ChallengeShape("challenge_shape: expires_at must be UTC")
    return t


def _iso_utc(t) -> str:
    """Go writes `time.Time` with RFC3339Nano: whole seconds have no fraction,
    and a fractional part keeps its digits with trailing zeros trimmed."""
    t = t.astimezone(datetime.timezone.utc)
    if not t.microsecond:
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0") + "Z"


def challenge_authorizes(challenge: dict) -> bool:
    """Go `(Challenge) Authorizes() bool` — always False; the method exists so
    that call sites cannot read a challenge as a verdict by accident."""
    return False


def validate_challenge(c: dict) -> None:
    """Go `(Challenge) Validate() error` — shape and bindings."""
    if c.get("@version") != CHALLENGE_VERSION:
        raise ChallengeShape('challenge_shape: version %s' % _q(c.get("@version")))
    if not c.get("challenge_id"):
        raise ChallengeShape("challenge_shape: challenge_id required")
    n = len((c.get("nonce") or "").encode("utf-8"))
    if n < MIN_CHALLENGE_NONCE_BYTES or n > MAX_CHALLENGE_NONCE_BYTES:
        raise ChallengeShape("challenge_shape: nonce must be %d..%d bytes" % (
            MIN_CHALLENGE_NONCE_BYTES, MAX_CHALLENGE_NONCE_BYTES))
    if not digest_usable(c.get("action_digest")):
        raise ChallengeShape("challenge_shape: action_digest required")
    if c.get("requirement_digest") is not None and not digest_usable(c["requirement_digest"]):
        raise ChallengeShape("challenge_shape: unusable requirement_digest")
    if not c.get("required"):
        raise ChallengeShape("challenge_shape: nothing required")
    for item in c["required"]:
        if not item.get("id"):
            raise ChallengeShape("challenge_shape: required item without an id")
    expires = _require_expires(c)
    retry = c.get("retry_timing")
    if retry is not None:
        not_before = _require_utc(retry.get("not_before"), "retry_timing.not_before")
        jitter = retry.get("jitter_sec", 0)
        if jitter < 0 or jitter > MAX_CHALLENGE_JITTER_SEC:
            raise ChallengeShape("challenge_shape: jitter_sec out of range")
        if not_before > expires:
            raise ChallengeShape("challenge_shape: retry_timing.not_before is after expiry")
    return None


def challenge_usable(c: dict, now: str) -> None:
    """Go `(Challenge) Usable(now time.Time) error` — an expired challenge is
    dead: retrying against it is the load amplification the specification
    warns about."""
    validate_challenge(c)
    when = _require_utc(now, "now")
    expires = _require_expires(c)
    if not when < expires:
        raise ChallengeExpired("challenge_expired: expired at %s" % c.get("expires_at"))
    retry = c.get("retry_timing")
    if retry is not None and when < _require_utc(retry.get("not_before"), "retry_timing.not_before"):
        raise ChallengeRetryNotBefore(
            'challenge_retry_not_before: opens at %s' % retry.get("not_before"))
    return None


def challenge_digest(c: dict) -> dict:
    """Go `(Challenge) Digest() (Digest, error)` — binds the challenge so a
    caller can identify exactly which challenge it answered."""
    validate_challenge(c)
    return digest_of(c)


def _sorted_challenge_items(items: list) -> list:
    return sorted(items, key=lambda i: (i.get("id", ""), i.get("constraint", ""), i.get("reason", "")))


def _build_challenge(version_items: list, params: dict) -> dict:
    c = {
        "@version": CHALLENGE_VERSION,
        "challenge_id": params.get("id", ""),
        "nonce": params.get("nonce", ""),
        "required": _sorted_challenge_items(version_items),
        "expires_at": _iso_utc(_require_utc(params.get("now"), "now")
                               + datetime.timedelta(seconds=int(params.get("ttl_sec") or 0))),
    }
    if params.get("audience"):
        c["audience"] = params["audience"]
    if params.get("action_digest"):
        c["action_digest"] = params["action_digest"]
    if params.get("obtain_hints"):
        c["obtain_hints"] = params["obtain_hints"]
    if params.get("retry_timing"):
        c["retry_timing"] = params["retry_timing"]
    validate_challenge(c)
    return c


def build_challenge_from_requirement(req: dict, result: dict, params: dict) -> dict:
    """Go `BuildChallengeFromRequirement(req, result, params) (Challenge, error)`.

    A satisfied result needs no challenge, and a hard denial with nothing
    missing is reported as such rather than dressed up as a retryable request.
    """
    validate_requirement(req)
    if result.get("verdict") == EVIDENCE_SATISFIED:
        raise ChallengeNotOutstanding("challenge_not_outstanding: requirement %s is satisfied" % req.get("requirement_id"))

    required: list = []
    for role in result.get("missing_roles") or []:
        required.append({"id": role, "reason": "role_unfilled"})
    for evaluation in result.get("constraints") or []:
        if evaluation.get("verdict") == EVIDENCE_SATISFIED:
            continue
        required.append({
            "id": evaluation.get("constraint"),
            "constraint": evaluation.get("constraint"),
            "reason": evaluation.get("reason", ""),
        })
    if len(required) == 0:
        raise ChallengeNotOutstanding(
            "challenge_not_outstanding: requirement %s reported no outstanding item" % req.get("requirement_id"))

    params = dict(params)
    params.setdefault("requirement_id", req.get("requirement_id"))
    c = _build_challenge(required, params)
    c["requirement_id"] = req.get("requirement_id")
    c["requirement_digest"] = requirement_digest(req)
    validate_challenge(c)
    return c


def build_challenge_from_decision(d: dict, params: dict) -> dict:
    """Go `BuildChallengeFromDecision(d, params) (Challenge, error)` — for an
    authorization decision carrying §8.4 residual obligations."""
    check_decision_shape(d)
    if d.get("verdict") != VERDICT_ALLOW_UNRESOLVED:
        raise ChallengeNotOutstanding(
            "challenge_not_outstanding: verdict %s carries no residual obligation" % d.get("verdict"))
    items = [{"id": constraint_identity(o), "constraint": o, "reason": "obligation_undischarged"}
             for o in obligations(d)]
    return _build_challenge(items, params)


# --- register/semantics/envelope.go ------------------------------------------

class EnvelopeShape(CLCError):
    pass


class EnvelopePayloadType(CLCError):
    pass


class EnvelopeSubjectMismatch(CLCError):
    pass


class EnvelopeSignature(CLCError):
    pass


PAYLOAD_TYPE_IN_TOTO = "application/vnd.in-toto+json"
STATEMENT_TYPE_IN_TOTO = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE_CLC_DECISION = "https://varwof.com/clc/v1/decision-record"

# subjectNameAction / subjectNameInputs — the two subject entries the profile
# pins, so an envelope whose statement does not carry the decision's own
# action/input digests is re-targetable and is refused.
SUBJECT_NAME_ACTION = "action"
SUBJECT_NAME_INPUTS = "clc-inputs"

_IN_TOTO_ALGS = {DIGEST_ALG_SHA256: "sha256", "sha-384": "sha384", "sha-512": "sha512"}


def pae(payload_type: str, payload: Any) -> bytes:
    """Go `PAE(payloadType, payload) []byte` — the DSSE v1 pre-authentication
    encoding:

        PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body

    DSSE signs these bytes, not the payload alone, so a payload cannot be
    reinterpreted under a different type."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    out = b"DSSEv1"
    for part in (payload_type.encode("utf-8"), payload):
        out += b" " + str(len(part)).encode("ascii") + b" " + part
    return out


def new_statement(rec: dict) -> dict:
    """Go `NewStatement(rec) (Statement, error)` — the in-toto statement for a
    decision record.  The subjects are the action and the decision's own input
    digest, so both are covered by any signature over the statement."""
    operations = rec.get("inputs", {}).get("operations") or []
    if len(operations) != 1:
        raise EnvelopeShape("envelope_shape: %d operations" % len(operations))
    if not rec.get("input_digest", {}).get("alg") or not rec.get("input_digest", {}).get("value"):
        raise EnvelopeShape("envelope_shape: record carries no input digest")
    alg = _IN_TOTO_ALGS.get(rec["input_digest"]["alg"])
    if alg is None:
        raise EnvelopeShape('envelope_shape: unsupported digest algorithm "%s"' % rec["input_digest"]["alg"])
    action_bytes = canonical_json(operations).encode("utf-8")
    action_digest = hashlib.sha256(action_bytes).hexdigest()
    return {
        "_type": STATEMENT_TYPE_IN_TOTO,
        "subject": [
            {"name": SUBJECT_NAME_ACTION, "digest": {alg: action_digest}},
            {"name": SUBJECT_NAME_INPUTS,
             "digest": {alg: base64.b64decode(rec["input_digest"]["value"]).hex()}},
        ],
        "predicateType": PREDICATE_TYPE_CLC_DECISION,
        "predicate": rec,
    }


def new_envelope(rec: dict) -> dict:
    """Go `NewEnvelope(rec) (Envelope, error)` — wraps a decision record in an
    unsigned DSSE envelope.

    `payload` and every signature hold the *decoded* text of Go's in-memory
    `[]byte`, not the bytes encoding/json would put on the wire.  Go writes them
    as base64; this port writes the same bytes as inline JSON strings, so a
    port-produced envelope is not byte-identical to a Go-produced one.  The
    signature covers PAE(payloadType, payload) — the raw bytes — which is
    identical either way, so verification is unaffected."""
    st = new_statement(rec)
    return {
        "payload": canonical_json(st),
        "payloadType": PAYLOAD_TYPE_IN_TOTO,
        "signatures": [],
    }


def envelope_statement(e: dict) -> dict:
    """Go `(Envelope) Statement() (Statement, error)`."""
    if e.get("payloadType") != PAYLOAD_TYPE_IN_TOTO:
        raise EnvelopePayloadType('envelope_payload_type: %s' % _q(e.get("payloadType")))
    if not e.get("payload"):
        raise EnvelopeShape("envelope_shape: empty payload")
    payload = e["payload"]
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8")
    try:
        return json.loads(payload)
    except ValueError as exc:
        raise EnvelopeShape("envelope_shape: %s" % exc)


def envelope_decision_record(e: dict) -> dict:
    """Go `(Envelope) DecisionRecord() (DecisionRecord, error)` — the record
    carried as the predicate."""
    return envelope_statement(e)["predicate"]


def envelope_sign(e: dict, key_id: str, sign) -> None:
    """Go `(Envelope) Sign(keyID, sign) error` — appends a signature over
    PAE(payloadType, payload).  The signing primitive is supplied by the
    caller: DSSE deliberately leaves the signature format to the out-of-band
    agreement."""
    if sign is None:
        raise EnvelopeShape("envelope_shape: nil signer")
    sig = sign(pae(e["payloadType"], e["payload"]))
    e.setdefault("signatures", []).append({"keyid": key_id, "sig": sig})
    return None


def _match_subject(got: list, want: dict) -> None:
    for s in got:
        if s.get("name") != want.get("name"):
            continue
        for alg, value in (want.get("digest") or {}).items():
            if (s.get("digest") or {}).get(alg) != value:
                raise EnvelopeSubjectMismatch(
                    'envelope_subject_mismatch: subject "%s" digest mismatch' % want.get("name"))
            return None
    raise EnvelopeSubjectMismatch('envelope_subject_mismatch: subject "%s" missing' % want.get("name"))


def envelope_check(e: dict) -> None:
    """Go `(Envelope) Check() error` — internal consistency without any
    signature: payload type, statement shape, subject binding to the decision,
    and the record's own digest/recomputation."""
    st = envelope_statement(e)
    if st.get("_type") != STATEMENT_TYPE_IN_TOTO:
        raise EnvelopeShape('envelope_shape: statement type %s' % _q(st.get("_type")))
    if st.get("predicateType") != PREDICATE_TYPE_CLC_DECISION:
        raise EnvelopeShape('envelope_shape: predicate type %s' % _q(st.get("predicateType")))
    record_verify(st["predicate"])
    want = new_statement(st["predicate"])
    for w in want["subject"]:
        _match_subject(st.get("subject") or [], w)
    return None


def envelope_verify_record(e: dict, verify) -> None:
    """Go `(Envelope) VerifyRecord(verify) error` — checks the envelope and then
    requires at least one signature to verify.  `verify` is the caller's
    signature primitive; it receives the KEYID hint (which MUST NOT be trusted
    on its own) and the PAE bytes."""
    envelope_check(e)
    signatures = e.get("signatures") or []
    if len(signatures) == 0:
        raise EnvelopeSignature("envelope_signature: no signatures")
    if verify is None:
        raise EnvelopeSignature("envelope_signature: nil verifier")
    pae_bytes = pae(e["payloadType"], e["payload"])
    first_error = None
    for sig in signatures:
        if not sig.get("sig"):
            if first_error is None:
                first_error = EnvelopeSignature("envelope_signature: empty signature")
            continue
        try:
            verify(sig.get("keyid"), pae_bytes, sig["sig"])
            return None
        except Exception as exc:  # noqa: BLE001 - any verifier failure is a refusal
            if first_error is None:
                first_error = EnvelopeSignature("envelope_signature: %s" % exc)
    if first_error is not None:
        raise first_error
    return None


# --- register/semantics/match.go ---------------------------------------------

class ActionShape(CLCError):
    pass


class ActionSuite(CLCError):
    pass


class ActionNotMatchable(CLCError):
    pass


class ActionProjectionLossy(CLCError):
    pass


SUITE_JCS_SHA256 = "jcs-sha256"
ACTION_ID_PREFIX = "clc-action:1"

MATCH_EXACT = "MATCH"
MATCH_NOT_EQUIVALENT = "NOT_EQUIVALENT"
MATCH_INDETERMINATE = "INDETERMINATE"

_SHA256_SIZE = 32


def action_type_definition(type_: str, material_fields: list) -> dict:
    """Go `ActionTypeDefinition` — the declared material field set of one action
    type.  Required and optional-but-included fields are both listed here."""
    return {"type": type_, "material_fields": list(material_fields or [])}


def validate_action_type_definition(d: dict) -> None:
    """Go `(ActionTypeDefinition) Validate() error`."""
    if not d.get("type"):
        raise ActionShape("action_shape: action type required")
    fields = d.get("material_fields") or []
    if len(fields) == 0:
        raise ActionShape("action_shape: action type %s declares no material fields" % d.get("type"))
    seen = set()
    for f in fields:
        if not f:
            raise ActionShape("action_shape: empty material field name")
        if f in seen:
            raise ActionShape('action_shape: duplicate material field "%s"' % f)
        seen.add(f)
    return None


def action_id(type_: str, suite: str, digest_: dict) -> dict:
    """Go `ActionId` — a typed, suite-tagged content identity for the material
    content of one action."""
    return {"type": type_, "suite": suite, "digest": digest_}


def _suite_valid(suite: str) -> bool:
    return suite == SUITE_JCS_SHA256


def _digest_alg_of(suite: str) -> str:
    return DIGEST_ALG_SHA256 if suite == SUITE_JCS_SHA256 else ""


def validate_action_id(a: dict) -> None:
    """Go `(ActionId) Validate() error` — the identifier's own shape."""
    if not a.get("type"):
        raise ActionShape("action_shape: action type required")
    if not _suite_valid(a.get("suite")):
        raise ActionSuite('action_suite: %s' % _q(a.get("suite")))
    d = a.get("digest") or {}
    if not d.get("alg") or not d.get("value"):
        raise ActionShape("action_shape: action digest required")
    # The digest length is suite-pinned: for jcs-sha256 the value must be
    # exactly 32 bytes.
    raw = base64.urlsafe_b64decode(_b64url_pad(d["value"]))
    if a.get("suite") == SUITE_JCS_SHA256 and len(raw) != _SHA256_SIZE:
        raise ActionShape("action_shape: %s digest must be %d bytes, got %d" % (
            a.get("suite"), _SHA256_SIZE, len(raw)))
    return None


_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")


def _b64url_strict(s: str) -> bool:
    """Go's `base64.RawURLEncoding.DecodeString`: alphabet only, no padding
    character, and a length that could not be produced by encoding bytes.
    Python's `b64decode` discards characters outside the alphabet instead of
    failing, so `!!` would decode to empty bytes rather than be refused."""
    if not _B64URL_RE.fullmatch(s or ""):
        return False
    return len(s or "") % 4 != 1


def _b64url_pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def action_id_string(a: dict) -> str:
    """Go `(ActionId) String() string` —
    clc-action:1:<type>:<suite>:<digest-b64url>."""
    return "%s:%s:%s:%s" % (ACTION_ID_PREFIX, a.get("type"), a.get("suite"),
                            a.get("digest", {}).get("value", ""))


def parse_action_id(s: str) -> dict:
    """Go `ParseActionId(s) (ActionId, error)` — parses the string form."""
    parts = s.split(":")
    if len(parts) != 5 or parts[0] != "clc-action" or parts[1] != "1":
        raise ActionShape('action_shape: %s' % _q(s))
    if not _b64url_strict(parts[4]):
        raise ActionShape("action_shape: digest is not base64url: %s" % _q(s))
    ident = action_id(parts[2], parts[3],
                      {"alg": _digest_alg_of(parts[3]), "value": parts[4]})
    validate_action_id(ident)
    return ident


def material_projection(d: dict, action: dict) -> dict:
    """Go `MaterialProjection(def, action) (map[string]any, error)` — the map
    ComputeActionID hashes, so a caller can disclose exactly what entered the
    identity."""
    validate_action_type_definition(d)
    out: dict = {}
    for field in d["material_fields"]:
        if field not in action:
            raise ActionNotMatchable(
                'action_not_matchable: material field "%s" absent for %s' % (field, d["type"]))
        out[field] = action[field]
    return out


def material_field_digest(d: dict, action: dict) -> list:
    """Go `MaterialFieldDigest(def, action) ([]string, error)` — the per-field
    digests of the material projection in a deterministic order."""
    projection = material_projection(d, action)
    out = []
    for field in sorted(projection):
        canonical = canonical_json(projection[field]).encode("utf-8")
        out.append("%s:%s" % (field, hashlib.sha256(canonical).hexdigest()))
    return out


def match(observed: dict, evidence: dict) -> str:
    """Go `Match(observed, evidence) MatchVerdict` — compares a natively
    verified evidence identity with the executor's observed identity.  It never
    guesses: anything it cannot decide is INDETERMINATE."""
    try:
        validate_action_id(observed)
        validate_action_id(evidence)
    except CLCError:
        return MATCH_INDETERMINATE
    if observed.get("type") != evidence.get("type") or observed.get("suite") != evidence.get("suite"):
        # Cross-type or cross-suite comparison is a mapping problem, not an
        # inequality.
        return MATCH_INDETERMINATE
    if digest_equal(observed.get("digest", {}), evidence.get("digest", {})):
        return MATCH_EXACT
    return MATCH_NOT_EQUIVALENT


def action_mapping_profile(id_: str, digest_: dict) -> dict:
    """Go `ActionMappingProfile` — names a projection by its content hash and is
    pinned by the relying party."""
    return {"id": id_, "digest": digest_}


def mapping_profile_pinned(profile: Optional[dict]) -> bool:
    """Go `(ActionMappingProfile) Pinned() bool` — a profile without a usable
    digest cannot be pinned, and an unpinned profile establishes nothing."""
    if not profile:
        return False
    return bool(profile.get("id")) and digest_usable(profile.get("digest"))


def map_and_match(profile: dict, projector, evidence: dict, expected: dict) -> str:
    """Go `MapAndMatch(profile, projector, evidence, expected) MatchVerdict`.

    Every failure mode — unpinned profile, projector error, or a projection
    that changes material content — is INDETERMINATE, never MATCH."""
    if not mapping_profile_pinned(profile) or projector is None:
        return MATCH_INDETERMINATE
    try:
        projected = projector(profile, evidence)
    except Exception:
        return MATCH_INDETERMINATE
    if projected.get("type") != expected.get("type") or projected.get("suite") != expected.get("suite"):
        return MATCH_INDETERMINATE
    return match(expected, projected)
